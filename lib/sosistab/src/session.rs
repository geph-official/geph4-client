use crate::runtime;
use crate::{crypt::LegacyAEAD, fec::FrameEncoder};
use crate::{
    crypt::NgAEAD,
    protocol::{DataFrameV1, DataFrameV2},
};
use bytes::Bytes;
use concurrent_queue::ConcurrentQueue;
use governor::{NegativeMultiDecision, Quota, RateLimiter};
use machine::RecvMachine;
use parking_lot::Mutex;
use rand::prelude::*;
use smol::channel::{Receiver, Sender, TrySendError};
use smol::prelude::*;
use smol_timeout::TimeoutExt;
use stats::StatGatherer;
use std::{
    num::NonZeroU32,
    sync::atomic::{AtomicU32, Ordering},
    time::SystemTime,
};
use std::{sync::Arc, time::Duration};

use self::stats::TimeSeries;

mod machine;
mod stats;

#[derive(Debug, Clone)]
pub(crate) struct SessionConfig {
    pub send_packet: Sender<Bytes>,
    pub recv_packet: Receiver<Bytes>,
    pub recv_timeout: Duration,
    pub statistics: usize,
    pub version: u64,
    pub send_crypt_legacy: LegacyAEAD,
    pub recv_crypt_legacy: LegacyAEAD,
    pub send_crypt_ng: NgAEAD,
    pub recv_crypt_ng: NgAEAD,
}

/// Representation of an isolated session that deals only in DataFrames and abstracts away all I/O concerns. It's the user's responsibility to poll the session. Otherwise, it might not make progress and will drop packets.
pub struct Session {
    send_tosend: Sender<Bytes>,
    recv_packet: Receiver<Bytes>,
    statistics: Arc<Mutex<TimeSeries<SessionStat>>>,
    machine: Mutex<RecvMachine>,
    machine_output: ConcurrentQueue<Bytes>,
    rate_limit: Arc<AtomicU32>,
    last_recv: Arc<Mutex<SystemTime>>,
    recv_timeout: Duration,
    _dropper: Vec<Box<dyn FnOnce() + Send + Sync + 'static>>,
    _task: smol::Task<()>,
}

impl Session {
    /// Creates a Session.
    pub(crate) fn new(cfg: SessionConfig) -> Self {
        let (send_tosend, recv_tosend) = smol::channel::unbounded();
        let rate_limit = Arc::new(AtomicU32::new(25600));
        let recv_timeout = cfg.recv_timeout;
        let statistics = Arc::new(Mutex::new(TimeSeries::new(cfg.statistics)));
        let machine = Mutex::new(RecvMachine::new(
            cfg.version,
            cfg.recv_crypt_legacy,
            cfg.recv_crypt_ng.clone(),
        ));
        let last_recv = Arc::new(Mutex::new(SystemTime::now()));
        let recv_packet = cfg.recv_packet.clone();

        let ctx = SessionSendCtx {
            cfg,
            statg: machine.lock().get_gather(),
            recv_tosend,
            rate_limit: rate_limit.clone(),
            recv_timeout,
            last_recv: last_recv.clone(),
        };

        let task = runtime::spawn(session_send_loop(ctx));
        Session {
            send_tosend,
            rate_limit,
            recv_packet,
            machine,
            machine_output: ConcurrentQueue::unbounded(),
            last_recv,
            statistics,
            recv_timeout,
            _dropper: Vec::new(),
            _task: task,
        }
    }

    /// Adds a closure to be run when the Session is dropped. Use this to manage associated "worker" resources.
    pub fn on_drop<T: FnOnce() + Send + Sync + 'static>(&mut self, thing: T) {
        self._dropper.push(Box::new(thing))
    }

    /// Takes a Bytes to be sent and stuffs it into the session.
    pub fn send_bytes(&self, to_send: Bytes) {
        let rate = self.rate_limit.load(Ordering::Relaxed);
        // if rate < 1000 {
        // RED with max 250ms latency
        let target_queue_len = rate / 4;
        let fill_ratio = self.send_tosend.len() as f64 / target_queue_len as f64;
        if rand::random::<f64>() < fill_ratio.powi(4) {
            // tracing::warn!("RED dropping packet (fill ratio {:.3})", fill_ratio);
            return;
        }
        // }
        if let Err(err) = self.send_tosend.try_send(to_send) {
            if let TrySendError::Closed(_) = err {
                self.recv_packet.close();
            } else {
                tracing::warn!("overflowing send_tosend");
            }
        }
    }

    /// Waits until the next application input is decoded by the session.
    pub async fn recv_bytes(&self) -> Option<Bytes> {
        loop {
            // try dequeuing from Q
            if let Ok(b) = self.machine_output.pop() {
                let raw_stat = self.machine.lock().get_gather();
                if rand::random::<f32>() < 0.1 {
                    let stat = SessionStat {
                        time: SystemTime::now(),
                        last_recv: raw_stat.high_recv_frame_no(),
                        total_recv: raw_stat.total_recv_frames(),
                        total_loss: 1.0
                            - (raw_stat.total_recv_frames() as f64
                                / raw_stat.high_recv_frame_no() as f64)
                                .min(1.0),
                        ping: raw_stat.ping(),
                    };
                    self.statistics.lock().push(stat);
                }
                break Some(b);
            }
            // receive more stuff
            let frame = self.recv_packet.recv().timeout(self.recv_timeout).await;
            if let Some(frame) = frame {
                let frame = frame.ok()?;
                let out = self.machine.lock().process(&frame);
                if let Some(out) = out {
                    for o in out {
                        self.machine_output.push(o).unwrap();
                    }
                    *self.last_recv.lock() = SystemTime::now();
                }
            } else {
                tracing::warn!("OH NO TIME TO DIEEE!");
                self.recv_packet.close();
                return None;
            }
        }
    }

    /// Sets the rate limit, in packets per second.
    pub fn set_ratelimit(&self, pps: u32) {
        self.rate_limit.store(pps, Ordering::Relaxed);
    }

    /// Gets the statistics.
    pub fn all_stats(&self) -> Vec<SessionStat> {
        self.statistics.lock().items().iter().cloned().collect()
    }

    /// Get the latest stats.
    pub fn latest_stat(&self) -> Option<SessionStat> {
        self.statistics.lock().items().iter().last().cloned()
    }
}

struct SessionSendCtx {
    cfg: SessionConfig,
    statg: Arc<StatGatherer>,
    recv_tosend: Receiver<Bytes>,
    rate_limit: Arc<AtomicU32>,
    recv_timeout: Duration,
    last_recv: Arc<Mutex<SystemTime>>,
}

// #[tracing::instrument(skip(ctx))]
async fn session_send_loop(ctx: SessionSendCtx) {
    // sending loop
    if ctx.cfg.version == 1 {
        session_send_loop_v1(ctx).await;
    } else {
        let version = ctx.cfg.version;
        session_send_loop_nextgen(ctx, version).await;
    }
}

const BURST_SIZE: usize = 20;

#[tracing::instrument(skip(ctx))]
async fn session_send_loop_v1(ctx: SessionSendCtx) -> Option<()> {
    let mut frame_no = 0u64;
    let mut run_no = 0u64;
    let mut to_send = Vec::new();

    let batch_limiter = RateLimiter::direct_with_clock(
        Quota::per_second(NonZeroU32::new(50u32).unwrap())
            .allow_burst(NonZeroU32::new(10u32).unwrap()),
        &governor::clock::MonotonicClock,
    );

    let policy_limiter = RateLimiter::direct_with_clock(
        Quota::per_second(NonZeroU32::new(25600u32).unwrap()),
        &governor::clock::MonotonicClock,
    );
    let mut encoder = FrameEncoder::new(4);
    loop {
        // obtain a vector of bytes to send
        let loss = ctx.statg.loss_u8();
        to_send.clear();
        to_send.push(ctx.recv_tosend.recv().await.ok()?);
        while to_send.len() < BURST_SIZE {
            if let Ok(val) = ctx.recv_tosend.try_recv() {
                to_send.push(val)
            } else {
                break;
            }
        }
        // we limit bursts that are less than half full only. this is so that we don't accidentally "rate limit" stuff
        if to_send.len() < BURST_SIZE / 2 {
            // we use smol to wait to be more efficient
            while let Err(err) = batch_limiter.check() {
                smol::Timer::at(err.earliest_possible()).await;
            }
        }
        let now = SystemTime::now();
        if let Ok(elapsed) = now.duration_since(*ctx.last_recv.lock()) {
            if elapsed > ctx.recv_timeout {
                tracing::warn!("skew-induced timeout detected. killing session now");
                return None;
            }
        }
        // encode into raptor
        let encoded = encoder.encode(loss, &to_send);
        let mut tosend = Vec::with_capacity(encoded.len());
        for (idx, bts) in encoded.iter().enumerate() {
            // limit
            let limit = ctx.rate_limit.load(Ordering::Relaxed);
            if limit < 1000 {
                if ctx.recv_tosend.len() > 100 {
                    continue;
                }
                let multiplier = 25600 / limit;
                while let Err(NegativeMultiDecision::BatchNonConforming(_, err)) =
                    policy_limiter.check_n(NonZeroU32::new(multiplier).unwrap())
                {
                    smol::Timer::at(err.earliest_possible()).await;
                }
            }
            tosend.push(DataFrameV1 {
                frame_no,
                run_no,
                run_idx: idx as u8,
                data_shards: to_send.len() as u8,
                parity_shards: (encoded.len() - to_send.len()) as u8,
                high_recv_frame_no: ctx.statg.high_recv_frame_no(),
                total_recv_frames: ctx.statg.total_recv_frames(),
                body: bts.clone(),
            });
            ctx.statg.ping_send(frame_no);
            frame_no += 1;
        }

        // TODO: batching
        for tosend in tosend {
            let encoded = ctx.cfg.send_crypt_legacy.pad_encrypt_v1(&[tosend], 1000);
            ctx.cfg.send_packet.send(encoded).await.ok()?;
        }

        // let tosend = ctx.cfg.send_crypt.pad_encrypt(msgs, target_len)

        // if ctx.cfg.use_batching.load(Ordering::Relaxed) {
        //     ctx.cfg.send_packet.send(tosend).await.ok()?;
        // } else {
        //     for tosend in tosend {
        //         ctx.cfg.send_packet.send(vec![tosend]).await.ok()?;
        //     }
        // }
        run_no += 1;
    }
}

#[tracing::instrument(skip(ctx))]
async fn session_send_loop_nextgen(ctx: SessionSendCtx, version: u64) -> Option<()> {
    enum Event {
        NewPayload(Bytes),
        FecTimeout,
    }

    let policy_limiter = RateLimiter::direct_with_clock(
        Quota::per_second(NonZeroU32::new(25600).unwrap()),
        &governor::clock::MonotonicClock,
    );

    // let hard_limiter = RateLimiter::direct_with_clock(
    //     Quota::per_second(NonZeroU32::new(15000).unwrap()).allow_burst(NonZeroU32::new(8).unwrap()),
    //     &governor::clock::MonotonicClock,
    // );

    const FEC_TIMEOUT_MS: u64 = 75;

    // FEC timer: when this expires, send parity packets regardless if we have assembled BURST_SIZE data packets.
    let mut fec_timer = smol::Timer::after(Duration::from_millis(FEC_TIMEOUT_MS));
    // Vector of "unfecked" frames.
    let mut unfecked: Vec<(u64, Bytes)> = Vec::new();
    let mut fec_encoder = FrameEncoder::new(1);
    let mut frame_no = 0;
    loop {
        smol::future::yield_now().await;
        // we die an early death if something went wrong
        if let Ok(elapsed) = SystemTime::now().duration_since(*ctx.last_recv.lock()) {
            if elapsed > ctx.recv_timeout {
                tracing::warn!("skew-induced timeout detected. killing session now");
                return None;
            }
        }
        // either we have something new to send, or the FEC timer expired.
        let event: Option<Event> = async {
            if unfecked.is_empty() {
                smol::future::pending::<()>().await;
            }
            if unfecked.len() < BURST_SIZE {
                // we need to wait, because the burst size isn't there yet
                (&mut fec_timer).await;
            }
            Some(Event::FecTimeout)
        }
        .or(async { Some(Event::NewPayload(ctx.recv_tosend.recv().await.ok()?)) })
        .await;
        match event? {
            // we have something to send as a data packet.
            Event::NewPayload(send_payload) => {
                let limit = ctx.rate_limit.load(Ordering::Relaxed);
                // if limit < 1000 {
                let multiplier = 25600 / limit;
                while let Err(NegativeMultiDecision::BatchNonConforming(_, err)) =
                    policy_limiter.check_n(NonZeroU32::new(multiplier).unwrap())
                {
                    smol::Timer::at(err.earliest_possible()).await;
                }
                // }
                // while let Err(e) = hard_limiter.check() {
                //     smol::Timer::at(e.earliest_possible()).await;
                // }
                let send_framed = DataFrameV2::Data {
                    frame_no,
                    high_recv_frame_no: ctx.statg.high_recv_frame_no(),
                    total_recv_frames: ctx.statg.total_recv_frames(),
                    body: send_payload.clone(),
                };
                // we now add to unfecked
                unfecked.push((frame_no, send_payload));
                let send_padded = send_framed.pad();
                ctx.statg.ping_send(frame_no);
                let send_encrypted = match version {
                    2 => ctx
                        .cfg
                        .send_crypt_legacy
                        .encrypt(&send_padded, rand::thread_rng().gen()),
                    3 => ctx.cfg.send_crypt_ng.encrypt(&send_padded),
                    _ => return None,
                };
                ctx.cfg.send_packet.send(send_encrypted).await.ok()?;

                // increment frame no
                frame_no += 1;
                // reset fec timer
                fec_timer.set_after(Duration::from_millis(FEC_TIMEOUT_MS));
            }
            // we have something to send, as a FEC packet.
            Event::FecTimeout => {
                // reset fec timer
                fec_timer.set_after(Duration::from_millis(FEC_TIMEOUT_MS));
                if unfecked.is_empty() {
                    continue;
                }
                let measured_loss = ctx.statg.loss_u8();
                if measured_loss == 0 {
                    unfecked.clear();
                    continue;
                }
                assert!(unfecked.len() <= BURST_SIZE);
                // encode
                let first_frame_no = unfecked[0].0;
                let data_count = unfecked.len();
                let expanded = fec_encoder.encode(
                    ctx.statg.loss_u8(),
                    &unfecked.iter().map(|v| v.1.clone()).collect::<Vec<_>>(),
                );
                let pad_size = unfecked.iter().map(|v| v.1.len()).max().unwrap_or_default() + 2;
                let parity = &expanded[unfecked.len()..];
                unfecked.clear();
                tracing::trace!("FecTimeout; sending {} parities", parity.len());
                let parity_count = parity.len();
                // encode parity, taking along the first data frame no to identify the run
                for (index, parity) in parity.iter().enumerate() {
                    let send_framed = DataFrameV2::Parity {
                        data_frame_first: first_frame_no,
                        data_count: data_count as u8,
                        parity_count: parity_count as u8,
                        parity_index: index as u8,
                        body: parity.clone(),
                        pad_size,
                    };
                    let send_padded = send_framed.pad();
                    let send_encrypted = match version {
                        2 => ctx
                            .cfg
                            .send_crypt_legacy
                            .encrypt(&send_padded, rand::thread_rng().gen()),
                        3 => ctx.cfg.send_crypt_ng.encrypt(&send_padded),
                        _ => return None,
                    };
                    ctx.cfg.send_packet.send(send_encrypted).await.ok()?;
                }
            }
        }
    }
}

/// Session stat
#[derive(Copy, Clone, Debug)]
pub struct SessionStat {
    pub time: SystemTime,
    pub last_recv: u64,
    pub total_recv: u64,
    // pub total_parity: u64,
    pub total_loss: f64,
    pub ping: Duration,
}
