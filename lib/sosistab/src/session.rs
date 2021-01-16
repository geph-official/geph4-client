use crate::msg::DataFrame;
use crate::runtime;
use crate::{fec::FrameEncoder, VarRateLimit};
use bytes::Bytes;
use concurrent_queue::ConcurrentQueue;
use governor::{Quota, RateLimiter};
use machine::RecvMachine;
use parking_lot::Mutex;

use smol::channel::{Receiver, Sender};
use smol_timeout::TimeoutExt;
use stats::StatGatherer;

use std::{
    num::NonZeroU32,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
    time::SystemTime,
};
use std::{sync::Arc, time::Duration};

use self::stats::TimeSeries;

mod machine;
mod stats;

#[derive(Debug, Clone)]
pub(crate) struct SessionConfig {
    pub target_loss: f64,
    pub send_frame: Sender<Vec<DataFrame>>,
    pub recv_frame: Receiver<DataFrame>,
    pub recv_timeout: Duration,
    pub statistics: usize,
    pub use_batching: Arc<AtomicBool>,
}

/// Representation of an isolated session that deals only in DataFrames and abstracts away all I/O concerns. It's the user's responsibility to poll the session. Otherwise, it might not make progress and will drop packets.
pub struct Session {
    send_tosend: Sender<Bytes>,
    recv_frame: Receiver<DataFrame>,
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
        let (send_tosend, recv_tosend) = smol::channel::bounded(1000);
        let rate_limit = Arc::new(AtomicU32::new(100000));
        let recv_timeout = cfg.recv_timeout;
        let statistics = Arc::new(Mutex::new(TimeSeries::new(cfg.statistics)));
        let machine = Mutex::new(RecvMachine::default());
        let last_recv = Arc::new(Mutex::new(SystemTime::now()));
        let recv_frame = cfg.recv_frame.clone();
        let task = runtime::spawn(session_loop(
            cfg,
            machine.lock().get_gather(),
            recv_tosend,
            rate_limit.clone(),
            recv_timeout,
            last_recv.clone(),
        ));
        Session {
            send_tosend,
            rate_limit,
            recv_frame,
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
        if let Err(err) = self.send_tosend.try_send(to_send) {
            if let smol::channel::TrySendError::Closed(_) = err {
                self.recv_frame.close();
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
            let frame = self.recv_frame.recv().timeout(self.recv_timeout).await;
            if let Some(frame) = frame {
                let frame = frame.ok()?;
                let mut machine = self.machine.lock();
                let out = machine.process(&frame);
                if let Some(out) = out {
                    for o in out {
                        self.machine_output.push(o).unwrap();
                    }
                    *self.last_recv.lock() = SystemTime::now();
                }
            } else {
                tracing::warn!("OH NO TIME TO DIEEE!");
                self.recv_frame.close();
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
        self.statistics.lock().items().into_iter().collect()
    }

    /// Get the latest stats.
    pub fn latest_stat(&self) -> Option<SessionStat> {
        self.statistics.lock().items().last().cloned()
    }
}

#[tracing::instrument(skip(statg))]
async fn session_loop(
    cfg: SessionConfig,
    statg: Arc<StatGatherer>,
    recv_tosend: Receiver<Bytes>,
    rate_limit: Arc<AtomicU32>,
    recv_timeout: Duration,
    last_send: Arc<Mutex<SystemTime>>,
) {
    // sending loop
    session_send_loop(
        cfg.clone(),
        &rate_limit,
        recv_tosend.clone(),
        statg,
        &last_send,
        recv_timeout,
    )
    .await;
}

const BURST_SIZE: usize = 32;

#[tracing::instrument(skip(statg))]
async fn session_send_loop(
    cfg: SessionConfig,
    rate_limit: &AtomicU32,
    recv_tosend: Receiver<Bytes>,
    statg: Arc<StatGatherer>,
    last_send: &Mutex<SystemTime>,
    recv_timeout: Duration,
) -> Option<()> {
    let mut shaper = VarRateLimit::new();

    let mut frame_no = 0u64;
    let mut run_no = 0u64;
    let mut to_send = Vec::new();

    let limiter = RateLimiter::direct_with_clock(
        Quota::per_second(NonZeroU32::new(100u32).unwrap()),
        &governor::clock::MonotonicClock,
    );
    loop {
        // obtain a vector of bytes to send
        let loss = statg.loss_u8();
        to_send.clear();
        to_send.push(recv_tosend.recv().await.ok()?);
        while to_send.len() < BURST_SIZE {
            if let Ok(val) = recv_tosend.try_recv() {
                to_send.push(val)
            } else {
                break;
            }
        }
        // we limit bursts that are less than half full only. this is so that we don't accidentally "rate limit" stuff
        if to_send.len() < BURST_SIZE / 2 {
            // we use smol to wait to be more efficient
            while let Err(err) = limiter.check() {
                smol::Timer::at(err.earliest_possible()).await;
            }
        }
        let now = SystemTime::now();
        if let Ok(elapsed) = now.duration_since(*last_send.lock()) {
            if elapsed > recv_timeout {
                tracing::warn!("skew-induced timeout detected. killing session now");
                return None;
            }
        }
        // encode into raptor
        let encoded = FrameEncoder::new(loss_to_u8(cfg.target_loss)).encode(loss, &to_send);
        let mut tosend = Vec::with_capacity(encoded.len());
        for (idx, bts) in encoded.iter().enumerate() {
            tosend.push(DataFrame {
                frame_no,
                run_no,
                run_idx: idx as u8,
                data_shards: to_send.len() as u8,
                parity_shards: (encoded.len() - to_send.len()) as u8,
                high_recv_frame_no: statg.high_recv_frame_no(),
                total_recv_frames: statg.total_recv_frames(),
                body: bts.clone(),
            });
            shaper.wait(rate_limit.load(Ordering::Relaxed)).await;
            statg.ping_send(frame_no);
            frame_no += 1;
        }

        if cfg.use_batching.load(Ordering::Relaxed) {
            cfg.send_frame.send(tosend).await.ok()?;
        } else {
            for tosend in tosend {
                cfg.send_frame.send(vec![tosend]).await.ok()?;
            }
        }
        run_no += 1;
    }
}

fn loss_to_u8(loss: f64) -> u8 {
    let loss = loss * 256.0;
    if loss > 254.0 {
        return 255;
    }
    loss as u8
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
