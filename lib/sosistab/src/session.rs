use crate::msg::DataFrame;
use crate::runtime;
use crate::{fec::FrameEncoder, VarRateLimit};
use bytes::Bytes;
use concurrent_queue::ConcurrentQueue;
use machine::RecvMachine;
use parking_lot::Mutex;

use smol::channel::{Receiver, Sender};
use smol::prelude::*;
use stats::StatGatherer;

use std::{
    sync::atomic::{AtomicU32, Ordering},
    time::SystemTime,
};
use std::{sync::Arc, time::Duration};

use self::stats::TimeSeries;

mod machine;
mod stats;

async fn infal<T, E, F: Future<Output = std::result::Result<T, E>>>(fut: F) -> T {
    match fut.await {
        Ok(res) => res,
        Err(_) => {
            smol::future::pending::<()>().await;
            unreachable!();
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SessionConfig {
    pub target_loss: f64,
    pub send_frame: Sender<Vec<DataFrame>>,
    pub recv_frame: Receiver<DataFrame>,
    pub recv_timeout: Duration,
    pub statistics: usize,
}

/// Representation of an isolated session that deals only in DataFrames and abstracts away all I/O concerns. It's the user's responsibility to poll the session. Otherwise, it might not make progress and will drop packets.
pub struct Session {
    send_tosend: Sender<Bytes>,
    recv_frame: Receiver<DataFrame>,
    statistics: Arc<Mutex<TimeSeries<SessionStat>>>,
    machine: Mutex<RecvMachine>,
    machine_output: ConcurrentQueue<Bytes>,
    rate_limit: Arc<AtomicU32>,
    last_send: Arc<Mutex<SystemTime>>,
    _dropper: Vec<Box<dyn FnOnce() + Send + Sync + 'static>>,
    _task: smol::Task<()>,
}

impl Session {
    /// Creates a Session.
    pub(crate) fn new(cfg: SessionConfig) -> Self {
        let (send_tosend, recv_tosend) = smol::channel::bounded(500);
        let rate_limit = Arc::new(AtomicU32::new(100000));
        let recv_timeout = cfg.recv_timeout;
        let statistics = Arc::new(Mutex::new(TimeSeries::new(cfg.statistics)));
        let machine = Mutex::new(RecvMachine::default());
        let last_send = Arc::new(Mutex::new(SystemTime::now()));
        let recv_frame = cfg.recv_frame.clone();
        let task = runtime::spawn(session_loop(
            cfg,
            machine.lock().get_gather(),
            recv_tosend,
            rate_limit.clone(),
            recv_timeout,
            last_send.clone(),
        ));
        Session {
            send_tosend,
            rate_limit,
            recv_frame,
            machine,
            machine_output: ConcurrentQueue::unbounded(),
            last_send,
            statistics,
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
        if self.send_tosend.try_send(to_send).is_err() {
            tracing::warn!("overflowed send buffer at session!");
        }
        *self.last_send.lock() = SystemTime::now();
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
            let frame = self.recv_frame.recv().await.ok()?;
            let mut machine = self.machine.lock();
            let out = machine.process(&frame);
            if let Some(out) = out {
                for o in out {
                    self.machine_output.push(o).unwrap();
                }
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

#[tracing::instrument(skip(statg))]
async fn session_send_loop(
    cfg: SessionConfig,
    rate_limit: &AtomicU32,
    recv_tosend: Receiver<Bytes>,
    statg: Arc<StatGatherer>,
    last_send: &Mutex<SystemTime>,
    recv_timeout: Duration,
) -> Option<()> {
    fn get_timeout(loss: u8) -> Duration {
        let loss = loss as u64;
        // if loss is zero, then we return 5
        if loss == 0 {
            Duration::from_millis(0)
        } else {
            // around 50 ms for full loss
            Duration::from_millis(loss * loss / 1500 + 5)
        }
    }

    let mut shaper = VarRateLimit::new();

    let mut frame_no = 0u64;
    let mut run_no = 0u64;
    let mut to_send = Vec::new();
    let mut abs_timeout = smol::Timer::after(get_timeout(statg.loss_u8()));
    loop {
        // obtain a vector of bytes to send
        let loss = statg.loss_u8();
        let to_send = {
            to_send.clear();
            // get as much tosend as possible within the timeout
            // this lets us do it at maximum efficiency
            to_send.push(recv_tosend.recv().await.ok()?);
            if loss > 0 {
                abs_timeout.set_after(get_timeout(loss));
                loop {
                    let break_now = async {
                        (&mut abs_timeout).await;
                        true
                    }
                    .or(async {
                        to_send.push(infal(recv_tosend.recv()).await);
                        false
                    });
                    if break_now.await || to_send.len() >= 32 {
                        break &to_send;
                    }
                }
            } else {
                &to_send
            }
        };
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
        cfg.send_frame.send(tosend).await.ok()?;
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
