use crate::msg::DataFrame;
use crate::runtime;
use crate::{
    fec::{FrameDecoder, FrameEncoder},
    VarRateLimit,
};
use bytes::Bytes;
use smol::channel::{Receiver, Sender};
use smol::prelude::*;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::Instant,
};
use std::{sync::Arc, time::Duration};

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
    pub send_frame: Sender<DataFrame>,
    pub recv_frame: Receiver<DataFrame>,
    pub recv_timeout: Duration,
}

/// Representation of an isolated session that deals only in DataFrames and abstracts away all I/O concerns. It's the user's responsibility to poll the session. Otherwise, it might not make progress and will drop packets.
pub struct Session {
    pub(crate) send_tosend: Sender<Bytes>,
    rate_limit: Arc<AtomicU32>,
    recv_input: Receiver<Bytes>,
    get_stats: Sender<Sender<SessionStats>>,
    _dropper: Vec<Box<dyn FnOnce() + Send + Sync + 'static>>,
    _task: smol::Task<()>,
}

impl Session {
    /// Creates a tuple of a Session and also a channel with which stuff is fed into the session.
    pub(crate) fn new(cfg: SessionConfig) -> Self {
        let (send_tosend, recv_tosend) = smol::channel::bounded(50);
        let (send_input, recv_input) = smol::channel::bounded(50);
        let (s, r) = smol::channel::unbounded();
        let rate_limit = Arc::new(AtomicU32::new(100000));
        let recv_timeout = cfg.recv_timeout;
        let task = runtime::spawn(session_loop(
            cfg,
            recv_tosend,
            send_input,
            rate_limit.clone(),
            r,
            recv_timeout,
        ));
        Session {
            send_tosend,
            recv_input,
            rate_limit,
            get_stats: s,
            _dropper: Vec::new(),
            _task: task,
        }
    }

    /// Adds a closure to be run when the Session is dropped. Use this to manage associated "worker" resources.
    pub fn on_drop<T: FnOnce() + Send + Sync + 'static>(&mut self, thing: T) {
        self._dropper.push(Box::new(thing))
    }

    /// Takes a Bytes to be sent and stuffs it into the session.
    pub async fn send_bytes(&self, to_send: Bytes) {
        if self.send_tosend.try_send(to_send).is_err() {
            log::trace!("overflowed send buffer at session!");
        }
        // drop(self.send_tosend.send(to_send).await)
    }

    /// Waits until the next application input is decoded by the session.
    pub async fn recv_bytes(&self) -> Option<Bytes> {
        self.recv_input.recv().await.ok()
    }

    /// Obtains current statistics.
    pub async fn get_stats(&self) -> Option<SessionStats> {
        let (send, recv) = smol::channel::bounded(1);
        self.get_stats.send(send).await.ok()?;
        recv.recv().await.ok()
    }

    /// Sets the rate limit, in packets per second.
    pub fn set_ratelimit(&self, pps: u32) {
        self.rate_limit.store(pps, Ordering::Relaxed);
    }
}

/// Statistics of a single Sosistab session.
#[derive(Debug)]
pub struct SessionStats {
    pub down_total: u64,
    pub down_loss: f64,
    pub down_recovered_loss: f64,
    pub down_redundant: f64,
    pub recent_seqnos: Vec<(Instant, u64)>,
    pub ping: Duration,
}

async fn session_loop(
    cfg: SessionConfig,
    recv_tosend: Receiver<Bytes>,
    send_input: Sender<Bytes>,
    rate_limit: Arc<AtomicU32>,
    recv_statreq: Receiver<Sender<SessionStats>>,
    recv_timeout: Duration,
) {
    let measured_loss = Arc::new(AtomicU8::new(0));
    let high_recv_frame_no = Arc::new(AtomicU64::new(0));
    let total_recv_frames = Arc::new(AtomicU64::new(0));
    let shaper = smol::lock::Mutex::new(VarRateLimit::new());
    let pinger = smol::lock::Mutex::new(PingCalc::default());

    // sending loop
    let send_task = session_send_loop(
        cfg.clone(),
        rate_limit.clone(),
        recv_tosend.clone(),
        measured_loss.clone(),
        high_recv_frame_no.clone(),
        total_recv_frames.clone(),
        &shaper,
        &pinger,
    );
    let recv_task = session_recv_loop(
        cfg,
        send_input,
        recv_statreq,
        measured_loss,
        high_recv_frame_no,
        total_recv_frames,
        &pinger,
        recv_timeout,
    );
    smol::future::race(send_task, recv_task).await;
}

#[allow(clippy::too_many_arguments)]
async fn session_send_loop(
    cfg: SessionConfig,
    rate_limit: Arc<AtomicU32>,
    recv_tosend: Receiver<Bytes>,
    measured_loss: Arc<AtomicU8>,
    high_recv_frame_no: Arc<AtomicU64>,
    total_recv_frames: Arc<AtomicU64>,
    shaper: &smol::lock::Mutex<VarRateLimit>,
    pinger: &smol::lock::Mutex<PingCalc>,
) -> Option<()> {
    fn get_timeout(loss: u8) -> Duration {
        let loss = loss as u64;
        // if loss is zero, then we return zero
        if loss == 0 {
            Duration::from_secs(0)
        } else {
            // around 50 ms for full loss
            Duration::from_millis(loss * loss / 1500 + 5)
        }
    }

    let mut frame_no = 0u64;
    let mut run_no = 0u64;
    let mut to_send = Vec::new();
    let mut abs_timeout = smol::Timer::after(get_timeout(measured_loss.load(Ordering::Relaxed)));
    loop {
        // obtain a vector of bytes to send
        let to_send = {
            to_send.clear();
            // get as much tosend as possible within the timeout
            // this lets us do it at maximum efficiency
            to_send.push(infal(recv_tosend.recv()).await);
            abs_timeout.set_after(get_timeout(measured_loss.load(Ordering::Relaxed)));
            loop {
                let break_now = async {
                    (&mut abs_timeout).await;
                    true
                }
                .or(async {
                    to_send.push(infal(recv_tosend.recv()).await);
                    false
                });
                if break_now.await || to_send.len() >= 64 {
                    break &to_send;
                }
            }
        };
        // encode into raptor
        let encoded = FrameEncoder::new(loss_to_u8(cfg.target_loss))
            .encode(measured_loss.load(Ordering::Relaxed), &to_send);
        for (idx, bts) in encoded.iter().enumerate() {
            if frame_no % 1000 == 0 {
                log::debug!(
                    "frame {}, measured loss {}",
                    frame_no,
                    measured_loss.load(Ordering::Relaxed)
                );
            }
            drop(
                cfg.send_frame
                    .send(DataFrame {
                        frame_no,
                        run_no,
                        run_idx: idx as u8,
                        data_shards: to_send.len() as u8,
                        parity_shards: (encoded.len() - to_send.len()) as u8,
                        high_recv_frame_no: high_recv_frame_no.load(Ordering::Relaxed),
                        total_recv_frames: total_recv_frames.load(Ordering::Relaxed),
                        body: bts.clone(),
                    })
                    .await,
            );
            shaper
                .lock()
                .await
                .wait(rate_limit.load(Ordering::Relaxed))
                .await;
            pinger.lock().await.send(frame_no);
            frame_no += 1;
        }
        run_no += 1;
    }
}

#[allow(clippy::too_many_arguments)]
async fn session_recv_loop(
    cfg: SessionConfig,
    send_input: Sender<Bytes>,
    recv_statreq: Receiver<Sender<SessionStats>>,
    measured_loss: Arc<AtomicU8>,
    high_recv_frame_no: Arc<AtomicU64>,
    total_recv_frames: Arc<AtomicU64>,
    pinger: &smol::lock::Mutex<PingCalc>,
    recv_timeout: Duration,
) -> Option<()> {
    let decoder = smol::lock::RwLock::new(RunDecoder::default());
    let seqnos = smol::lock::RwLock::new(VecDeque::new());
    // receive loop
    let recv_loop = async {
        let mut rp_filter = ReplayFilter::new(0);
        let mut loss_calc = LossCalculator::new();
        let mut timer = smol::Timer::after(recv_timeout);
        loop {
            let timer_ref = &mut timer;
            let new_frame = async { cfg.recv_frame.recv().await.ok() }
                .or(async {
                    timer_ref.await;
                    None
                })
                .await?;
            timer.set_after(recv_timeout);
            if !rp_filter.add(new_frame.frame_no) {
                log::trace!(
                    "recv_loop: replay filter dropping frame {}",
                    new_frame.frame_no
                );
                continue;
            }
            {
                let mut seqnos = seqnos.write().await;
                seqnos.push_back((Instant::now(), new_frame.frame_no));
                if seqnos.len() > 100000 {
                    seqnos.pop_front();
                }
            }
            loss_calc.update_params(new_frame.high_recv_frame_no, new_frame.total_recv_frames);
            measured_loss.store(loss_to_u8(loss_calc.median), Ordering::Relaxed);
            high_recv_frame_no.fetch_max(new_frame.frame_no, Ordering::Relaxed);
            total_recv_frames.fetch_add(1, Ordering::Relaxed);
            pinger.lock().await.ack(new_frame.high_recv_frame_no);
            if let Some(output) = decoder.write().await.input(
                new_frame.run_no,
                new_frame.run_idx,
                new_frame.data_shards,
                new_frame.parity_shards,
                &new_frame.body,
            ) {
                for item in output {
                    let _ = send_input.send(item).await;
                }
            }
        }
    };
    // stats loop
    let stats_loop = async {
        loop {
            let req = infal(recv_statreq.recv()).await;
            let decoder = decoder.read().await;
            let ping = pinger.lock().await.ping();
            let response = SessionStats {
                down_total: high_recv_frame_no.load(Ordering::Relaxed),
                down_loss: 1.0
                    - (total_recv_frames.load(Ordering::Relaxed) as f64
                        / high_recv_frame_no.load(Ordering::Relaxed) as f64)
                        .min(1.0),
                down_recovered_loss: 1.0
                    - (decoder.correct_count as f64 / decoder.total_count as f64).min(1.0),
                down_redundant: decoder.total_parity_shards as f64
                    / decoder.total_data_shards as f64,
                recent_seqnos: seqnos.read().await.iter().cloned().collect(),
                ping,
            };
            infal(req.send(response)).await;
        }
    };
    smol::future::race(stats_loop, recv_loop).await
}
/// A reordering-resistant FEC reconstructor
#[derive(Default)]
struct RunDecoder {
    top_run: u64,
    bottom_run: u64,
    decoders: HashMap<u64, FrameDecoder>,
    total_count: u64,
    correct_count: u64,

    total_data_shards: u64,
    total_parity_shards: u64,
}

impl RunDecoder {
    fn input(
        &mut self,
        run_no: u64,
        run_idx: u8,
        data_shards: u8,
        parity_shards: u8,
        bts: &[u8],
    ) -> Option<Vec<Bytes>> {
        if run_no >= self.bottom_run {
            if run_no > self.top_run {
                self.top_run = run_no;
                // advance bottom
                while self.top_run - self.bottom_run > 100 {
                    if let Some(dec) = self.decoders.remove(&self.bottom_run) {
                        if dec.good_pkts() + dec.lost_pkts() > 1 {
                            self.total_count += (dec.good_pkts() + dec.lost_pkts()) as u64;
                            self.correct_count += dec.good_pkts() as u64
                        }
                    }
                    self.bottom_run += 1;
                }
            }
            let decoder = self
                .decoders
                .entry(run_no)
                .or_insert_with(|| FrameDecoder::new(data_shards as usize, parity_shards as usize));
            if run_idx < data_shards {
                self.total_data_shards += 1
            } else {
                self.total_parity_shards += 1
            }
            if let Some(res) = decoder.decode(bts, run_idx as usize) {
                Some(res)
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// A filter for replays. Records recently seen seqnos and rejects either repeats or really old seqnos.
#[derive(Debug)]
struct ReplayFilter {
    top_seqno: u64,
    bottom_seqno: u64,
    seen_seqno: HashSet<u64>,
}

impl ReplayFilter {
    fn new(start: u64) -> Self {
        ReplayFilter {
            top_seqno: start,
            bottom_seqno: start,
            seen_seqno: HashSet::new(),
        }
    }

    fn add(&mut self, seqno: u64) -> bool {
        if seqno < self.bottom_seqno {
            // out of range. we can't know, so we just say no
            return false;
        }
        // check the seen
        if self.seen_seqno.contains(&seqno) {
            return false;
        }
        self.top_seqno = seqno;
        while self.top_seqno - self.bottom_seqno > 10000 {
            self.seen_seqno.remove(&self.bottom_seqno);
            self.bottom_seqno += 1;
        }
        true
    }
}

fn loss_to_u8(loss: f64) -> u8 {
    let loss = loss * 256.0;
    if loss > 254.0 {
        return 255;
    }
    loss as u8
}

/// A packet loss calculator.
struct LossCalculator {
    last_top_seqno: u64,
    last_total_seqno: u64,
    last_time: Instant,
    loss_samples: VecDeque<f64>,
    median: f64,
}

impl LossCalculator {
    fn new() -> LossCalculator {
        LossCalculator {
            last_top_seqno: 0,
            last_total_seqno: 0,
            last_time: Instant::now(),
            loss_samples: VecDeque::new(),
            median: 0.0,
        }
    }

    fn update_params(&mut self, top_seqno: u64, total_seqno: u64) {
        let now = Instant::now();
        if total_seqno > self.last_total_seqno + 100
            && top_seqno > self.last_top_seqno + 100
            && now.saturating_duration_since(self.last_time).as_millis() > 2000
        {
            let delta_top = top_seqno.saturating_sub(self.last_top_seqno) as f64;
            let delta_total = total_seqno.saturating_sub(self.last_total_seqno) as f64;
            log::debug!(
                "updating loss calculator with {}/{}",
                delta_total,
                delta_top
            );
            self.last_top_seqno = top_seqno;
            self.last_total_seqno = total_seqno;
            let loss_sample = 1.0 - delta_total / delta_top.max(delta_total);
            self.loss_samples.push_back(loss_sample);
            if self.loss_samples.len() > 64 {
                self.loss_samples.pop_front();
            }
            let median = {
                let mut lala: Vec<f64> = self.loss_samples.iter().cloned().collect();
                lala.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap());
                lala[lala.len() / 4]
            };
            self.median = median;
            self.last_time = now;
        }
        // self.median = (1.0 - total_seqno as f64 / top_seqno as f64).max(0.0);
    }
}

/// A ping calculator
#[derive(Debug, Default)]
struct PingCalc {
    send_seqno: Option<u64>,
    send_time: Option<Instant>,
    pings: VecDeque<Duration>,
}

impl PingCalc {
    fn send(&mut self, sn: u64) {
        if self.send_seqno.is_some() {
            return;
        }
        self.send_seqno = Some(sn);
        self.send_time = Some(Instant::now());
    }
    fn ack(&mut self, sn: u64) {
        if let Some(send_seqno) = self.send_seqno {
            if sn >= send_seqno {
                let ping_sample = self.send_time.take().unwrap().elapsed();
                self.pings.push_back(ping_sample);
                if self.pings.len() > 8 {
                    self.pings.pop_front();
                }
                self.send_seqno = None
            }
        }
    }
    fn ping(&self) -> Duration {
        self.pings
            .iter()
            .cloned()
            .min()
            .unwrap_or_else(|| Duration::from_secs(1000))
    }
}
