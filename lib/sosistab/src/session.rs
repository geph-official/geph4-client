use crate::fec::{FrameDecoder, FrameEncoder};
use crate::msg::DataFrame;
use crate::runtime;
use async_channel::{Receiver, Sender};
use async_lock::Lock;
use bytes::Bytes;
use smol::prelude::*;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::time::Duration;

async fn infal<T, E, F: Future<Output = std::result::Result<T, E>>>(fut: F) -> T {
    match fut.await {
        Ok(res) => res,
        Err(_) => {
            smol::future::pending::<()>().await;
            unreachable!();
        }
    }
}

pub struct SessionConfig {
    pub latency: Duration,
    pub target_loss: f64,
    pub send_frame: Sender<DataFrame>,
    pub recv_frame: Receiver<DataFrame>,
}

/// Representation of an isolated session that deals only in DataFrames and abstracts away all I/O concerns. It's the user's responsibility to poll the session. Otherwise, it might not make progress and will drop packets.
pub struct Session {
    send_tosend: Sender<Bytes>,
    recv_input: Receiver<Bytes>,
    get_stats: Sender<Sender<SessionStats>>,
    _dropper: Vec<Box<dyn FnOnce() + Send + Sync + 'static>>,
    _task: smol::Task<()>,
}

impl Session {
    /// Creates a tuple of a Session and also a channel with which stuff is fed into the session.
    pub fn new(cfg: SessionConfig) -> Self {
        let (send_tosend, recv_tosend) = async_channel::bounded(100);
        let (send_input, recv_input) = async_channel::bounded(1000);
        let (s, r) = async_channel::unbounded();
        let task = runtime::spawn(session_loop(cfg, recv_tosend, send_input, r));
        Session {
            send_tosend,
            recv_input,
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
        // if self.send_tosend.try_send(to_send).is_err() {
        //     log::warn!("overflowed send buffer at session!");
        // }
        drop(self.send_tosend.send(to_send).await)
    }

    /// Waits until the next application input is decoded by the session.
    pub async fn recv_bytes(&self) -> Bytes {
        self.recv_input.recv().await.unwrap()
    }

    /// Obtains current statistics.
    pub async fn get_stats(&self) -> SessionStats {
        let (send, recv) = async_channel::bounded(1);
        self.get_stats.send(send).await.unwrap();
        recv.recv().await.unwrap()
    }
}

/// Statistics of a single Sosistab session.
pub struct SessionStats {
    pub down_total: u64,
    pub down_loss: f64,
    pub down_recovered_loss: f64,
    pub down_redundant: f64,
}

async fn session_loop(
    cfg: SessionConfig,
    recv_tosend: Receiver<Bytes>,
    send_input: Sender<Bytes>,
    recv_statreq: Receiver<Sender<SessionStats>>,
) {
    let measured_loss = AtomicU8::new(0);
    let high_recv_frame_no = AtomicU64::new(0);
    let total_recv_frames = AtomicU64::new(0);

    // sending loop
    let send_loop = async {
        let mut frame_no = 0u64;
        let mut run_no = 0u64;
        let mut to_send = Vec::new();
        loop {
            // obtain a vector of bytes to send
            let to_send = {
                to_send.clear();
                // get as much tosend as possible within the timeout
                // this lets us do it at maximum efficiency
                to_send.push(infal(recv_tosend.recv()).await);
                let mut timeout = smol::Timer::after(cfg.latency);
                loop {
                    let res = async {
                        (&mut timeout).await;
                        true
                    }
                    .or(async {
                        to_send.push(infal(recv_tosend.recv()).await);
                        false
                    });
                    if res.await || to_send.len() >= 16 {
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
                // lim.until_ready().await;
                frame_no += 1;
            }
            run_no += 1;
        }
    };
    let decoder = Lock::new(RunDecoder::default());
    // receive loop
    let recv_loop = async {
        let mut rp_filter = ReplayFilter::new(0);
        let mut loss_calc = LossCalculator::new();
        loop {
            let new_frame = infal(cfg.recv_frame.recv()).await;
            if !rp_filter.add(new_frame.frame_no) {
                log::trace!(
                    "recv_loop: replay filter dropping frame {}",
                    new_frame.frame_no
                );
                continue;
            }
            loss_calc.update_params(new_frame.high_recv_frame_no, new_frame.total_recv_frames);
            measured_loss.store(loss_to_u8(loss_calc.median), Ordering::Relaxed);
            high_recv_frame_no.fetch_max(new_frame.frame_no, Ordering::Relaxed);
            total_recv_frames.fetch_add(1, Ordering::Relaxed);
            if let Some(output) = decoder.lock().await.input(
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
            let decoder = decoder.lock().await;
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
            };
            infal(req.send(response)).await;
        }
    };
    smol::future::race(send_loop, recv_loop)
        .or(stats_loop)
        .await;
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
                        self.total_count += (dec.good_pkts() + dec.lost_pkts()) as u64;
                        self.correct_count += dec.good_pkts() as u64
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
        while self.top_seqno - self.bottom_seqno > 1000 {
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
    loss_samples: VecDeque<f64>,
    median: f64,
}

impl LossCalculator {
    fn new() -> LossCalculator {
        LossCalculator {
            last_top_seqno: 0,
            last_total_seqno: 0,
            loss_samples: VecDeque::new(),
            median: 0.0,
        }
    }

    fn update_params(&mut self, top_seqno: u64, total_seqno: u64) {
        if total_seqno > self.last_total_seqno + 30 && top_seqno > self.last_top_seqno + 30 {
            let delta_top = top_seqno.saturating_sub(self.last_top_seqno) as f64;
            let delta_total = total_seqno.saturating_sub(self.last_total_seqno) as f64;
            self.last_top_seqno = top_seqno;
            self.last_total_seqno = total_seqno;
            let loss_sample = 1.0 - delta_total / delta_top.max(delta_total);
            self.loss_samples.push_back(loss_sample);
            if self.loss_samples.len() > 1000 {
                self.loss_samples.pop_front();
            }
            let median = {
                let mut lala: Vec<f64> = self.loss_samples.iter().cloned().collect();
                lala.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap());
                lala[lala.len() / 4]
            };
            self.median = median
        }
        // self.median = (1.0 - total_seqno as f64 / top_seqno as f64).max(0.0);
    }
}
