use parking_lot::RwLock;
use std::{
    collections::VecDeque,
    sync::{atomic::AtomicU64, Arc},
    time::{Duration, Instant},
};

use crate::StatsGatherer;
/// Stat gatherer
pub struct StatsCalculator {
    high_recv_frame_no: AtomicU64,
    total_recv_frames: AtomicU64,
    actual_loss: RwLock<Option<f64>>,
    loss_calc: RwLock<SendLossCalc>,
    ping_calc: RwLock<PingCalc>,
    gather: Arc<StatsGatherer>,
}

impl StatsCalculator {
    /// Creates a new StatCalculator based on a StatsGatherer.
    pub fn new(gather: Arc<StatsGatherer>) -> Self {
        Self {
            high_recv_frame_no: Default::default(),
            total_recv_frames: Default::default(),
            actual_loss: Default::default(),
            loss_calc: Default::default(),
            ping_calc: Default::default(),
            gather,
        }
    }

    /// Process an incoming dataframe.
    pub fn incoming(
        &self,
        frame_no: u64,
        their_hrfn: u64,
        their_trf: u64,
        actual_loss: Option<f64>,
    ) {
        self.high_recv_frame_no
            .fetch_max(frame_no, std::sync::atomic::Ordering::Relaxed);
        self.total_recv_frames
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.ping_calc.write().ack(their_hrfn);
        if let Some(actual_loss) = actual_loss {
            // tracing::warn!("recording actual loss {}", actual_loss);
            self.actual_loss.write().replace(actual_loss);
        } else {
            self.loss_calc.write().update_params(their_hrfn, their_trf);
        }
        self.sync()
    }

    fn sync(&self) {
        self.gather
            .update("high_recv", self.high_recv_frame_no() as f32);
        self.gather
            .update("total_recv", self.total_recv_frames() as f32);
        self.gather.update("send_loss", self.loss() as f32);
        self.gather.update("smooth_ping", self.ping().as_secs_f32());
        self.gather
            .update("raw_ping", self.raw_ping().as_secs_f32());
    }

    /// Get high recv frame no
    pub fn high_recv_frame_no(&self) -> u64 {
        self.high_recv_frame_no
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get total recv frames
    pub fn total_recv_frames(&self) -> u64 {
        self.total_recv_frames
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get loss
    pub fn loss(&self) -> f64 {
        self.actual_loss
            .read()
            .clone()
            .unwrap_or_else(|| self.loss_calc.read().median)
    }

    /// Get loss as u8
    pub fn loss_u8(&self) -> u8 {
        (self.loss() * 255.0) as u8
    }

    /// Get ping
    pub fn ping(&self) -> Duration {
        self.ping_calc.read().ping()
    }

    /// Get rawping
    pub fn raw_ping(&self) -> Duration {
        self.ping_calc.read().raw_ping()
    }

    /// "Send" a ping
    pub fn ping_send(&self, frame_no: u64) {
        self.ping_calc.write().send(frame_no)
    }

    // /// "Ack" a ping
    // pub fn ping_ack(&self, frame_no: u64) {
    //     self.ping_calc.write().ack(frame_no)
    // }
}

/// A ping calculator
#[derive(Debug, Default)]
struct PingCalc {
    send_seqno: Option<u64>,
    send_time: Option<Instant>,
    pings: VecDeque<Duration>,
}

impl PingCalc {
    pub fn send(&mut self, sn: u64) {
        if self.send_seqno.is_some() {
            return;
        }
        self.send_seqno = Some(sn);
        self.send_time = Some(Instant::now());
    }
    pub fn ack(&mut self, sn: u64) {
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
    pub fn ping(&self) -> Duration {
        self.pings
            .iter()
            .cloned()
            .min()
            .unwrap_or_else(|| Duration::from_secs(1000))
    }
    pub fn raw_ping(&self) -> Duration {
        self.pings
            .iter()
            .cloned()
            .last()
            .unwrap_or_else(|| Duration::from_secs(1000))
    }
}

/// A packet loss calculator for the sending side.
#[derive(Debug)]
struct SendLossCalc {
    last_top_seqno: u64,
    last_total_seqno: u64,
    last_time: Instant,
    loss_samples: VecDeque<f64>,
    median: f64,
}

impl Default for SendLossCalc {
    fn default() -> Self {
        Self::new()
    }
}

impl SendLossCalc {
    pub fn new() -> SendLossCalc {
        SendLossCalc {
            last_top_seqno: 0,
            last_total_seqno: 0,
            last_time: Instant::now(),
            loss_samples: VecDeque::new(),
            median: 0.0,
        }
    }

    pub fn update_params(&mut self, top_seqno: u64, total_seqno: u64) {
        let now = Instant::now();
        if total_seqno > self.last_total_seqno + 100
            && top_seqno > self.last_top_seqno + 100
            && now.saturating_duration_since(self.last_time).as_millis() > 500
        {
            let delta_top = top_seqno.saturating_sub(self.last_top_seqno) as f64;
            let delta_total = total_seqno.saturating_sub(self.last_total_seqno) as f64;
            tracing::debug!(
                "updating loss calculator with {}/{}",
                delta_total,
                delta_top
            );
            self.last_top_seqno = top_seqno;
            self.last_total_seqno = total_seqno;
            let loss_sample = 1.0 - delta_total / delta_top.max(delta_total);
            self.loss_samples.push_back(loss_sample);
            if self.loss_samples.len() > 16 {
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
