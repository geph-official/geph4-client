use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use crate::runtime::RateLimiter;

/// Receive-side loss calculator.
///
/// The basic algorithm is to note "gaps" in packets, then nothing them as lost when those gaps are unfilled for a while.
pub struct RecvLossCalc {
    last_seen_seqno: u64,
    good_seqnos: BTreeMap<u64, Instant>,
    gap_seqnos: BTreeMap<u64, Instant>,
    lost_count: f64,
    good_count: f64,

    // "half-life" of the loss calculation
    window: f64,
    last_loss_update: Instant,

    // rate limit that denies "floods" of packets to prevent congestion-related losses from being recorded
    congestion_limit: RateLimiter,
}

impl RecvLossCalc {
    /// Creates a new RecvLossCalc with a given window. The window value is approximately how many seconds of data to consider when calculating loss.
    pub fn new(window: f64) -> Self {
        Self {
            last_seen_seqno: 0,
            good_seqnos: BTreeMap::new(),
            gap_seqnos: BTreeMap::new(),
            lost_count: 0.0,
            good_count: 1.0,

            window,
            last_loss_update: Instant::now(),

            congestion_limit: RateLimiter::new(1000),
        }
    }

    /// Record a seen seqno
    pub fn record(&mut self, seqno: u64) {
        // first try to fill a gap with this seqno
        if let Some(gap) = self.gap_seqnos.remove(&seqno) {
            self.good_seqnos.insert(seqno, gap);
        } else if seqno > self.last_seen_seqno {
            for missing in (self.last_seen_seqno..seqno).skip(1) {
                self.gap_seqnos.insert(missing, Instant::now());
            }
            self.last_seen_seqno = seqno;
            self.good_seqnos.insert(seqno, Instant::now());
        }
        // prune and calculate loss
        self.calculate_loss();
    }

    /// Calculate loss
    pub fn calculate_loss(&mut self) -> f64 {
        let mut torem = vec![];
        let under_limit = self.congestion_limit.check(1000);
        let now = Instant::now();
        for (key, val) in self.good_seqnos.iter() {
            if now.saturating_duration_since(*val) > Duration::from_secs(1) {
                torem.push(*key);
                if under_limit {
                    self.good_count += 1.0;
                }
            } else {
                break;
            }
        }
        for (key, val) in self.gap_seqnos.iter() {
            if now.saturating_duration_since(*val) > Duration::from_secs(1) {
                torem.push(*key);
                if under_limit {
                    self.lost_count += 1.0;
                }
            } else {
                break;
            }
        }
        if under_limit {
            for item in torem {
                self.good_seqnos.remove(&item);
                self.gap_seqnos.remove(&item);
            }
            // divide the good lost stuff
            let divider = 2.0f64.powf(
                now.saturating_duration_since(self.last_loss_update)
                    .as_secs_f64()
                    / self.window,
            );
            self.last_loss_update = now;
            if self.good_count > 10.0 {
                self.good_count /= divider;
                self.lost_count /= divider;
            }
        }
        // loss
        self.lost_count / (self.good_count + self.lost_count)
    }
}
