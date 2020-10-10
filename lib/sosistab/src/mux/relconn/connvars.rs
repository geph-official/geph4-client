use std::{collections::BTreeSet, time::Instant};

use bytes::Bytes;

use crate::mux::structs::*;

use super::inflight::Inflight;

pub(crate) struct ConnVars {
    pub inflight: Inflight,
    pub next_free_seqno: Seqno,
    pub retrans_count: u64,

    pub delayed_ack_timer: Option<Instant>,
    pub ack_seqnos: BTreeSet<Seqno>,

    pub reorderer: Reorderer<Bytes>,
    pub lowest_unseen: Seqno,
    // read_buffer: VecDeque<Bytes>,
    slow_start: bool,
    ssthresh: f64,
    pub cwnd: f64,
    last_loss: Instant,

    flights: u64,
    last_flight: Instant,

    loss_rate: f64,

    pub closing: bool,
}

impl Default for ConnVars {
    fn default() -> Self {
        ConnVars {
            inflight: Inflight::new(),
            next_free_seqno: 0,
            retrans_count: 0,

            delayed_ack_timer: None,
            ack_seqnos: BTreeSet::new(),

            reorderer: Reorderer::default(),
            lowest_unseen: 0,

            slow_start: true,
            ssthresh: 10000.0,
            cwnd: 16.0,
            last_loss: Instant::now(),

            flights: 0,
            last_flight: Instant::now(),

            loss_rate: 0.0,

            closing: false,
        }
    }
}

impl ConnVars {
    fn cwnd_target(&self) -> f64 {
        (self.inflight.bdp() * 1.5).min(10000.0).max(16.0)
    }

    pub fn pacing_rate(&self) -> f64 {
        if self.loss_rate > 0.02 {
            return self.inflight.rate() * 0.5;
        }
        // self.inflight.bandwidth_estimate() * 2.0
        // 10000.0
        let multiplier = if self.flights % 100 == 1 {
            0.1
        } else {
            match self.flights % 2 {
                0 => 1.5,
                1 => 0.5,
                _ => 0.95,
            }
        };
        self.inflight.rate() * multiplier
    }

    pub fn congestion_ack(&mut self) {
        self.loss_rate *= 0.99;
        self.cwnd = (self.cwnd * 0.9 + self.cwnd_target() * 0.1).min(self.cwnd + 32.0 / self.cwnd);
        let now = Instant::now();
        if now.saturating_duration_since(self.last_flight) > self.inflight.srtt() {
            self.flights += 1;
            self.last_flight = now
        }
    }

    pub fn congestion_loss(&mut self) {
        self.loss_rate = self.loss_rate * 0.99 + 0.01;
        let now = Instant::now();
        if now.saturating_duration_since(self.last_loss) > self.inflight.srtt() {
            // if self.loss_rate > 0.02 {
            self.cwnd *= 0.8;
            // }
            log::debug!(
                "LOSS CWND => {}; loss rate {}, srtt {}ms",
                self.cwnd,
                self.loss_rate,
                self.inflight.srtt().as_millis()
            );
            self.last_loss = now;
        }
    }
}
