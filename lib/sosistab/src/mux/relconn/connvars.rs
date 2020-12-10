use std::{collections::BTreeSet, collections::VecDeque, time::Instant};

use bytes::Bytes;

use crate::mux::structs::*;

use super::inflight::Inflight;

pub(crate) struct ConnVars {
    pub pre_inflight: VecDeque<Message>,
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
            pre_inflight: VecDeque::new(),
            inflight: Inflight::new(),
            next_free_seqno: 0,
            retrans_count: 0,

            delayed_ack_timer: None,
            ack_seqnos: BTreeSet::new(),

            reorderer: Reorderer::default(),
            lowest_unseen: 0,

            slow_start: true,
            cwnd: 64.0,
            ssthresh: 500.0,
            last_loss: Instant::now(),

            flights: 0,
            last_flight: Instant::now(),

            loss_rate: 0.0,

            closing: false,
        }
    }
}

impl ConnVars {
    pub fn pacing_rate(&self) -> f64 {
        // calculate implicit rate
        self.cwnd / self.inflight.min_rtt().as_secs_f64()
    }

    pub fn congestion_ack(&mut self) {
        let now = Instant::now();
        if now.saturating_duration_since(self.last_flight) > self.inflight.srtt() {
            self.flights += 1;
            self.last_flight = now
        }
        self.loss_rate *= 0.99;
        if self.slow_start && self.cwnd < self.ssthresh {
            self.cwnd += 1.0
        } else {
            let n = (0.23 * self.cwnd.powf(0.8)).max(1.0);
            self.cwnd += n / self.cwnd;
        }
    }

    pub fn congestion_loss(&mut self) {
        self.slow_start = false;
        self.loss_rate = self.loss_rate * 0.99 + 0.01;
        let now = Instant::now();
        if now.saturating_duration_since(self.last_loss) > self.inflight.srtt() {
            let bdp = self.inflight.bdp();
            self.cwnd = self.cwnd.min((self.cwnd * 0.5).max(bdp));
            tracing::debug!(
                "LOSS CWND => {}; loss rate {}, srtt {}ms, rate {}",
                self.cwnd,
                self.loss_rate,
                self.inflight.srtt().as_millis(),
                self.inflight.rate()
            );
            self.last_loss = now;
        }
    }
}
