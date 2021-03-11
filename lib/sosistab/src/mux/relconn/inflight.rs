use crate::mux::structs::*;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use self::calc::RttCalculator;

mod calc;

#[derive(Debug, Clone)]
/// An element of Inflight.
pub struct InflightEntry {
    seqno: Seqno,
    acked: bool,
    send_time: Instant,
    pub retrans: u64,
    pub payload: Message,

    rto_duration: Duration,
}

impl InflightEntry {
    fn retrans_time(&self) -> Instant {
        self.send_time + self.rto_duration
    }
}

/// A data structure that tracks in-flight packets.
pub struct Inflight {
    segments: BTreeMap<Seqno, InflightEntry>,
    first_rto: Option<(Seqno, Instant)>,
    rtt: RttCalculator,
}

impl Inflight {
    /// Creates a new Inflight.
    pub fn new() -> Self {
        Inflight {
            segments: Default::default(),
            first_rto: None,
            rtt: Default::default(),
        }
    }

    pub fn len(&self) -> usize {
        self.segments.len()
    }

    pub fn inflight(&self) -> usize {
        self.len()
    }

    pub fn srtt(&self) -> Duration {
        self.rtt.srtt()
    }

    pub fn rto(&self) -> Duration {
        self.rtt.rto()
    }

    pub fn rtt_var(&self) -> Duration {
        self.rtt.rtt_var()
    }

    pub fn min_rtt(&self) -> Duration {
        self.rtt.min_rtt()
    }

    /// Mark all inflight packets less than a certain sequence number as acknowledged.
    pub fn mark_acked_lt(&mut self, seqno: Seqno) {
        let mut to_remove = vec![];
        for (k, _) in self.segments.iter() {
            if *k < seqno {
                to_remove.push(*k);
            } else {
                // we can rely on iteration order
                break;
            }
        }
        for seqno in to_remove {
            self.mark_acked(seqno);
        }
    }

    /// Marks a particular inflight packet as acknowledged. Returns whether or not there was actually such an inflight packet.
    pub fn mark_acked(&mut self, seqno: Seqno) -> bool {
        let now = Instant::now();

        if let Some(seg) = self.segments.remove(&seqno) {
            if seg.retrans == 0 {
                self.rtt
                    .record_sample(now.saturating_duration_since(seg.send_time))
            }
            true
        } else {
            false
        }
    }

    /// Inserts a packet to the inflight.
    pub fn insert(&mut self, seqno: Seqno, msg: Message) {
        let now = Instant::now();
        let rto_duration = self.rtt.rto();
        let rto = now + rto_duration;
        self.segments.insert(
            seqno,
            InflightEntry {
                seqno,
                acked: false,
                send_time: now,
                payload: msg,
                retrans: 0,
                rto_duration,
            },
        );
        if let Some((_, old_rto)) = self.first_rto {
            if rto < old_rto {
                self.first_rto = Some((seqno, rto))
            }
        } else {
            self.first_rto = Some((seqno, rto))
        }
    }

    /// Returns the retransmission time of the first possibly retransmitted packet, as well as its seqno.
    pub fn first_rto(&self) -> Option<(Seqno, Instant)> {
        self.first_rto
    }

    /// Recalculates the first rto
    fn recalc_first_rto(&mut self) {
        // hopefully this is not way too slow
        self.first_rto = self
            .segments
            .iter()
            .min_by_key(|v| v.1.retrans_time())
            .map(|v| (*v.0, v.1.retrans_time()))
    }

    /// Retransmits a particular seqno.
    pub fn retransmit(&mut self, seqno: Seqno) -> Option<Message> {
        let payload = {
            let entry = self.segments.get_mut(&seqno);
            entry.map(|entry| {
                entry.rto_duration += entry.rto_duration;
                entry.retrans += 1;
                entry.payload.clone()
            })
        };
        self.recalc_first_rto();
        payload
    }
}

// struct RateCalculator {
//     rate: f64,
//     rate_update_time: Instant,
// }

// impl Default for RateCalculator {
//     fn default() -> Self {
//         RateCalculator {
//             rate: 500.0,
//             rate_update_time: Instant::now(),
//         }
//     }
// }

// impl RateCalculator {
//     fn record_sample(&mut self, sample: f64) {
//         let now = Instant::now();
//         if now
//             .saturating_duration_since(self.rate_update_time)
//             .as_secs()
//             > 3
//             || sample > self.rate
//         {
//             self.rate = sample;
//             self.rate_update_time = now;
//         }
//     }
// }

// fn diff(a: u64, b: u64) -> u64 {
//     if b > a {
//         b - a
//     } else {
//         a - b
//     }
// }
