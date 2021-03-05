use crate::mux::structs::*;
use std::{
    cmp::Reverse,
    collections::BTreeSet,
    collections::VecDeque,
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

    delivered: u64,
    delivered_time: Instant,
}

/// A data structure that tracks in-flight packets.
pub struct Inflight {
    segments: VecDeque<InflightEntry>,
    inflight_count: usize,
    times: priority_queue::PriorityQueue<Seqno, Reverse<Instant>>,
    fast_retrans: BTreeSet<Seqno>,
    rtt: RttCalculator,
    rate: RateCalculator,

    delivered: u64,
    delivered_time: Instant,
}

impl Inflight {
    pub fn new() -> Self {
        Inflight {
            segments: VecDeque::new(),
            inflight_count: 0,
            times: priority_queue::PriorityQueue::new(),
            fast_retrans: BTreeSet::new(),
            rtt: RttCalculator::default(),
            rate: RateCalculator::default(),

            delivered: 0,
            delivered_time: Instant::now(),
        }
    }

    pub fn rate(&self) -> f64 {
        self.rate.rate
    }

    pub fn bdp(&self) -> f64 {
        self.rate() * self.min_rtt().as_secs_f64()
    }

    pub fn len(&self) -> usize {
        self.segments.len()
    }

    pub fn inflight(&self) -> usize {
        dbg!(self.inflight_count);
        if self.inflight_count > self.segments.len() {
            panic!(
                "inflight_count = {}, segment len = {}",
                self.inflight_count,
                self.segments.len()
            );
        }
        self.inflight_count
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

    pub fn mark_acked_lt(&mut self, seqno: Seqno) {
        for segseq in self.segments.iter().map(|v| v.seqno).collect::<Vec<_>>() {
            if segseq < seqno {
                self.mark_acked(segseq);
            } else {
                break;
            }
        }
    }

    pub fn mark_acked(&mut self, seqno: Seqno) -> bool {
        let mut toret = false;
        let now = Instant::now();
        // mark the right one
        if let Some(entry) = self.segments.front() {
            let first_seqno = entry.seqno;
            if seqno >= first_seqno {
                let offset = (seqno - first_seqno) as usize;
                let rtt_var = self.rtt_var().max(Duration::from_millis(50));
                // fast: if this ack is for something more than FASTRT_THRESH "into" the buffer, we do fast retransmit
                if let Some(acked_send_time) = self.segments.get_mut(offset).map(|v| v.send_time) {
                    for entry in self.segments.iter_mut() {
                        if entry.send_time + rtt_var < acked_send_time {
                            if !entry.acked && entry.retrans == 0 {
                                entry.retrans += 1;
                                tracing::debug!(
                                    "fast retransmit {} (retrans {})",
                                    entry.seqno,
                                    entry.retrans
                                );
                                self.fast_retrans.insert(entry.seqno);
                            }
                        } else {
                            break;
                        }
                    }
                }

                if let Some(seg) = self.segments.get_mut(offset) {
                    if !seg.acked {
                        self.delivered += 1;
                        self.delivered_time = now;
                        toret = true;
                        seg.acked = true;
                        self.inflight_count -= 1;
                        if seg.retrans == 0 {
                            if let Message::Rel { .. } = &seg.payload {
                                // calculate rate
                                let data_acked = self.delivered - seg.delivered;
                                let ack_elapsed = self
                                    .delivered_time
                                    .saturating_duration_since(seg.delivered_time);
                                let rate_sample = data_acked as f64 / ack_elapsed.as_secs_f64();
                                self.rate.record_sample(rate_sample)
                            }
                        }

                        if seg.retrans == 0 {
                            self.rtt
                                .record_sample(now.saturating_duration_since(seg.send_time))
                        }
                    }
                }
                // shrink if possible
                while self.len() > 0 && self.segments.front().unwrap().acked {
                    self.segments.pop_front();
                }
            }
        }
        toret
    }

    pub fn insert(&mut self, seqno: Seqno, msg: Message) {
        let rto = self.rtt.rto();
        if self.get_seqno(seqno).is_none() {
            self.segments.push_back(InflightEntry {
                seqno,
                acked: false,
                send_time: Instant::now(),
                payload: msg,
                retrans: 0,
                delivered: self.delivered,
                delivered_time: self.delivered_time,
            });
            self.inflight_count += 1;
        }
        self.times.push(seqno, Reverse(Instant::now() + rto));
    }

    pub fn get_seqno(&mut self, seqno: Seqno) -> Option<&mut InflightEntry> {
        if let Some(first_entry) = self.segments.front() {
            let first_seqno = first_entry.seqno;
            if seqno >= first_seqno {
                let offset = (seqno - first_seqno) as usize;
                return self.segments.get_mut(offset);
            }
        }
        None
    }

    pub fn wait_first(&mut self) -> smol::Timer {
        if self.fast_retrans.iter().next().is_some() {
            return smol::Timer::at(Instant::now());
        }
        if !self.times.is_empty() {
            let (_, time) = self.times.peek().unwrap();
            return smol::Timer::at(time.0);
        }
        smol::Timer::at(Instant::now() + Duration::from_secs(100000000))
    }

    pub fn pop_first(&mut self) -> anyhow::Result<u64> {
        if let Some(seq) = self.fast_retrans.iter().next() {
            let seq = *seq;
            self.fast_retrans.remove(&seq);
            Ok(seq)
        } else {
            let (seqno, _) = self
                .times
                .pop()
                .ok_or_else(|| anyhow::anyhow!("could not pop from times"))?;
            let mut rto = self.rtt.rto();
            if let Some(seg) = self.get_seqno(seqno) {
                if !seg.acked {
                    seg.retrans += 1;
                    let rtx = seg.retrans;
                    for _ in 0..rtx {
                        rto *= 2;
                        // rto /= 2
                    }

                    self.times.push(seqno, Reverse(Instant::now() + rto));
                    Ok(seqno)
                } else {
                    anyhow::bail!("popped was already acked?!")
                }
            } else {
                anyhow::bail!("popped was already acked?!");
            }
        }
    }
}

struct RateCalculator {
    rate: f64,
    rate_update_time: Instant,
}

impl Default for RateCalculator {
    fn default() -> Self {
        RateCalculator {
            rate: 500.0,
            rate_update_time: Instant::now(),
        }
    }
}

impl RateCalculator {
    fn record_sample(&mut self, sample: f64) {
        let now = Instant::now();
        if now
            .saturating_duration_since(self.rate_update_time)
            .as_secs()
            > 3
            || sample > self.rate
        {
            self.rate = sample;
            self.rate_update_time = now;
        }
    }
}

fn diff(a: u64, b: u64) -> u64 {
    if b > a {
        b - a
    } else {
        a - b
    }
}
