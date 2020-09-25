use crate::mux::structs::*;
use std::{
    cmp::Reverse,
    collections::BTreeSet,
    collections::VecDeque,
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct InflightEntry {
    seqno: Seqno,
    acked: bool,
    send_time: Instant,
    pub retrans: u64,
    pub payload: Message,
}

#[derive(Default)]
pub struct Inflight {
    segments: VecDeque<InflightEntry>,
    inflight_count: usize,
    times: priority_queue::PriorityQueue<Seqno, Reverse<Instant>>,
    fast_retrans: BTreeSet<Seqno>,
    rtt: RttCalculator,
}

impl Inflight {
    pub fn bdp(&self) -> f64 {
        self.rtt.bdp()
    }

    pub fn len(&self) -> usize {
        self.segments.len()
    }

    pub fn inflight(&self) -> usize {
        if self.inflight_count > self.segments.len() {
            panic!(
                "inflight_count = {}, segment len = {}",
                self.inflight_count,
                self.segments.len()
            );
        }
        self.inflight_count
    }

    pub fn rto(&self) -> Duration {
        self.rtt.rto()
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
                if let Some(seg) = self.segments.get_mut(offset) {
                    if !seg.acked {
                        toret = true;
                        seg.acked = true;
                        self.inflight_count -= 1;
                        if seg.retrans == 0 {
                            self.rtt
                                .record_sample(now.saturating_duration_since(seg.send_time));
                        }
                        // time-based fast retransmit
                        // let fast_retrans_thresh = self.rtt.srtt / 4;
                        // let seg = seg.clone();
                        // for cand in self.segments.iter_mut() {
                        //     if !cand.acked
                        //         && cand.retrans == 0
                        //         && seg
                        //             .send_time
                        //             .saturating_duration_since(cand.send_time)
                        //             .as_millis() as u64
                        //             > fast_retrans_thresh
                        //     {
                        //         self.fast_retrans.insert(cand.seqno);
                        //         cand.retrans += 1;
                        //     }
                        // }
                        // packet-based fast retransmit
                        // for cand in self.segments.iter_mut() {
                        //     if !cand.acked && cand.retrans == 0 && seqno >= cand.seqno + 3 {
                        //         self.fast_retrans.insert(cand.seqno);
                        //         cand.retrans += 1;
                        //         self.times.push(cand.seqno, Reverse(Instant::now() + rto));
                        //     }
                        // }
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

    pub async fn wait_first(&mut self) -> (Seqno, bool) {
        if let Some(seq) = self.fast_retrans.iter().next() {
            let seq = *seq;
            self.fast_retrans.remove(&seq);
            return (seq, false);
        }
        while !self.times.is_empty() {
            let (_, time) = self.times.peek().unwrap();
            let time = time.0.saturating_duration_since(Instant::now());
            smol::Timer::after(time).await;
            let (seqno, _) = self.times.pop().unwrap();
            let rto = self.rtt.rto();
            if let Some(seg) = self.get_seqno(seqno) {
                if !seg.acked {
                    seg.retrans += 1;
                    // eprintln!(
                    //     "retransmitting seqno {} {} times after {}ms",
                    //     seg.seqno,
                    //     seg.retrans,
                    //     Instant::now()
                    //         .saturating_duration_since(seg.send_time)
                    //         .as_millis()
                    // );
                    let rtx = seg.retrans;
                    let minrto = rto * 2u32.pow(rtx as u32);

                    self.times.push(seqno, Reverse(Instant::now() + minrto));
                    return (seqno, true);
                }
            }
        }
        smol::future::pending().await
    }
}

struct RttCalculator {
    // standard TCP stuff
    srtt: u64,
    rttvar: u64,
    rto: u64,

    // rate estimation
    min_rtt: u64,
    rtt_update_time: Instant,
    arrival_interval: f64,
    last_deliv_time: Instant,

    existing: bool,
}

impl Default for RttCalculator {
    fn default() -> Self {
        RttCalculator {
            srtt: 1000,
            rttvar: 1000,
            rto: 1000,
            min_rtt: 1000,
            rtt_update_time: Instant::now(),
            arrival_interval: 0.0,
            last_deliv_time: Instant::now(),
            existing: false,
        }
    }
}

impl RttCalculator {
    fn record_sample(&mut self, sample: Duration) {
        let sample = sample.as_millis() as u64;
        if !self.existing {
            self.srtt = sample;
            self.rttvar = sample / 2;
        } else {
            self.rttvar = self.rttvar * 3 / 4 + diff(self.srtt, sample) / 4;
            self.srtt = self.srtt * 7 / 8 + sample / 8;
        }
        self.rto = sample.max(self.srtt + (4 * self.rttvar).max(10)) + 50;
        // delivery rate
        let now = Instant::now();
        if self.srtt < self.min_rtt
            || now
                .saturating_duration_since(self.rtt_update_time)
                .as_millis()
                > 2000
        {
            self.min_rtt = self.srtt;
            self.rtt_update_time = now;
        }
        let drate_sample = now.duration_since(self.last_deliv_time).as_secs_f64();
        self.arrival_interval = self.arrival_interval * 0.999 + drate_sample * 0.001;
        self.last_deliv_time = now;
    }

    fn rto(&self) -> Duration {
        Duration::from_millis(self.rto)
    }

    fn bdp(&self) -> f64 {
        1.0 / self.arrival_interval * (self.min_rtt as f64 / 1000.0)
    }
}

fn diff(a: u64, b: u64) -> u64 {
    if b > a {
        b - a
    } else {
        a - b
    }
}
