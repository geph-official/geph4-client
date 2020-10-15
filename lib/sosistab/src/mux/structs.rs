use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, num::NonZeroU32};

/// A sequence number.
pub type Seqno = u64;

/// A message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    Urel(Bytes),
    Rel {
        kind: RelKind,
        stream_id: u16,
        seqno: Seqno,
        payload: Bytes,
    },
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum RelKind {
    Syn,
    SynAck,
    Data,
    DataAck,
    Fin,
    FinAck,
    Rst,
}

#[derive(Clone)]
pub struct Reorderer<T: Clone> {
    pkts: HashMap<Seqno, T>,
    min: Seqno,
}

impl<T: Clone> Default for Reorderer<T> {
    fn default() -> Self {
        Reorderer {
            pkts: HashMap::new(),
            min: 0,
        }
    }
}

impl<T: Clone> Reorderer<T> {
    pub fn insert(&mut self, seq: Seqno, item: T) -> bool {
        if seq >= self.min && seq <= self.min + 30000 {
            if self.pkts.insert(seq, item).is_some() {
                log::warn!("spurious retransmission of {} received", seq);
            }
            // self.pkts.insert(seq, item);
            true
        } else {
            log::trace!("rejecting (seq={}, min={})", seq, self.min);
            false
        }
    }
    pub fn take(&mut self) -> Vec<T> {
        let mut output = Vec::new();
        for idx in self.min.. {
            if let Some(item) = self.pkts.remove(&idx) {
                output.push(item.clone());
                self.min = idx + 1;
            } else {
                break;
            }
        }
        output
    }
}

pub struct VarRateLimit {
    limiter: governor::RateLimiter<
        governor::state::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::MonotonicClock,
    >,
}

const DIVIDER: u32 = 1000000;
const DIVIDER_FRAC: u32 = 100;

impl VarRateLimit {
    pub fn new() -> Self {
        VarRateLimit {
            limiter: governor::RateLimiter::direct_with_clock(
                governor::Quota::per_second(NonZeroU32::new(DIVIDER).unwrap())
                    .allow_burst(NonZeroU32::new(DIVIDER / DIVIDER_FRAC).unwrap()),
                &governor::clock::MonotonicClock::default(),
            ),
        }
    }

    pub async fn wait(&self, speed: u32) {
        let speed = speed.max(DIVIDER_FRAC * 2);
        let divided = NonZeroU32::new((DIVIDER / speed.max(1)).max(1)).unwrap();
        // self.limiter.until_n_ready(divided).await.unwrap()
        while let Err(governor::NegativeMultiDecision::BatchNonConforming(_, until)) =
            self.limiter.check_n(divided)
        {
            smol::Timer::at(until.earliest_possible()).await;
        }
    }

    // pub async fn wait(&self, speed: u32) {
    //     while !self.check(speed.max(DIVIDER_FRAC * 2)) {
    //         smol::Timer::after(Duration::from_millis(1)).await;
    //     }
    // }
}
