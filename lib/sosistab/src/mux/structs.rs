use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Duration, time::Instant};

use super::mempress;

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

impl Message {
    /// clears the payload, freeing memory sooner rather than later
    pub fn clear_payload(&mut self) {
        match self {
            Message::Urel(b) => *b = Bytes::new(),
            Message::Rel { payload, .. } => *payload = Bytes::new(),
        }
    }
}

// impl Message {
//     pub fn seqno(&self) -> Seqno {
//         match self {
//             Message::Rel { seqno, .. } => *seqno,
//             _ => 0,
//         }
//     }
// }

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
    pkts: BTreeMap<Seqno, T>,
    min: Seqno,
}

impl<T: Clone> Default for Reorderer<T> {
    fn default() -> Self {
        Reorderer {
            pkts: BTreeMap::new(),
            min: 0,
        }
    }
}

impl<T: Clone> Drop for Reorderer<T> {
    fn drop(&mut self) {
        mempress::decr(self.pkts.len());
    }
}

impl<T: Clone> Reorderer<T> {
    pub fn insert(&mut self, seq: Seqno, item: T) -> bool {
        if seq >= self.min && seq <= self.min + 20000 {
            if self.pkts.insert(seq, item).is_some() {
                log::trace!("spurious retransmission of {} received", seq);
            } else {
                mempress::incr(1);
            }
            // self.pkts.insert(seq, item);
            true
        } else {
            log::trace!("rejecting (seq={}, min={})", seq, self.min);
            false
        }
    }
    pub fn take(&mut self) -> Vec<T> {
        let mut output = Vec::with_capacity(self.pkts.len());
        for idx in self.min.. {
            if let Some(item) = self.pkts.remove(&idx) {
                mempress::decr(1);
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
    next_time: smol::lock::Mutex<Instant>,
}

impl VarRateLimit {
    pub fn new() -> Self {
        Self {
            next_time: smol::lock::Mutex::new(Instant::now()),
        }
    }

    pub async fn wait(&self, speed: u32) {
        let mut next_time = self.next_time.lock().await;
        smol::Timer::at(*next_time).await;
        *next_time = Instant::now()
            .checked_add(Duration::from_micros(1_000_000 / (speed.max(100)) as u64))
            .expect("time OOB")
    }

    // pub async fn wait(&self, speed: u32) {
    //     while !self.check(speed.max(DIVIDER_FRAC * 2)) {
    //         smol::Timer::after(Duration::from_millis(1)).await;
    //     }
    // }
}
