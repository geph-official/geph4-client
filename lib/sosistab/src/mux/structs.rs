use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration, time::Instant};

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
    pub fn seqno(&self) -> Seqno {
        match self {
            Message::Rel { seqno, .. } => *seqno,
            _ => 0,
        }
    }
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
        if seq >= self.min && seq <= self.min + 20000 {
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
        if self.pkts.is_empty() {
            self.pkts = HashMap::new()
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
