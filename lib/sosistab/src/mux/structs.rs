use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
impl<T: Clone> Reorderer<T> {
    pub fn insert(&mut self, seq: Seqno, item: T) -> bool {
        if seq >= self.min && seq <= self.min + 20000 {
            if self.pkts.insert(seq, item).is_some() {
                log::trace!("spurious retransmission of {} received", seq);
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
                output.push(item.clone());
                self.min = idx + 1;
            } else {
                break;
            }
        }
        output
    }
}
