use std::sync::Arc;

use bytes::Bytes;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::{fec::FrameDecoder, msg::DataFrame};

use super::stats::StatGatherer;

/// I/O-free receiving machine.
#[derive(Default)]
pub struct RecvMachine {
    decoder: RunDecoder,
    replay_filter: ReplayFilter,
    ping_calc: Arc<StatGatherer>,
}

impl RecvMachine {
    /// Processes a single frame. If successfully decoded, return the inner data.
    pub fn process(&mut self, frame: &DataFrame) -> Option<Vec<Bytes>> {
        if !self.replay_filter.add(frame.frame_no) {
            return None;
        }
        self.ping_calc.incoming(frame);
        self.decoder.input(
            frame.run_no,
            frame.run_idx,
            frame.data_shards,
            frame.parity_shards,
            &frame.body,
        )
    }

    /// Retrieves the inner stat gatherer.
    pub fn get_gather(&self) -> Arc<StatGatherer> {
        self.ping_calc.clone()
    }
}

/// A filter for replays. Records recently seen seqnos and rejects either repeats or really old seqnos.
#[derive(Debug, Default)]
struct ReplayFilter {
    top_seqno: u64,
    bottom_seqno: u64,
    seen_seqno: FxHashSet<u64>,
}

impl ReplayFilter {
    fn add(&mut self, seqno: u64) -> bool {
        if seqno < self.bottom_seqno {
            // out of range. we can't know, so we just say no
            return false;
        }
        // check the seen
        if self.seen_seqno.contains(&seqno) {
            return false;
        }
        self.top_seqno = seqno;
        while self.top_seqno - self.bottom_seqno > 10000 {
            self.seen_seqno.remove(&self.bottom_seqno);
            self.bottom_seqno += 1;
        }
        true
    }
}

/// A reordering-resistant FEC reconstructor
#[derive(Default)]
struct RunDecoder {
    top_run: u64,
    bottom_run: u64,
    decoders: FxHashMap<u64, FrameDecoder>,
    total_count: u64,
    correct_count: u64,

    total_data_shards: u64,
    total_parity_shards: u64,
}

impl RunDecoder {
    fn input(
        &mut self,
        run_no: u64,
        run_idx: u8,
        data_shards: u8,
        parity_shards: u8,
        bts: &[u8],
    ) -> Option<Vec<Bytes>> {
        if run_no >= self.bottom_run {
            if run_no > self.top_run {
                self.top_run = run_no;
                // advance bottom
                while self.top_run - self.bottom_run > 100 {
                    if let Some(dec) = self.decoders.remove(&self.bottom_run) {
                        if dec.good_pkts() + dec.lost_pkts() > 1 {
                            self.total_count += (dec.good_pkts() + dec.lost_pkts()) as u64;
                            self.correct_count += dec.good_pkts() as u64
                        }
                    }
                    self.bottom_run += 1;
                }
            }
            let decoder = self
                .decoders
                .entry(run_no)
                .or_insert_with(|| FrameDecoder::new(data_shards as usize, parity_shards as usize));
            if run_idx < data_shards {
                self.total_data_shards += 1
            } else {
                self.total_parity_shards += 1
            }
            if let Some(res) = decoder.decode(bts, run_idx as usize) {
                Some(res)
            } else {
                None
            }
        } else {
            None
        }
    }
}
