use std::sync::Arc;

use crate::{
    crypt::{LegacyAEAD, NgAEAD},
    fec::{pre_encode, FrameDecoder},
    protocol::{DataFrameV1, DataFrameV2},
};
use bytes::Bytes;
use cached::Cached;
use cached::TimedSizedCache;
use rustc_hash::{FxHashMap, FxHashSet};

use super::stats::StatGatherer;

/// I/O-free receiving machine.
pub struct RecvMachine {
    version: u64,
    decoder: RunDecoder,
    oob_decoder: OobDecoder,
    recv_crypt_legacy: LegacyAEAD,
    recv_crypt_ng: NgAEAD,
    replay_filter: ReplayFilter,
    ping_calc: Arc<StatGatherer>,
}

impl RecvMachine {
    /// Creates a new machine based on a version and a down decrypter.
    pub fn new(version: u64, recv_crypt_legacy: LegacyAEAD, recv_crypt_ng: NgAEAD) -> Self {
        Self {
            version,
            decoder: RunDecoder::default(),
            oob_decoder: OobDecoder::new(1000),
            recv_crypt_legacy,
            recv_crypt_ng,
            replay_filter: ReplayFilter::default(),
            ping_calc: Default::default(),
        }
    }

    /// Processes a single frame. If successfully decoded, return the inner data.
    pub fn process(&mut self, packet: &[u8]) -> Option<Vec<Bytes>> {
        if self.version == 1 {
            self.process_v1(packet)
        } else {
            self.process_ng(packet)
        }
    }

    fn process_v1(&mut self, packet: &[u8]) -> Option<Vec<Bytes>> {
        let frames: Vec<DataFrameV1> = self.recv_crypt_legacy.pad_decrypt_v1(packet)?;
        let mut output = Vec::with_capacity(1);
        for frame in frames {
            if !self.replay_filter.add(frame.frame_no) {
                return None;
            }
            self.ping_calc.incoming(
                frame.frame_no,
                frame.high_recv_frame_no,
                frame.total_recv_frames,
            );
            output.extend(
                self.decoder
                    .input(
                        frame.run_no,
                        frame.run_idx,
                        frame.data_shards,
                        frame.parity_shards,
                        &frame.body,
                    )
                    .unwrap_or_default(),
            );
        }
        Some(output)
    }

    fn process_ng(&mut self, packet: &[u8]) -> Option<Vec<Bytes>> {
        let plain_frame = match self.version {
            2 => self.recv_crypt_legacy.decrypt(packet)?,
            3 => self.recv_crypt_ng.decrypt(packet)?,
            _ => return None,
        };
        let v2frame = DataFrameV2::depad(&plain_frame)?;
        match v2frame {
            DataFrameV2::Data {
                frame_no,
                high_recv_frame_no,
                total_recv_frames,
                body,
            } => {
                if !self.replay_filter.add(frame_no) {
                    return None;
                }
                self.ping_calc
                    .incoming(frame_no, high_recv_frame_no, total_recv_frames);
                self.oob_decoder.insert_data(frame_no, body.clone());
                Some(vec![body])
            }
            DataFrameV2::Parity {
                data_frame_first,
                data_count,
                parity_count,
                parity_index,
                pad_size,
                body,
            } => {
                let res = self.oob_decoder.insert_parity(
                    ParitySpaceKey {
                        first_data: data_frame_first,
                        data_len: data_count,
                        parity_len: parity_count,
                        pad_size,
                    },
                    parity_index,
                    body,
                );
                let mut toret = Vec::with_capacity(res.len());
                for (i, body) in res {
                    if self.replay_filter.add(i) {
                        toret.push(body);
                    }
                }
                if !toret.is_empty() {
                    tracing::debug!("reconstructed {} packets", toret.len());
                    Some(toret)
                } else {
                    None
                }
            }
        }
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

/// An out-of-band FEC reconstructor
struct OobDecoder {
    data_frames: TimedSizedCache<u64, Bytes>,
    parity_space: TimedSizedCache<ParitySpaceKey, FxHashMap<u8, Bytes>>,
}

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct ParitySpaceKey {
    first_data: u64,
    data_len: u8,
    parity_len: u8,
    pad_size: usize,
}

impl OobDecoder {
    /// Create a new OOB decoder that has at most that many entries
    fn new(max_size: usize) -> Self {
        let data_frames = TimedSizedCache::with_size_and_lifespan(max_size, 1);
        let parity_space = TimedSizedCache::with_size_and_lifespan(max_size, 1);
        Self {
            data_frames,
            parity_space,
        }
    }

    /// Insert a new data frame.
    fn insert_data(&mut self, frame_no: u64, data: Bytes) {
        self.data_frames.cache_set(frame_no, data);
    }

    /// Inserts a new parity frame, and attempt to reconstruct.
    fn insert_parity(
        &mut self,
        parity_info: ParitySpaceKey,
        parity_idx: u8,
        parity: Bytes,
    ) -> Vec<(u64, Bytes)> {
        let hash_ref = self
            .parity_space
            .cache_get_or_set_with(parity_info, FxHashMap::default);
        // if 255 is set, this means that the parity is done
        if hash_ref.get(&255).is_some() {
            return vec![];
        }
        hash_ref.insert(parity_idx, parity);

        // now we attempt reconstruction
        let actual_data = {
            let mut toret = Vec::new();
            for i in parity_info.first_data..parity_info.first_data + (parity_info.data_len as u64)
            {
                if let Some(v) = self.data_frames.cache_get(&i) {
                    toret.push((i, v.clone()))
                }
            }
            toret
        };
        if actual_data.len() + hash_ref.len() >= parity_info.data_len as _ {
            hash_ref.insert(255, Bytes::new());
            let mut decoder =
                FrameDecoder::new(parity_info.data_len as _, parity_info.parity_len as _);
            // we first insert the data shards.
            for (i, data) in actual_data.iter() {
                if data.len() + 2 > parity_info.pad_size {
                    return vec![];
                }
                let data = pre_encode(&data, parity_info.pad_size);
                decoder.decode(&data, (i - parity_info.first_data) as _);
            }
            // then the parity shards
            for (par_idx, data) in hash_ref {
                if let Some(res) = decoder.decode(
                    data,
                    (parity_info.data_len.saturating_add(*par_idx as u8)) as _,
                ) {
                    return res
                        .into_iter()
                        .enumerate()
                        .map(|(i, res)| (parity_info.first_data + i as u64, res))
                        .collect();
                }
            }
        }
        return vec![];
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
