use std::sync::Arc;

use bytes::Bytes;

use super::{post_decode, wrapped::WrappedReedSolomon};

/// A single-use FEC decoder.
#[derive(Debug)]
pub struct FrameDecoder {
    data_shards: usize,
    parity_shards: usize,
    space: Vec<Vec<u8>>,
    present: Vec<bool>,
    present_count: usize,
    rs_decoder: Arc<WrappedReedSolomon>,
    done: bool,
}

impl FrameDecoder {
    #[tracing::instrument(level = "trace")]
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        // if rand::random::<f64>() < 0.1 {
        tracing::trace!("decoding with {}/{}", data_shards, parity_shards);
        // }
        FrameDecoder {
            data_shards,
            parity_shards,
            present_count: 0,
            space: vec![],
            present: vec![false; data_shards + parity_shards],
            rs_decoder: WrappedReedSolomon::new_cached(data_shards, parity_shards),
            done: false,
        }
    }

    pub fn good_pkts(&self) -> usize {
        if self.done {
            return self.data_shards;
        }
        self.present
            .iter()
            .enumerate()
            .map(|(i, v)| if *v && i < self.data_shards { 1 } else { 0 })
            .sum::<usize>()
            .min(self.data_shards)
    }

    pub fn lost_pkts(&self) -> usize {
        self.data_shards - self.good_pkts()
    }

    #[tracing::instrument(level = "trace", skip(pkt))]
    pub fn decode(&mut self, pkt: &[u8], pkt_idx: usize) -> Option<Vec<Bytes>> {
        // if we don't have parity shards, don't touch anything
        if self.parity_shards == 0 {
            self.done = true;
            return Some(vec![post_decode(Bytes::copy_from_slice(pkt))?]);
        }
        if self.space.is_empty() {
            tracing::trace!("decode with pad len {}", pkt.len());
            self.space = vec![vec![0u8; pkt.len()]; self.data_shards + self.parity_shards]
        }
        if self.space.len() <= pkt_idx {
            return None;
        }
        if self.done
            || pkt_idx > self.space.len()
            || pkt_idx > self.present.len()
            || self.space[pkt_idx].len() != pkt.len()
        {
            return None;
        }
        // decompress without allocation
        self.space[pkt_idx].copy_from_slice(pkt);
        if !self.present[pkt_idx] {
            self.present_count += 1
        }
        self.present[pkt_idx] = true;
        // if I'm a data shard, just return it
        if pkt_idx < self.data_shards {
            return Some(vec![post_decode(Bytes::copy_from_slice(
                &self.space[pkt_idx],
            ))?]);
        }
        if self.present_count < self.data_shards {
            tracing::trace!("don't even attempt yet");
            return None;
        }
        let mut ref_vec: Vec<(&mut [u8], bool)> = self
            .space
            .iter_mut()
            .zip(self.present.iter())
            .map(|(v, pres)| (v.as_mut(), *pres))
            .collect();
        // otherwise, attempt to reconstruct
        tracing::trace!(
            "attempting to reconstruct (data={}, parity={})",
            self.data_shards,
            self.parity_shards
        );
        self.rs_decoder.get_inner().reconstruct(&mut ref_vec).ok()?;
        self.done = true;
        let res = self
            .space
            .drain(0..)
            .zip(self.present.iter().cloned())
            .take(self.data_shards)
            .filter_map(|(elem, present)| {
                if !present {
                    post_decode(Bytes::copy_from_slice(&elem))
                } else {
                    None
                }
            })
            .collect();
        Some(res)
    }
}
