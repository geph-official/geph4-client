use bytes::{Bytes, BytesMut};
use probability::distribution::Distribution;
use reed_solomon_erasure::galois_8;
use std::collections::HashMap;
/// A forward error correction encoder. Retains internal state for memoization, memory pooling etc.
#[derive(Debug)]
pub struct FrameEncoder {
    // table mapping current loss in pct + run length => overhead
    rate_table: HashMap<(u8, usize), usize>,
    // target loss rate
    target_loss: u8,
    // encoder pool
    rs_encoders: HashMap<(usize, usize), galois_8::ReedSolomon>,
}

impl FrameEncoder {
    /// Creates a new Encoder at the given loss level.
    pub fn new(target_loss: u8) -> Self {
        FrameEncoder {
            rate_table: HashMap::new(),
            target_loss,
            rs_encoders: HashMap::new(),
        }
    }

    /// Encodes a slice of packets into more packets.
    pub fn encode(&mut self, measured_loss: u8, pkts: &[Bytes]) -> Vec<Bytes> {
        // first we precode the packets
        let mut padded_pkts: Vec<BytesMut> = pkts.iter().map(|p| pre_encode(p, 1300)).collect();
        // then we get an encoder for this size
        let data_shards = pkts.len();
        let parity_shards = self.repair_len(measured_loss, pkts.len());
        // then we encode
        // prepare the space for in-place mutation
        let mut parity_shard_space = vec![[0u8; 1300]; parity_shards];
        let mut padded_pkts: Vec<&mut [u8]> = padded_pkts.iter_mut().map(|v| v.as_mut()).collect();
        for r in parity_shard_space.iter_mut() {
            padded_pkts.push(r);
        }
        if parity_shards > 0 {
            let encoder = self
                .rs_encoders
                .entry((data_shards, parity_shards))
                .or_insert_with(|| {
                    galois_8::ReedSolomon::new(data_shards, parity_shards)
                        .expect("didn't successfully construct RS encoder")
                });
            // do the encoding
            encoder.encode(&mut padded_pkts).expect("can't encode");
        }
        // return
        let mut toret = Vec::with_capacity(data_shards + parity_shards);
        toret.extend(
            padded_pkts
                .iter()
                .map(|p| {
                    let pre_len = p.len();
                    let post = snap::raw::Encoder::new().compress_vec(&p).unwrap();
                    log::trace!("compressing {} => {}", pre_len, post.len());
                    post
                })
                .map(|vec| Bytes::copy_from_slice(&vec)),
        );
        toret
    }

    /// Calculates the number of repair blocks needed to properly reconstruct a run of packets.
    fn repair_len(&mut self, measured_loss: u8, run_len: usize) -> usize {
        let target_loss = self.target_loss;
        (*self
            .rate_table
            .entry((measured_loss, run_len))
            .or_insert_with(|| {
                for additional_len in 0.. {
                    let distro = probability::distribution::Binomial::with_failure(
                        run_len + additional_len,
                        (measured_loss as f64 / 256.0).max(1e-100).min(1.0 - 1e-100),
                    );
                    let result_loss = distro.distribution(run_len as f64);
                    if result_loss <= target_loss as f64 / 256.0 {
                        return additional_len.saturating_sub(1usize);
                    }
                }
                panic!()
            }))
        .min(255 - run_len)
    }
}

/// A single-use FEC decoder.
pub struct FrameDecoder {
    data_shards: usize,
    parity_shards: usize,
    space: Vec<([u8; 1300])>,
    present: Vec<bool>,
    rs_decoder: galois_8::ReedSolomon,
    done: bool,
}

impl FrameDecoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        FrameDecoder {
            data_shards,
            parity_shards,
            space: vec![[0u8; 1300]; data_shards + parity_shards],
            present: vec![false; data_shards + parity_shards],
            rs_decoder: galois_8::ReedSolomon::new(data_shards, parity_shards.max(1)).unwrap(),
            done: false,
        }
    }

    pub fn good_pkts(&self) -> usize {
        if self.done {
            return self.data_shards;
        }
        let res = self
            .present
            .iter()
            .enumerate()
            .map(|(i, v)| if *v && i < self.data_shards { 1 } else { 0 })
            .sum::<usize>()
            .min(self.data_shards);
        res
    }

    pub fn lost_pkts(&self) -> usize {
        self.data_shards - self.good_pkts()
    }

    pub fn decode(&mut self, pkt: &[u8], pkt_idx: usize) -> Option<Vec<Bytes>> {
        if self.done || pkt_idx > self.space.len() || pkt_idx > self.present.len() {
            return None;
        }
        // decompress without allocation
        snap::raw::Decoder::new()
            .decompress(pkt, &mut self.space[pkt_idx])
            .ok()?;
        self.present[pkt_idx] = true;
        // if I'm a data shard, just return it
        if pkt_idx < self.data_shards || self.parity_shards == 0 {
            return Some(vec![post_decode(Bytes::copy_from_slice(
                &self.space[pkt_idx],
            ))?]);
        }
        let mut ref_vec: Vec<(&mut [u8], bool)> = self
            .space
            .iter_mut()
            .zip(self.present.iter())
            .map(|(v, pres)| (v.as_mut(), *pres))
            .collect();
        // otherwise, attempt to reconstruct
        self.rs_decoder.reconstruct(&mut ref_vec).ok()?;
        self.done = true;
        Some(
            self.space
                .iter()
                .zip(self.present.iter().cloned())
                .take(self.data_shards)
                .filter_map(|(elem, present)| {
                    if !present {
                        post_decode(Bytes::copy_from_slice(elem))
                    } else {
                        None
                    }
                })
                .collect(),
        )
    }
}

fn pre_encode(pkt: &[u8], len: usize) -> BytesMut {
    assert!(pkt.len() <= 65535);
    assert!(pkt.len() + 2 <= len);
    log::trace!("pre-encoding pkt with len {} => {}", pkt.len(), len);
    let hdr = (pkt.len() as u16).to_le_bytes();
    let mut bts = BytesMut::with_capacity(len);
    bts.extend_from_slice(&hdr);
    bts.extend_from_slice(&pkt);
    bts.extend_from_slice(&vec![0u8; len - pkt.len() - 2]);
    bts
}

fn post_decode(raw: Bytes) -> Option<Bytes> {
    if raw.len() < 2 {
        return None;
    }
    let body_len = u16::from_le_bytes([raw[0], raw[1]]);
    Some(raw.slice(2..2 + body_len as usize))
}

// #[cfg(test)]
// mod tests {
//     extern crate test;
//     use super::*;

//     #[bench]
//     fn bench_frame_encoder(b: &mut test::Bencher) {
//         let lala = vec![Bytes::from([0u8; 1024].as_ref()); 10];
//         let mut encoder = FrameEncoder::new(1);
//         b.iter(|| {
//             encoder.encode(0, &lala);
//         })
//     }
// }
