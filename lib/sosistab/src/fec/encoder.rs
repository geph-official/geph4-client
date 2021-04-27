use bytes::{Bytes, BytesMut};
use probability::distribution::Distribution;

use rustc_hash::FxHashMap;

use super::{pre_encode, wrapped::WrappedReedSolomon};

/// A forward error correction encoder. Retains internal state for memoization, memory pooling etc.
#[derive(Debug)]
pub struct FrameEncoder {
    // table mapping current loss in pct + run length => overhead
    rate_table: FxHashMap<(u8, usize), usize>,
    // target loss rate
    target_loss: u8,
}

impl FrameEncoder {
    /// Creates a new Encoder at the given loss level.
    #[tracing::instrument(level = "trace")]
    pub fn new(target_loss: u8) -> Self {
        FrameEncoder {
            rate_table: FxHashMap::default(),
            target_loss,
        }
    }

    /// Encodes a slice of packets into more packets.
    #[tracing::instrument(level = "trace", skip(pkts))]
    pub fn encode(&mut self, measured_loss: u8, pkts: &[Bytes]) -> Vec<Bytes> {
        // max length
        let max_length = pkts.iter().map(|v| v.len()).max().unwrap();
        // first we precode the packets
        let mut padded_pkts: Vec<BytesMut> =
            pkts.iter().map(|p| pre_encode(p, max_length + 2)).collect();
        // then we get an encoder for this size
        let data_shards = pkts.len();
        let parity_shards = self.repair_len(measured_loss, pkts.len());
        // then we encode
        // prepare the space for in-place mutation
        let mut parity_shard_space = vec![vec![0u8; max_length + 2]; parity_shards];
        let mut padded_pkts: Vec<&mut [u8]> = padded_pkts.iter_mut().map(|v| v.as_mut()).collect();
        for r in parity_shard_space.iter_mut() {
            padded_pkts.push(r);
        }
        // tracing::debug!(
        //     "{:.1}% => {}/{}",
        //     100.0 * measured_loss as f64 / 256.0,
        //     data_shards,
        //     parity_shards
        // );
        if parity_shards > 0 {
            let encoder = WrappedReedSolomon::new_cached(data_shards, parity_shards);
            // do the encoding
            encoder
                .get_inner()
                .encode(&mut padded_pkts)
                .expect("can't encode");
        }
        // return
        let mut toret = Vec::with_capacity(data_shards + parity_shards);
        toret.extend(padded_pkts.iter().map(|vec| Bytes::copy_from_slice(&vec)));
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
        .min(run_len * 2)
    }
}
