use std::{
    ops::Deref,
    sync::{atomic::AtomicU8, Arc},
};

use arc_swap::ArcSwap;
use cached::proc_macro::cached;
use reed_solomon_erasure::galois_8;

/// A wrapped ReedSolomon instance.
#[derive(Debug)]
pub struct WrappedReedSolomon {
    inner: ArcSwap<galois_8::ReedSolomon>,
    data_shards: usize,
    parity_shards: usize,
    counter: AtomicU8,
}

/// New cached arc.
#[cached(size = 20)]
fn new_cached_wrs(data_shards: usize, parity_shards: usize) -> Arc<WrappedReedSolomon> {
    Arc::new(WrappedReedSolomon::new(data_shards, parity_shards))
}

impl WrappedReedSolomon {
    /// Creates a new wrapped RS
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        let inner = galois_8::ReedSolomon::new(data_shards.max(1), parity_shards.max(1)).unwrap();
        Self {
            inner: ArcSwap::from(Arc::new(inner)),
            data_shards,
            parity_shards,
            counter: AtomicU8::default(),
        }
    }

    /// New cached
    pub fn new_cached(data_shards: usize, parity_shards: usize) -> Arc<Self> {
        new_cached_wrs(data_shards, parity_shards)
    }

    /// Obtains the inner RS.
    pub fn get_inner(&self) -> impl Deref<Target = galois_8::ReedSolomon> {
        let count = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count == 255 {
            let inner = galois_8::ReedSolomon::new(self.data_shards, self.parity_shards).unwrap();
            self.inner.swap(Arc::new(inner));
        }
        self.inner.load_full()
    }
}
