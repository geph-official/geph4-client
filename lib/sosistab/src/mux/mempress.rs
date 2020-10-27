use std::sync::atomic::{AtomicUsize, Ordering};
static MEMPRESS_COUNTER: AtomicUsize = AtomicUsize::new(0);

const LO_WMARK: usize = 100000;

pub fn incr(n: usize) {
    MEMPRESS_COUNTER.fetch_add(n, Ordering::Relaxed);
}

pub fn decr(n: usize) {
    MEMPRESS_COUNTER.fetch_sub(n, Ordering::Relaxed);
}

fn current() -> usize {
    MEMPRESS_COUNTER.load(Ordering::Relaxed)
}

pub fn is_pressured() -> bool {
    let c = current();
    if c > LO_WMARK {
        log::warn!("under memory pressue ({} > {})", c, LO_WMARK);
        true
    } else {
        false
    }
}
