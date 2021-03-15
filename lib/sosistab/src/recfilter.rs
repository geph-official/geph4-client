use std::time::Instant;

use once_cell::sync::Lazy;
use parking_lot::Mutex;

// recently seen tracker
pub struct RecentFilter {
    curr_bloom: bloomfilter::Bloom<[u8]>,
    last_bloom: bloomfilter::Bloom<[u8]>,
    curr_time: Instant,
}

impl RecentFilter {
    fn new() -> Self {
        RecentFilter {
            curr_bloom: bloomfilter::Bloom::new_for_fp_rate(1000000, 0.01),
            last_bloom: bloomfilter::Bloom::new_for_fp_rate(1000000, 0.01),
            curr_time: Instant::now(),
        }
    }

    pub fn check(&mut self, val: &[u8]) -> bool {
        let start = Instant::now();
        if start.saturating_duration_since(self.curr_time).as_secs() > 300 {
            std::mem::swap(&mut self.curr_bloom, &mut self.last_bloom);
            self.curr_bloom.clear();
            self.curr_time = start
        }
        !(self.curr_bloom.check_and_set(val) || self.last_bloom.check(val))
    }
}

/// A global recent filter.
pub static RECENT_FILTER: Lazy<Mutex<RecentFilter>> = Lazy::new(|| Mutex::new(RecentFilter::new()));
