use std::num::NonZeroU32;

use governor::{state::NotKeyed, NegativeMultiDecision, Quota};

/// A generic rate limiter.
pub struct RateLimiter {
    inner: governor::RateLimiter<
        NotKeyed,
        governor::state::InMemoryState,
        governor::clock::MonotonicClock,
    >,
    unlimited: bool,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given speed limit, in KB/s
    pub fn new(limit: u32) -> Self {
        let limit = NonZeroU32::new(limit * 1024).unwrap();
        let inner = governor::RateLimiter::new(
            Quota::per_second(limit).allow_burst(NonZeroU32::new(128 * 1024).unwrap()),
            governor::state::InMemoryState::default(),
            &governor::clock::MonotonicClock::default(),
        );
        Self {
            inner,
            unlimited: false,
        }
    }

    /// Creates a new unlimited ratelimit.
    pub fn unlimited() -> Self {
        let inner = governor::RateLimiter::new(
            Quota::per_second(NonZeroU32::new(128 * 1024).unwrap()),
            governor::state::InMemoryState::default(),
            &governor::clock::MonotonicClock::default(),
        );
        Self {
            inner,
            unlimited: true,
        }
    }

    /// Waits until the given number of bytes can be let through.
    pub async fn wait(&self, bytes: usize) {
        if bytes == 0 || self.unlimited {
            return;
        }
        let bytes = NonZeroU32::new(bytes as u32).unwrap();
        while let Err(err) = self.inner.check_n(bytes) {
            match err {
                NegativeMultiDecision::BatchNonConforming(_, until) => {
                    smol::Timer::at(until.earliest_possible()).await;
                }
                NegativeMultiDecision::InsufficientCapacity(_) => {
                    panic!("insufficient capacity in rate limiter")
                }
            }
        }
    }
}
