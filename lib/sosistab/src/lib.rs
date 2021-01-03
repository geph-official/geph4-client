mod client;
mod crypt;
mod fec;
mod listener;
pub use client::*;
pub use listener::*;
use std::time::{Duration, Instant};
mod msg;
pub mod runtime;
mod session;
pub use session::*;
mod backhaul;
pub mod mux;
mod stats;
pub use backhaul::*;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

pub(crate) struct VarRateLimit {
    next_time: Instant,
    timer: smol::Timer,
}

impl VarRateLimit {
    pub fn new() -> Self {
        Self {
            next_time: Instant::now(),
            timer: smol::Timer::at(Instant::now()),
        }
    }
    pub async fn wait(&mut self, speed: u32) {
        if speed > 10000 {
            return;
        }
        tracing::warn!("actually waiting, {}", speed);
        self.timer.set_at(self.next_time);
        (&mut self.timer).await;
        self.next_time = Instant::now()
            .checked_add(Duration::from_micros(1_000_000 / (speed.max(100)) as u64))
            .expect("time OOB")
    }

    // pub async fn wait(&self, speed: u32) {
    //     while !self.check(speed.max(DIVIDER_FRAC * 2)) {
    //         smol::Timer::after(Duration::from_millis(1)).await;
    //     }
    // }
}
