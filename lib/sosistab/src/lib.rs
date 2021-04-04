mod client;
mod crypt;
mod fec;
mod listener;
pub use client::*;
use crypt::{LegacyAead, NgAead};
pub use listener::*;
use std::time::{Duration, Instant};
mod protocol;
pub mod runtime;
mod session;
pub use session::*;
mod backhaul;
mod mux;
pub use mux::*;
mod tcp;
use backhaul::*;
mod batchan;
mod recfilter;

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
        if speed > 50000 {
            return;
        }
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

/// Debug AEAD speeds
pub fn debug_aead() {
    tracing::warn!("** CRYPTOGRAPHY SELF-TEST **");
    const ITERS: u64 = 10000;
    let old = LegacyAead::new(&[0; 32]);
    let new = NgAead::new(&[0; 32]);
    let old_start = Instant::now();
    for _ in 0..ITERS {
        old.decrypt(&old.encrypt(&[0; 1024], 0));
    }
    let old_kps = ITERS as f64 / old_start.elapsed().as_secs_f64();
    tracing::warn!("LegacyAEAD: {} MB/s", old_kps / 1024.0);
    let new_start = Instant::now();
    for _ in 0..ITERS {
        new.decrypt(&new.encrypt(&[0; 1024]));
    }
    let new_kps = ITERS as f64 / new_start.elapsed().as_secs_f64();
    tracing::warn!("NewAEAD: {} MB/s", new_kps / 1024.0);
}
