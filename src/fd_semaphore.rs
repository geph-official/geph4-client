use anyhow::Context;
use binary_search::Direction;
use once_cell::sync::Lazy;
use smol::lock::{Semaphore, SemaphoreGuardArc};

use std::sync::Arc;

#[cfg(unix)]
static FD_LIMIT: Lazy<usize> = Lazy::new(|| {
    let ((largest_low, _), _) = binary_search::binary_search((1, ()), (65536, ()), |lim| {
        if rlimit::utils::increase_nofile_limit(lim).unwrap_or_default() >= lim {
            Direction::Low(())
        } else {
            Direction::High(())
        }
    });
    let _ = rlimit::utils::increase_nofile_limit(largest_low);
    log::info!("** set fd limit to {} **", largest_low);
    largest_low as usize
});

#[cfg(not(unix))]
static FD_LIMIT: Lazy<usize> = Lazy::new(|| 1024);

// limit the number of fds to half the limit number to avoid running out
static FD_SEMAPHORE: Lazy<Arc<Semaphore>> = Lazy::new(|| Arc::new(Semaphore::new(*FD_LIMIT / 2)));

/// Blocks until a file descriptor is free, then acquires a guard.
pub(crate) async fn acquire_fd() -> anyhow::Result<SemaphoreGuardArc> {
    FD_SEMAPHORE.try_acquire_arc().context("could not acquire")
}
