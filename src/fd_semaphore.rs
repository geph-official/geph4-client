use anyhow::Context;
use once_cell::sync::Lazy;
use smol::lock::{Semaphore, SemaphoreGuardArc};
use smol_timeout::TimeoutExt;
use std::{sync::Arc, time::Duration};

// limit the number of fds to a very low number to avoid running out
#[cfg(target_os = "macos")]
static FD_SEMAPHORE: Lazy<Arc<Semaphore>> = Lazy::new(|| Arc::new(Semaphore::new(64)));

#[cfg(not(target_os = "macos"))]
static FD_SEMAPHORE: Lazy<Arc<Semaphore>> = Lazy::new(|| Arc::new(Semaphore::new(512)));

/// Blocks until a file descriptor is free, then acquires a guard.
pub(crate) async fn acquire_fd() -> anyhow::Result<SemaphoreGuardArc> {
    FD_SEMAPHORE
        .acquire_arc()
        .timeout(Duration::from_millis(300))
        .await
        .context("could not acquire")
}
