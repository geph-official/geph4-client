use std::sync::Arc;

use once_cell::sync::Lazy;
use smol::lock::{Semaphore, SemaphoreGuardArc};

// limit the number of fds to a very low number to avoid running out
static FD_SEMAPHORE: Lazy<Arc<Semaphore>> = Lazy::new(|| Arc::new(Semaphore::new(128)));

/// Blocks until a file descriptor is free, then acquires a guard.
pub(crate) async fn acquire_fd() -> SemaphoreGuardArc {
    FD_SEMAPHORE.acquire_arc().await
}
