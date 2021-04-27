use std::sync::Arc;

use once_cell::sync::Lazy;
use parking_lot::{lock_api::RawMutex, Mutex};
use smol::channel::Sender;

// sosistab stats
static SOSISTAB_STATS: Lazy<Arc<sosistab::StatsGatherer>> =
    Lazy::new(|| Arc::new(sosistab::StatsGatherer::new_active()));

/// Gets the global sosistab gatherer
pub fn global_sosistab_stats() -> Arc<sosistab::StatsGatherer> {
    Arc::clone(&SOSISTAB_STATS)
}

/// Global logger.
pub static GLOBAL_LOGGER: Mutex<Option<Sender<String>>> = Mutex::const_new(RawMutex::INIT, None);
