use std::{collections::VecDeque, sync::Arc};

use once_cell::sync::Lazy;
use parking_lot::RwLock;

// sosistab stats
static SOSISTAB_STATS: Lazy<Arc<sosistab::StatsGatherer>> =
    Lazy::new(|| Arc::new(sosistab::StatsGatherer::new_active()));

/// Gets the global sosistab gatherer
pub fn global_sosistab_stats() -> Arc<sosistab::StatsGatherer> {
    Arc::clone(&SOSISTAB_STATS)
}

pub static GLOBAL_LOGGER: Lazy<RwLock<VecDeque<String>>> =
    Lazy::new(|| RwLock::new(VecDeque::new()));
