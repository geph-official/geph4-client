use std::{collections::VecDeque, sync::Arc};

use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

// sosistab stats
static SOSISTAB_STATS: Lazy<Arc<sosistab::StatsGatherer>> =
    Lazy::new(|| Arc::new(sosistab::StatsGatherer::new_active()));

/// Gets the global sosistab gatherer
pub fn global_sosistab_stats() -> Arc<sosistab::StatsGatherer> {
    Arc::clone(&SOSISTAB_STATS)
}

#[derive(Default, Serialize, Deserialize)]
pub struct StatCollector {
    total_rx: Mutex<u64>,
    total_tx: Mutex<u64>,

    open_conns: Mutex<u64>,
    open_latency: Mutex<f64>,

    loss: Mutex<f64>,

    exit_info: Mutex<Option<binder_transport::ExitDescriptor>>,
}

impl StatCollector {
    pub fn incr_total_rx(&self, bytes: u64) {
        *self.total_rx.lock() += bytes;
    }
    pub fn incr_total_tx(&self, bytes: u64) {
        *self.total_tx.lock() += bytes;
    }

    pub fn set_latency(&self, ms: f64) {
        *self.open_latency.lock() = ms
    }

    pub fn set_loss(&self, loss: f64) {
        *self.loss.lock() = loss
    }

    // pub fn get_latency(&self) -> f64 {
    //     *self.open_latency.lock()
    // }

    pub fn set_exit_descriptor(&self, desc: Option<binder_transport::ExitDescriptor>) {
        *self.exit_info.lock() = desc
    }
}

pub static GLOBAL_LOGGER: Lazy<RwLock<VecDeque<String>>> =
    Lazy::new(|| RwLock::new(VecDeque::new()));
