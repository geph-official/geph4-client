use std::collections::VecDeque;

use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize)]
pub struct StatCollector {
    total_rx: Mutex<u64>,
    total_tx: Mutex<u64>,

    open_conns: Mutex<u64>,
    open_latency: Mutex<f64>,
    exit_info: Mutex<Option<binder_transport::ExitDescriptor>>,
}

impl StatCollector {
    pub fn incr_total_rx(&self, bytes: u64) {
        *self.total_rx.lock() += bytes
    }
    pub fn incr_total_tx(&self, bytes: u64) {
        *self.total_tx.lock() += bytes
    }

    pub fn set_latency(&self, ms: f64) {
        let mut old = self.open_latency.lock();
        if *old > 0.1 {
            if ms > *old {
                *old = *old * 0.9 + ms * 0.1;
            } else {
                *old = *old * 0.5 + ms * 0.5
            }
        } else {
            *old = ms
        }
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
