use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StatCollector {
    total_rx: Mutex<u64>,
    total_tx: Mutex<u64>,

    open_conns: Mutex<u64>,
    exit_info: Mutex<Option<binder_transport::ExitDescriptor>>,
}

impl StatCollector {
    pub fn incr_total_rx(&self, bytes: u64) {
        *self.total_rx.lock() += bytes
    }
    pub fn incr_total_tx(&self, bytes: u64) {
        *self.total_tx.lock() += bytes
    }

    pub fn incr_open_conns(&self) {
        *self.open_conns.lock() += 1
    }
    pub fn decr_open_conns(&self) {
        *self.open_conns.lock() -= 1
    }
    // pub fn get_open_conns(&self) -> u64 {
    //     *self.open_conns.lock()
    // }

    pub fn set_exit_descriptor(&self, desc: Option<binder_transport::ExitDescriptor>) {
        *self.exit_info.lock() = desc
    }
}
