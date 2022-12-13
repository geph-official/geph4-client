use parking_lot::RwLock;
use smol_str::SmolStr;
use sosistab2::PipeStats;

use std::time::SystemTime;

#[derive(Clone, Debug)]
pub struct StatItem {
    pub time: SystemTime,
    pub endpoint: SmolStr,
    pub protocol: SmolStr,
    pub stats: PipeStats,
    pub send_bytes: u64,
    pub recv_bytes: u64,
}

#[derive(Default)]
pub struct StatsGatherer {
    buffer: RwLock<im::Vector<StatItem>>,
}

impl StatsGatherer {
    /// Pushes a stat item to the gatherer.
    pub fn push(&self, item: StatItem) {
        let mut buffer = self.buffer.write();
        buffer.push_back(item);
        if buffer.len() > 10000 {
            buffer.pop_front();
        }
    }

    /// Obtains all the stats items.
    pub fn all_items(&self) -> im::Vector<StatItem> {
        self.buffer.read().clone()
    }
}
