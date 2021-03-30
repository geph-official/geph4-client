use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use sosistab::SessionStat;

/// Derive delta-stats from the original stats.
pub fn stat_derive(stats: &im::Vector<SessionStat>) -> Vec<DeltaStat> {
    // we go over the stats, grouping them by Unix second
    let mut bins: BTreeMap<u64, Vec<SessionStat>> = BTreeMap::new();
    for stat in stats.iter() {
        let bin = bins.entry(stat.time.duration_since(UNIX_EPOCH).unwrap().as_secs() / 3);
        bin.or_default().push(*stat);
    }

    let mut toret = bins
        .iter()
        .map(|(_, window)| {
            let first = window.first().unwrap();
            let last = window.last().unwrap();
            let delta_time = Duration::from_secs(3);
            let delta_top = last.high_recv - first.high_recv;
            let delta_recv = last.total_recv - first.total_recv;
            let delta_sent = last.total_sent - first.total_sent;
            let recv_speed = delta_recv as f64 / delta_time.as_secs_f64();
            let send_speed = delta_sent as f64 / delta_time.as_secs_f64();
            let loss = 1.0 - delta_recv as f64 / (delta_top as f64).max(1.0);
            DeltaStat {
                time: last.time,
                send_speed,
                recv_speed,
                loss: if delta_recv > 10 { Some(loss) } else { None },
            }
        })
        .collect::<Vec<_>>();
    // as a last step, we normalize the loss. this is done by finding all negative losses and crediting them against previous losses.
    normalize_loss(&mut toret);
    toret.truncate((toret.len() - 1).max(0));
    toret
}

fn normalize_loss(items: &mut [DeltaStat]) {
    // we go through items in reverse
    let mut debt = 0.0;
    for item in items.iter_mut().rev() {
        if let Some(loss) = item.loss.as_mut() {
            if *loss < 0.0 {
                debt += -*loss;
                *loss = 0.0;
            } else {
                let amount = debt.min(*loss);
                *loss -= amount;
                debt -= amount;
            }
        }
    }
}

/// Delta statistics
#[derive(Serialize, Clone, Debug, Copy)]
pub struct DeltaStat {
    time: SystemTime,
    send_speed: f64,
    recv_speed: f64,
    loss: Option<f64>,
}
