use std::time::{Duration, SystemTime};

use serde::Serialize;

use crate::stats::global_sosistab_stats;

/// Derive delta-stats from the original stats.
pub fn stat_derive() -> Vec<DeltaStat> {
    let cutoff = SystemTime::now() - Duration::from_secs(600);
    let stats = global_sosistab_stats();
    let sent_series = stats
        .get_timeseries("total_sent_bytes")
        .unwrap_or_default()
        .after(cutoff);
    let recv_series = stats
        .get_timeseries("total_recv_bytes")
        .unwrap_or_default()
        .after(cutoff);
    let mut toret = vec![];
    let now = SystemTime::now();
    for seconds_before_now in 0..600 {
        let end_time = now - Duration::from_secs(seconds_before_now);
        let start_time = end_time - Duration::from_secs(5);
        let send_speed = (sent_series.get(end_time) - sent_series.get(start_time)) as f64 / 5.0;
        let recv_speed = (recv_series.get(end_time) - recv_series.get(start_time)) as f64 / 5.0;
        toret.push(DeltaStat {
            time: end_time,
            send_speed,
            recv_speed,
            loss: None,
        })
    }
    toret.reverse();
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
