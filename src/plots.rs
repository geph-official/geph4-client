use serde::Serialize;
use std::time::{Duration, SystemTime};

// use crate::stats::global_sosistab_stats;

/// Derive delta-stats from the original stats.
pub fn stat_derive(stats: geph4_protocol::tunnel::Stats) -> Vec<DeltaStat> {
    let mut toret = vec![];
    let now = SystemTime::now();
    let first_time = stats
        .ping_series
        .earliest()
        .map(|v| v.0)
        .unwrap_or_else(|| now - Duration::from_secs(600))
        + Duration::from_secs(3);
    for seconds_before_now in 0..600 {
        let end_time = now - Duration::from_secs(seconds_before_now);
        let start_time = end_time - Duration::from_secs(5);
        if start_time < first_time {
            break;
        }
        let send_speed =
            (stats.sent_series.get(end_time) - stats.sent_series.get(start_time)) as f64 / 5.0;
        let recv_speed =
            (stats.recv_series.get(end_time) - stats.recv_series.get(start_time)) as f64 / 5.0;
        let loss = stats.loss_series.get(end_time);
        let ping = stats.ping_series.get(end_time);
        toret.push(DeltaStat {
            time: end_time,
            send_speed,
            recv_speed,
            loss: Some(loss as f64 * 100.0),
            ping: ping as f64 * 1000.0,
        })
    }
    toret.reverse();
    toret
}

/// Delta statistics
#[derive(Serialize, Clone, Debug, Copy)]
pub struct DeltaStat {
    time: SystemTime,
    send_speed: f64,
    recv_speed: f64,
    ping: f64,
    loss: Option<f64>,
}
