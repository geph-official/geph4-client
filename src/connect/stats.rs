use std::{
    collections::HashMap,
    convert::Infallible,
    thread::JoinHandle,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use itertools::Itertools;
use nanorpc::nanorpc_derive;
use nanorpc::RpcService;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use super::{CONNECT_CONFIG, TUNNEL};

/// The main stats-serving thread.
pub static STATS_THREAD: Lazy<JoinHandle<Infallible>> = Lazy::new(|| {
    std::thread::spawn(|| loop {
        let server = tiny_http::Server::http(CONNECT_CONFIG.stats_listen).unwrap();
        for mut request in server.incoming_requests() {
            smolscale::spawn(async move {
                if let Ok(key) = std::env::var("GEPH_RPC_KEY") {
                    if !request.url().contains(&key) {
                        anyhow::bail!("missing rpc key")
                    }
                }
                let mut s = String::new();
                request.as_reader().read_to_string(&mut s)?;
                let resp = StatsControlService(DummyImpl)
                    .respond_raw(serde_json::from_str(&s)?)
                    .await;
                request.respond(tiny_http::Response::from_data(serde_json::to_vec(&resp)?))?;
                anyhow::Ok(())
            })
            .detach()
        }
    })
});

/// Basic tunnel statistics.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct BasicStats {
    pub total_sent_bytes: f32,
    pub total_recv_bytes: f32,
    pub last_loss: f32,
    pub last_ping: f32, // latency
}

#[derive(Copy, Clone)]
struct DummyImpl;

impl StatsControlProtocol for DummyImpl {}

#[nanorpc_derive]
#[async_trait]
pub trait StatsControlProtocol {
    /// Obtains whether or not the daemon is connected.
    async fn is_connected(&self) -> bool {
        TUNNEL.is_connected()
    }

    /// Obtains statistics.
    async fn basic_stats(&self) -> BasicStats {
        let s = TUNNEL.get_stats().await;
        BasicStats {
            total_recv_bytes: s.total_recv_bytes,
            total_sent_bytes: s.total_sent_bytes,
            last_loss: s.last_loss,
            last_ping: s.last_ping,
        }
    }

    /// Obtains time-series statistics.
    async fn timeseries_stats(&self, series: Timeseries) -> Vec<(u64, f32)> {
        let s = TUNNEL.get_stats().await;
        let diffify = |series: sosistab::TimeSeries| {
            let mut accum = HashMap::new();
            let mut last = 0.0f32;
            let now = SystemTime::now();
            for (&time, &total) in series.iter() {
                if let Ok(dur) = now.duration_since(time) {
                    if dur.as_secs() > 600 {
                        continue;
                    }
                }
                let bucket = time.duration_since(UNIX_EPOCH).unwrap().as_secs();
                let diff = (total - last).max(0.0);
                last = total;
                *accum.entry(bucket).or_default() += diff;
            }
            let first = accum.keys().min().copied().unwrap_or_default();
            let end = accum.keys().max().copied().unwrap_or_default();
            (first..end)
                .map(|i| (i, accum.get(&i).copied().unwrap_or_default()))
                .collect_vec()
        };
        match series {
            Timeseries::SendSpeed => {
                let series = s.sent_series;
                diffify(series)
            }
            Timeseries::RecvSpeed => {
                let series = s.recv_series;
                diffify(series)
            }
            Timeseries::Loss => todo!(),
        }
    }

    /// Turns off the daemon.
    async fn kill(&self) -> bool {
        smolscale::spawn(async {
            smol::Timer::after(Duration::from_millis(300)).await;
            std::process::exit(0);
        })
        .detach();
        true
    }
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
pub enum Timeseries {
    RecvSpeed,
    SendSpeed,
    Loss,
}
