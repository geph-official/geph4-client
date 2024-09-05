pub mod gatherer;

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use async_trait::async_trait;
use itertools::Itertools;
use smol_str::SmolStr;
use smolscale::reaper::TaskReaper;

use self::gatherer::StatsGatherer;

use nanorpc::nanorpc_derive;
use nanorpc::RpcService;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use super::ConnectContext;

/// The main stats-serving thread.
pub async fn serve_stats_loop(ctx: ConnectContext) -> anyhow::Result<()> {
    smol::unblock(move || {
        let reaper = TaskReaper::new();
        let ctx = ctx.clone();
        loop {
            let server = tiny_http::Server::http(ctx.opt.stats_listen)
                .ok()
                .context("could not start listening")?;

            for mut request in server.incoming_requests() {
                let ctx = ctx.clone();
                reaper.attach(smolscale::spawn(async move {
                    if let Ok(key) = std::env::var("GEPH_RPC_KEY") {
                        if !request.url().contains(&key) {
                            anyhow::bail!("missing rpc key")
                        }
                    }
                    let mut s = String::new();
                    request.as_reader().read_to_string(&mut s)?;
                    let resp = StatsControlService(StatsControlProtocolImpl { ctx })
                        .respond_raw(serde_json::from_str(&s)?)
                        .await;
                    request.respond(tiny_http::Response::from_data(serde_json::to_vec(&resp)?))?;
                    anyhow::Ok(())
                }));
            }
        }
    })
    .await
}

/// Basic tunnel statistics.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicStats {
    pub total_sent_bytes: f32,
    pub total_recv_bytes: f32,

    pub last_ping: f32, // latency
    pub protocol: SmolStr,
    pub address: SmolStr,
}

#[derive(Clone)]
struct StatsControlProtocolImpl {
    ctx: ConnectContext,
}

#[async_trait]
impl StatsControlProtocol for StatsControlProtocolImpl {
    /// Obtains whether or not the daemon is connected.
    async fn is_connected(&self) -> bool {
        self.ctx.tunnel.status().await.connected()
    }

    /// Obtains statistics.
    async fn basic_stats(&self) -> BasicStats {
        loop {
            let stats = STATS_GATHERER.all_items().last().cloned();

            if let Some(stats) = stats {
                return BasicStats {
                    address: stats.endpoint,
                    protocol: stats.protocol,
                    last_ping: stats.ping.as_secs_f32() * 1000.0,
                    total_recv_bytes: STATS_RECV_BYTES.load(Ordering::Relaxed) as f32,
                    total_sent_bytes: STATS_SEND_BYTES.load(Ordering::Relaxed) as f32,
                };
            }
            smol::Timer::after(Duration::from_millis(100)).await;
        }
    }

    /// Get all logs after the given Unix timestamp.
    async fn get_logs(&self, timestamp: u64) -> Vec<(u64, String)> {
        let logs = match self
            .ctx
            .debug
            .get_loglines(UNIX_EPOCH + Duration::from_secs(timestamp))
            .await
        {
            Ok(logs) => logs,
            Err(error) => {
                log::error!("Error occurred: {:?}", error);
                return vec![];
            }
        };
        logs.into_iter()
            .map(|(time, line)| (time.duration_since(UNIX_EPOCH).unwrap().as_secs(), line))
            .collect()
    }

    /// Obtains time-series statistics.
    async fn timeseries_stats(&self, series: Timeseries) -> Vec<(u64, f32)> {
        let s = STATS_GATHERER.all_items();
        let diffify = |series: Vec<(SystemTime, f32)>| {
            series
                .windows(2)
                .map(|v| {
                    if let [(t1, v1), (t2, v2)] = v {
                        let t1 = t1.duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
                        let t2 = t2.duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
                        let dt = (t2 - t1) as f32;
                        (((t1 + t2) / 2.0) as _, (*v2 - *v1) / dt)
                    } else {
                        unreachable!()
                    }
                })
                .collect_vec()
        };
        match series {
            Timeseries::SendSpeed => {
                let series = s
                    .iter()
                    .map(|item| (item.time, item.send_bytes as f32))
                    .collect_vec();
                diffify(series)
            }
            Timeseries::RecvSpeed => {
                let series = s
                    .iter()
                    .map(|item| (item.time, item.recv_bytes as f32))
                    .collect_vec();
                diffify(series)
            }

            Timeseries::Ping => {
                let zoomed = if s.len() > 200 {
                    s.clone().slice(s.len() - 200..)
                } else {
                    s
                };
                zoomed
                    .into_iter()
                    .map(|i| {
                        (
                            i.time.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                            i.ping.as_secs_f32() * 1000.0,
                        )
                    })
                    .collect_vec()
            }
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

#[nanorpc_derive]
#[async_trait]
pub trait StatsControlProtocol {
    /// Obtains whether or not the daemon is connected.
    async fn is_connected(&self) -> bool;

    /// Obtains statistics.
    async fn basic_stats(&self) -> BasicStats;

    /// Get all logs after the given Unix timestamp.
    async fn get_logs(&self, timestamp: u64) -> Vec<(u64, String)>;

    /// Obtains time-series statistics.
    async fn timeseries_stats(&self, series: Timeseries) -> Vec<(u64, f32)>;

    /// Turns off the daemon.
    async fn kill(&self) -> bool;
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
pub enum Timeseries {
    RecvSpeed,
    SendSpeed,

    Ping,
}

pub static STATS_GATHERER: Lazy<StatsGatherer> = Lazy::new(Default::default);

pub static STATS_SEND_BYTES: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(0));

pub static STATS_RECV_BYTES: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(0));
