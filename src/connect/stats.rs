use std::{convert::Infallible, thread::JoinHandle, time::Duration};

use async_trait::async_trait;

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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicStats {
    pub total_sent_bytes: f32,
    pub total_recv_bytes: f32,
    pub last_loss: f32,
    pub last_ping: f32, // latency
    pub protocol: String,
    pub address: String,
}

#[derive(Copy, Clone)]
struct DummyImpl;

impl StatsControlProtocol for DummyImpl {}

#[nanorpc_derive]
#[async_trait]
pub trait StatsControlProtocol {
    /// Obtains whether or not the daemon is connected.
    async fn is_connected(&self) -> bool {
        TUNNEL.status().connected()
    }

    /// Obtains statistics.
    async fn basic_stats(&self) -> BasicStats {
        todo!()
        // let s = TUNNEL.get_stats().await;
        // let status = TUNNEL.status();
        // BasicStats {
        //     total_recv_bytes: s.total_recv_bytes,
        //     total_sent_bytes: s.total_sent_bytes,
        //     last_loss: s.last_loss,
        //     last_ping: s.last_ping,
        //     protocol: match &status {
        //         ConnectionStatus::Connected {
        //             protocol,
        //             address: _,
        //         } => protocol.clone().into(),
        //         _ => "".into(),
        //     },
        //     address: match status {
        //         ConnectionStatus::Connected {
        //             protocol: _,
        //             address,
        //         } => address.into(),
        //         _ => "".into(),
        //     },
        // }
    }

    /// Obtains time-series statistics.
    async fn timeseries_stats(&self, _series: Timeseries) -> Vec<(u64, f32)> {
        todo!()
        // let s = TUNNEL.get_stats().await;
        // let diffify = |series: sosistab::TimeSeries| {
        //     let mut accum = HashMap::new();
        //     let mut last = 0.0f32;
        //     let now = SystemTime::now();
        //     accum.insert(now.duration_since(UNIX_EPOCH).unwrap().as_secs(), 0.0);
        //     accum.insert(now.duration_since(UNIX_EPOCH).unwrap().as_secs() - 1, 0.0);
        //     for (&time, &total) in series.iter() {
        //         if let Ok(dur) = now.duration_since(time) {
        //             if dur.as_secs() > 600 {
        //                 continue;
        //             }
        //         }
        //         let bucket = time.duration_since(UNIX_EPOCH).unwrap().as_secs();
        //         let diff = (total - last).max(0.0);
        //         last = total;
        //         *accum.entry(bucket).or_default() += diff;
        //     }
        //     let first = accum.keys().min().copied().unwrap_or_default();
        //     let end = accum.keys().max().copied().unwrap_or_default();
        //     (first..end)
        //         .map(|i| (i, accum.get(&i).copied().unwrap_or_default()))
        //         .collect_vec()
        // };
        // match series {
        //     Timeseries::SendSpeed => {
        //         let series = s.sent_series;
        //         diffify(series)
        //     }
        //     Timeseries::RecvSpeed => {
        //         let series = s.recv_series;
        //         diffify(series)
        //     }
        //     Timeseries::Loss => (0..200)
        //         .rev()
        //         .map(|t| {
        //             let tstamp = SystemTime::now() - Duration::from_secs(t);
        //             let tt = tstamp.duration_since(UNIX_EPOCH).unwrap().as_secs();
        //             (
        //                 tt,
        //                 s.loss_series
        //                     .get(SystemTime::now() - Duration::from_secs(t)),
        //             )
        //         })
        //         .collect_vec(),
        //     Timeseries::Ping => (0..200)
        //         .rev()
        //         .filter_map(|t| {
        //             let tstamp = SystemTime::now() - Duration::from_secs(t);
        //             let tt = tstamp.duration_since(UNIX_EPOCH).unwrap().as_secs();
        //             let res = s
        //                 .ping_series
        //                 .get(SystemTime::now() - Duration::from_secs(t));
        //             if res > 10.0 {
        //                 None
        //             } else {
        //                 Some((tt, res * 1000.0))
        //             }
        //         })
        //         .collect_vec(),
        // }
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
    Ping,
}
