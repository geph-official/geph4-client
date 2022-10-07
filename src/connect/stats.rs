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

    /// Turns off the daemon.
    async fn kill(&self) -> bool {
        smolscale::spawn(async {
            smol::Timer::after(Duration::from_secs(1)).await;
            std::process::exit(0);
        })
        .detach();
        true
    }
}
