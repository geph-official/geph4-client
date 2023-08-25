use std::net::SocketAddr;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct BridgeMetrics {
    pub address: SocketAddr,
    pub protocol: String,
    pub pipe_latency: Option<f64>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum Metrics {
    ConnEstablished {
        bridges: Vec<BridgeMetrics>,
        total_latency: f64,
    },
}
