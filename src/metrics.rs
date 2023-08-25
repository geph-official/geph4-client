use std::net::SocketAddr;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct BridgeMetrics {
    pub address: SocketAddr,
    pub protocol: String,
    pub pipe_latency: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct Metrics {
    pub r#type: MetricsType,
    pub bridges: Vec<BridgeMetrics>,
    pub total_latency: f64,
}

#[derive(Debug, Serialize)]
pub enum MetricsType {
    ConnEstablished,
}
