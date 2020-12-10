use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// A client request
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientReq {
    pub packets: Vec<Bytes>,
    pub timeout_ms: u64,
}

/// A server response
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerResp {
    pub packets: Vec<Bytes>,
}
