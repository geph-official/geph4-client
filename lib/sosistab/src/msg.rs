use bytes::Bytes;
use serde::{Deserialize, Serialize};
/// Frame sent as a session-negotiation message. This is always encrypted with the cookie.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HandshakeFrame {
    /// Frame sent from client to server when opening a connection. This is always globally encrypted.
    ClientHello {
        long_pk: x25519_dalek::PublicKey,
        eph_pk: x25519_dalek::PublicKey,
        version: u64,
    },
    /// Frame sent from server to client to give a cookie for finally opening a connection.
    ServerHello {
        long_pk: x25519_dalek::PublicKey,
        eph_pk: x25519_dalek::PublicKey,
        /// This value includes all the info required to reconstruct a session, encrypted under a secret key only the server knows.
        resume_token: Bytes,
    },

    /// Frame sent from client to server to either signal roaming, or complete an initial handshake. This is globally encrypted.
    /// Clients should send a ClientResume every time they suspect that their IP has changed.
    ClientResume {
        resume_token: Bytes,
        /// Which shard is this
        shard_id: u8,
    },
}

/// Frame sent as an per-session message. This is always encrypted with a per-session key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataFrame {
    /// Strictly incrementing counter of frames. Must never repeat.
    pub frame_no: u64,
    /// Strictly incrementing counter of runs
    pub run_no: u64,
    /// Run index
    pub run_idx: u8,
    /// Data shards in this run.
    pub data_shards: u8,
    /// Parity shards in this run.
    pub parity_shards: u8,
    /// Index.
    /// Highest delivered frame
    pub high_recv_frame_no: u64,
    /// Total delivered frames
    pub total_recv_frames: u64,
    /// Body.
    pub body: Bytes,
}
