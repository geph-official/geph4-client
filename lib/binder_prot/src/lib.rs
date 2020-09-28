use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// A **signed** exit route message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitRouteMsg {
    pub sender: ed25519_dalek::PublicKey,
    pub signature: ed25519_dalek::Signature,
    inner: Vec<u8>,
}

impl ExitRouteMsg {
    /// Consumes the message, verifies the signature, and returns the actual message contents.
    pub fn verify(&self) -> Option<InnerExitRouteMsg> {
        // verify the signature
        if self
            .sender
            .verify_strict(&self.inner, &self.signature)
            .is_err()
        {
            return None;
        }
        // decode the message
        bincode::deserialize(&self.inner).ok()
    }
}

/// The actual contents of an exit route message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InnerExitRouteMsg {
    pub expiry_date: std::time::SystemTime,
    pub address: SocketAddr,
    pub cookie: Vec<u8>,
}
