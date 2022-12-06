use std::time::Duration;

use anyhow::Context;
use async_net::SocketAddr;
use smol::future::FutureExt;
use sosistab::{Multiplex, Session};

/// A session before it can really be used. It directly wraps a sosistab Session.
pub struct ProtoSession {
    pub inner: Session,
    pub remote_addr: SocketAddr,
}

impl ProtoSession {
    /// Remote addr of session.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Creates a multiplexed session directly.
    pub fn multiplex(self) -> Multiplex {
        // We send a packet consisting of 32 zeros. This is the standard signal for a fresh session that doesn't hijack an existing multiplex.
        // self.inner.send_bytes(vec![0; 32].into());
        self.inner.multiplex()
    }

    /// Hijacks an existing multiplex with this session.
    pub async fn hijack(self, other_mplex: &Multiplex, other_id: [u8; 32]) -> anyhow::Result<()> {
        log::debug!(
            "starting hijack of other_id = {}...",
            hex::encode(&other_id[..5])
        );
        // Then we repeatedly spam the ID on the inner session until we receive one packet (which we assume to be a data packet from the successfully hijacked multiplex)
        let spam_loop = async {
            loop {
                self.inner.send_bytes(other_id.as_ref()).await?;
                smol::Timer::after(Duration::from_secs(1)).await;
            }
        };
        spam_loop
            .race(async {
                let down = self
                    .inner
                    .recv_bytes()
                    .await
                    .context("inner session failed in hijack")?;
                log::debug!(
                    "finished hijack of other_id = {} with downstream data of {}!",
                    hex::encode(&other_id[..5]),
                    down.len()
                );
                Ok::<_, anyhow::Error>(())
            })
            .await?;
        other_mplex.replace_session(self.inner).await;
        Ok(())
    }
}
