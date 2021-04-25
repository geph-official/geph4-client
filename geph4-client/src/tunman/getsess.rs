use crate::{cache::ClientCache, stats::global_sosistab_stats};
use anyhow::Context;
use async_net::SocketAddr;
use binder_transport::ExitDescriptor;
use smol::prelude::*;
use smol_timeout::TimeoutExt;
use sosistab::{Multiplex, Session};
use std::time::{Duration, Instant};

/// Obtains a session.
pub async fn get_session(
    exit_info: &ExitDescriptor,
    ccache: &ClientCache,
    use_bridges: bool,
    use_tcp: bool,
) -> anyhow::Result<ProtoSession> {
    let bridge_sess_async = async {
        let bridges = ccache
            .get_bridges(&exit_info.hostname)
            .await
            .context("can't get bridges")?;
        log::debug!("got {} bridges", bridges.len());
        if bridges.is_empty() {
            anyhow::bail!("absolutely no bridges found")
        }
        let start = Instant::now();
        // spawn a task for *every* bridge
        let (send, recv) = smol::channel::unbounded();
        let _tasks: Vec<_> = bridges
            .into_iter()
            .map(|desc| {
                let send = send.clone();
                smolscale::spawn(async move {
                    log::debug!("connecting through {}...", desc.endpoint);
                    let res = async {
                        if !use_tcp {
                            for _ in 0u8..3 {
                                let _ = sosistab::connect_udp(
                                    desc.endpoint,
                                    desc.sosistab_key,
                                    global_sosistab_stats(),
                                )
                                .await;
                            }
                            sosistab::connect_udp(
                                desc.endpoint,
                                desc.sosistab_key,
                                global_sosistab_stats(),
                            )
                            .await
                        } else {
                            sosistab::connect_tcp(
                                desc.endpoint,
                                desc.sosistab_key,
                                global_sosistab_stats(),
                            )
                            .await
                        }
                    }
                    .timeout(Duration::from_secs(10))
                    .await;
                    if let Some(res) = res {
                        drop(send.send((desc.endpoint, res)).await)
                    }
                })
            })
            .collect();
        // wait for a successful result
        loop {
            let (saddr, res) = recv.recv().await.context("ran out of bridges")?;
            if let Ok(res) = res {
                log::info!(
                    "{} is our fastest bridge, latency={}",
                    saddr,
                    start.elapsed().as_millis()
                );
                break Ok((res, saddr));
            }
        }
    };
    let connected_sess_async = async {
        if use_bridges {
            bridge_sess_async.await
        } else {
            aioutils::try_race(
                async {
                    let server_addr = aioutils::resolve(&format!("{}:19831", exit_info.hostname))
                        .await
                        .context("can't resolve hostname of exit")?
                        .into_iter()
                        .find(|v| v.is_ipv4())
                        .context("can't find ipv4 address for exit")?;

                    Ok((
                        if use_tcp {
                            sosistab::connect_tcp(
                                server_addr,
                                exit_info.sosistab_key,
                                global_sosistab_stats(),
                            )
                            .await?
                        } else {
                            sosistab::connect_udp(
                                server_addr,
                                exit_info.sosistab_key,
                                global_sosistab_stats(),
                            )
                            .await?
                        },
                        server_addr,
                    ))
                },
                async {
                    smol::Timer::after(Duration::from_secs(1)).await;
                    log::warn!("racing with bridges because direct connection took a while");
                    bridge_sess_async.await
                },
            )
            .await
        }
    };
    let (sess, remote_addr) = connected_sess_async
        .or(async {
            smol::Timer::after(Duration::from_secs(40)).await;
            ccache.purge_bridges(&exit_info.hostname)?;
            anyhow::bail!("initial connection timeout after 40");
        })
        .await?;
    Ok(ProtoSession {
        inner: sess,
        remote_addr,
    })
}

/// A session before it can really be used. It directly wraps a sosistab Session.
pub struct ProtoSession {
    inner: Session,
    remote_addr: SocketAddr,
}

impl ProtoSession {
    /// Remote addr of session.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Creates a multiplexed session directly.
    pub fn multiplex(self) -> Multiplex {
        // // We send a packet consisting of 32 zeros. This is the standard signal for a fresh session that doesn't hijack an existing multiplex.
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
                self.inner.send_bytes(other_id.to_vec().into()).await?;
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
