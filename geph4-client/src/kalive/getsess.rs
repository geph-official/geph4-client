use crate::cache::ClientCache;
use anyhow::Context;
use binder_transport::ExitDescriptor;
use smol::prelude::*;
use std::time::{Duration, Instant};

use super::infal;

pub async fn get_session(
    exit_info: ExitDescriptor,
    ccache: &ClientCache,
    use_bridges: bool,
    use_tcp: bool,
) -> anyhow::Result<sosistab::Session> {
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
                    drop(
                        send.send((desc.endpoint, {
                            // we effectively sum 5 RTTs. this filters out the high-jitter/high-loss crap.
                            if !use_tcp {
                                for _ in 0u8..5 {
                                    let _ = sosistab::connect_udp(desc.endpoint, desc.sosistab_key)
                                        .await;
                                }
                                sosistab::connect_udp(desc.endpoint, desc.sosistab_key).await
                            } else {
                                sosistab::connect_tcp(desc.endpoint, desc.sosistab_key).await
                            }
                        }))
                        .await,
                    )
                })
            })
            .collect();
        // wait for a successful result
        loop {
            let (saddr, res) = recv.recv().await.context("ran out of bridges")?;
            if let Ok(res) = res {
                log::info!(
                    "{} is our fastest bridge, 5rtt={}",
                    saddr,
                    start.elapsed().as_millis()
                );
                break Ok(res);
            }
        }
    };
    let connected_sess_async = async {
        if use_bridges {
            bridge_sess_async.await
        } else {
            async {
                let server_addr = aioutils::resolve(&format!("{}:19831", exit_info.hostname))
                    .await
                    .context("can't resolve hostname of exit")?
                    .into_iter()
                    .find(|v| v.is_ipv4())
                    .context("can't find ipv4 address for exit")?;

                Ok(infal(if use_tcp {
                    sosistab::connect_tcp(server_addr, exit_info.sosistab_key).await
                } else {
                    sosistab::connect_udp(server_addr, exit_info.sosistab_key).await
                })
                .await)
            }
            .or(async {
                smol::Timer::after(Duration::from_secs(1)).await;
                log::warn!("racing with bridges because direct connection took a while");
                bridge_sess_async.await
            })
            .await
        }
    };
    connected_sess_async
        .or(async {
            smol::Timer::after(Duration::from_secs(20)).await;
            anyhow::bail!("initial connection timeout after 20");
        })
        .await
}
