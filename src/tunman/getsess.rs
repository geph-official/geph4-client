use crate::stats::global_sosistab_stats;
use anyhow::Context;
use async_net::SocketAddr;

use futures_util::stream::FuturesUnordered;
use smol::prelude::*;
use smol_timeout::TimeoutExt;
use sosistab::{Multiplex, Session};
use std::{
    convert::TryFrom,
    time::{Duration, Instant},
};
use tap::{Pipe, Tap};

use super::tunnelctx::TunnelCtx;

fn sosistab_udp(
    server_addr: SocketAddr,
    server_pk: x25519_dalek::PublicKey,
    shard_count: usize,
    reset_interval: Duration,
) -> sosistab::ClientConfig {
    sosistab::ClientConfig::new(
        sosistab::Protocol::DirectUdp,
        server_addr,
        server_pk,
        global_sosistab_stats(),
    )
    .pipe(|mut cfg| {
        cfg.shard_count = shard_count;
        cfg.reset_interval = Some(reset_interval);
        cfg
    })
}

fn sosistab_tcp(
    server_addr: SocketAddr,
    server_pk: x25519_dalek::PublicKey,
    shard_count: usize,
    reset_interval: Duration,
) -> sosistab::ClientConfig {
    sosistab::ClientConfig::new(
        sosistab::Protocol::DirectTcp,
        server_addr,
        server_pk,
        global_sosistab_stats(),
    )
    .pipe(|mut cfg| {
        cfg.shard_count = shard_count;
        cfg.reset_interval = Some(reset_interval);
        cfg
    })
}

/// Gets a session, given a context and a destination
async fn get_one_sess(
    ctx: TunnelCtx,
    addr: SocketAddr,
    pubkey: x25519_dalek::PublicKey,
) -> anyhow::Result<Session> {
    let tcp_fut = sosistab_tcp(
        addr,
        pubkey,
        ctx.opt.tcp_shard_count,
        Duration::from_secs(ctx.opt.tcp_shard_lifetime),
    )
    .connect();
    if !ctx.opt.use_tcp {
        Ok(geph4_aioutils::try_race(
            async {
                let sess = sosistab_udp(
                    addr,
                    pubkey,
                    ctx.opt.udp_shard_count,
                    Duration::from_secs(ctx.opt.udp_shard_lifetime),
                )
                .connect()
                .await?;
                log::info!("connected to UDP for {}", addr);
                Ok(sess)
            },
            async {
                smol::Timer::after(Duration::from_secs(2)).await;
                log::warn!("switching to TCP for {}!", addr);
                tcp_fut.await
            },
        )
        .await?)
    } else {
        Ok(tcp_fut.await?)
    }
}

/// Obtains a session.
pub async fn get_session(
    ctx: TunnelCtx,
    bias_for: Option<SocketAddr>,
) -> anyhow::Result<ProtoSession> {
    // if we override, we don't bother with any of this cool stuff
    if let Some(url) = ctx.opt.override_connect.as_ref() {
        let pk_and_url = url.split('@').collect::<Vec<_>>();
        let server_pk = x25519_dalek::PublicKey::from(
            <[u8; 32]>::try_from(
                hex::decode(&pk_and_url.get(0).context("URL not in form PK@host:port")?)
                    .context("PK is not hex")?,
            )
            .unwrap(),
        );
        let server_addr: SocketAddr = pk_and_url
            .get(1)
            .context("URL not in form PK@host:port")?
            .parse()
            .context("cannot parse host:port")?;
        Ok(ProtoSession {
            inner: if ctx.opt.use_tcp {
                sosistab_tcp(
                    server_addr,
                    server_pk,
                    ctx.opt.tcp_shard_count,
                    Duration::from_secs(ctx.opt.tcp_shard_lifetime),
                )
                .connect()
                .await?
            } else {
                // We spam this several times in parallel and take the "worst".
                const TRY_COUNT: usize = 5;
                let mut racer = FuturesUnordered::new();
                for _ in 0..TRY_COUNT {
                    let udp_shard_count = ctx.opt.udp_shard_count;
                    let udp_shard_lifetime = ctx.opt.udp_shard_lifetime;
                    racer.push(async move {
                        Ok::<_, anyhow::Error>(
                            sosistab_udp(
                                server_addr,
                                server_pk,
                                udp_shard_count,
                                Duration::from_secs(udp_shard_lifetime),
                            )
                            .connect()
                            .await?,
                        )
                    });
                }
                for _ in 0..TRY_COUNT - 1 {
                    // throw away all except one
                    racer.next().await.expect("racer ran out")?;
                }
                racer.next().await.expect("racer ran out")?
            },
            remote_addr: server_addr,
        })
    } else {
        let use_bridges = ctx.opt.use_bridges || ctx.opt.should_use_bridges().await;
        let bridge_sess_async = get_through_fastest_bridge(ctx.clone(), bias_for);
        let connected_sess_async = async {
            if use_bridges {
                bridge_sess_async.await
            } else {
                geph4_aioutils::try_race(
                    async {
                        let server_addr = geph4_aioutils::resolve(&format!(
                            "{}:19831",
                            ctx.selected_exit.hostname
                        ))
                        .await
                        .context("can't resolve hostname of exit")?
                        .into_iter()
                        .find(|v| v.is_ipv4())
                        .context("can't find ipv4 address for exit")?;

                        Ok(ProtoSession {
                            inner: get_one_sess(
                                ctx.clone(),
                                server_addr,
                                ctx.selected_exit.sosistab_key,
                            )
                            .await?,
                            remote_addr: server_addr,
                        })
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

        Ok(connected_sess_async
            .or(async {
                smol::Timer::after(Duration::from_secs(40)).await;
                anyhow::bail!("initial connection timeout after 40");
            })
            .await
            .tap(|x| {
                if x.is_err() {
                    log::warn!("** purging bridges **");
                    let _ = ctx.ccache.purge_bridges(&ctx.selected_exit.hostname);
                }
            })?)
    }
}

/// Obtain a session through bridges
async fn get_through_fastest_bridge(
    ctx: TunnelCtx,
    privileged: Option<SocketAddr>,
) -> anyhow::Result<ProtoSession> {
    let mut bridges = ctx
        .ccache
        .get_bridges(&ctx.selected_exit.hostname)
        .await
        .context("can't get bridges")?;
    log::debug!("got {} bridges", bridges.len());
    if let Some(force_bridge) = ctx.opt.force_bridge {
        bridges.retain(|f| f.endpoint.ip() == force_bridge);
    }
    if bridges.is_empty() {
        anyhow::bail!("absolutely no bridges found")
    }
    let start = Instant::now();
    // spawn a task for *every* bridge
    let mut bridge_futures = FuturesUnordered::new();
    for bridge in bridges.iter().cloned() {
        let fut = async {
            if let Some(privileged) = privileged {
                if bridge.endpoint != privileged {
                    smol::Timer::after(Duration::from_secs(5)).await;
                }
            }
            let conn = get_one_sess(ctx.clone(), bridge.endpoint, bridge.sosistab_key)
                .timeout(Duration::from_secs(20))
                .await
                .context(format!("connection timed out for {}", bridge.endpoint))?
                .context(format!("connection failed for {}", bridge.endpoint))?;
            Ok::<_, anyhow::Error>((conn, bridge))
        };
        bridge_futures.push(fut);
    }
    // wait for a successful result
    while let Some(res) = bridge_futures.next().await {
        match res {
            Ok((res, bdesc)) => {
                log::info!(
                    "found fastest bridge {} in {} ms",
                    bdesc.endpoint,
                    start.elapsed().as_millis()
                );
                return Ok(ProtoSession {
                    inner: res,
                    remote_addr: bdesc.endpoint,
                });
            }
            Err(err) => {
                log::warn!("a bridge failed: {:?}", err);
            }
        }
    }
    anyhow::bail!("all bridges failed")
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
