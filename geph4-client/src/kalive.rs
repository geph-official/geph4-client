use crate::cache::ClientCache;
use crate::{stats::StatCollector, vpn::run_vpn};
use anyhow::Context;
use smol::channel::{Receiver, Sender};
use smol::prelude::*;
use smol_timeout::TimeoutExt;
use std::time::Duration;
use std::{sync::Arc, time::Instant};
/// An "actor" that keeps a client session alive.
#[derive(Clone)]
pub struct Keepalive {
    open_socks5_conn: Sender<(String, Sender<sosistab::mux::RelConn>)>,
    get_stats: Sender<Sender<Vec<sosistab::SessionStat>>>,
    _task: Arc<smol::Task<anyhow::Result<()>>>,
}

impl Keepalive {
    /// Creates a new keepalive.
    pub fn new(
        stats: Arc<StatCollector>,
        exit_host: &str,
        use_bridges: bool,
        stdio_vpn: bool,
        ccache: Arc<ClientCache>,
    ) -> Self {
        let (send, recv) = smol::channel::unbounded();
        let (send_stats, recv_stats) = smol::channel::unbounded();
        Keepalive {
            open_socks5_conn: send,
            get_stats: send_stats,
            _task: Arc::new(smolscale::spawn(keepalive_actor(
                stats,
                exit_host.to_string(),
                use_bridges,
                stdio_vpn,
                ccache,
                recv,
                recv_stats,
            ))),
        }
    }

    /// Opens a connection
    pub async fn connect(&self, remote: &str) -> anyhow::Result<sosistab::mux::RelConn> {
        let (send, recv) = smol::channel::bounded(1);
        self.open_socks5_conn
            .send((remote.to_string(), send))
            .await?;
        Ok(recv.recv().await?)
    }

    /// Gets session statistics
    pub async fn get_stats(&self) -> anyhow::Result<Vec<sosistab::SessionStat>> {
        let (send, recv) = smol::channel::bounded(1);
        self.get_stats.send(send).await?;
        Ok(recv.recv().await?)
    }
}

async fn keepalive_actor(
    stats: Arc<StatCollector>,
    exit_host: String,
    use_bridges: bool,
    stdio_vpn: bool,
    ccache: Arc<ClientCache>,
    recv_socks5_conn: Receiver<(String, Sender<sosistab::mux::RelConn>)>,
    recv_get_stats: Receiver<Sender<Vec<sosistab::SessionStat>>>,
) -> anyhow::Result<()> {
    loop {
        if let Err(err) = keepalive_actor_once(
            stats.clone(),
            exit_host.clone(),
            use_bridges,
            stdio_vpn,
            ccache.clone(),
            recv_socks5_conn.clone(),
            recv_get_stats.clone(),
        )
        .await
        {
            log::warn!("keepalive_actor restarting: {:#?}", err);
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    }
}

async fn keepalive_actor_once(
    stats: Arc<StatCollector>,
    exit_host: String,
    use_bridges: bool,
    stdio_vpn: bool,
    ccache: Arc<ClientCache>,
    recv_socks5_conn: Receiver<(String, Sender<sosistab::mux::RelConn>)>,
    recv_get_stats: Receiver<Sender<Vec<sosistab::SessionStat>>>,
) -> anyhow::Result<()> {
    stats.set_exit_descriptor(None);

    // find the exit
    let mut exits = ccache.get_exits().await.context("can't get exits")?;
    if exits.is_empty() {
        anyhow::bail!("no exits found")
    }
    exits.sort_by(|a, b| {
        strsim::damerau_levenshtein(&a.hostname, &exit_host)
            .cmp(&strsim::damerau_levenshtein(&b.hostname, &exit_host))
    });
    let exit_host = exits[0].hostname.clone();

    let bridge_sess_async = async {
        let bridges = ccache
            .get_bridges(&exit_host)
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
                            for _ in 0..5 {
                                let _ =
                                    sosistab::connect_udp(desc.endpoint, desc.sosistab_key).await;
                            }
                            sosistab::connect_udp(desc.endpoint, desc.sosistab_key).await
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
    let exit_info = exits.iter().find(|v| v.hostname == exit_host).unwrap();
    let connected_sess_async = async {
        if use_bridges {
            bridge_sess_async.await
        } else {
            async {
                Ok(infal(
                    sosistab::connect_tcp(
                        aioutils::resolve(&format!("{}:19831", exit_info.hostname))
                            .await
                            .context("can't resolve hostname of exit")?
                            .into_iter()
                            .find(|v| v.is_ipv4())
                            .context("can't find ipv4 address for exit")?,
                        exit_info.sosistab_key,
                    )
                    .await,
                )
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
    let session: anyhow::Result<sosistab::Session> = connected_sess_async
        .or(async {
            smol::Timer::after(Duration::from_secs(20)).await;
            anyhow::bail!("initial connection timeout after 20");
        })
        .await;
    let session = session?;
    let mux = Arc::new(sosistab::mux::Multiplex::new(session));
    let scope = smol::Executor::new();
    // now let's authenticate
    let token = ccache.get_auth_token().await?;
    authenticate_session(&mux, &token)
        .timeout(Duration::from_secs(5))
        .await
        .ok_or_else(|| anyhow::anyhow!("authentication timed out"))??;
    log::info!(
        "KEEPALIVE MAIN LOOP for exit_host={}, use_bridges={}",
        exit_host,
        use_bridges
    );
    stats.set_exit_descriptor(Some(exits[0].clone()));
    scope
        .spawn(async {
            loop {
                smol::Timer::after(Duration::from_secs(200)).await;
                if mux
                    .open_conn(None)
                    .timeout(Duration::from_secs(60))
                    .await
                    .is_none()
                {
                    log::warn!("watchdog conn didn't work!");
                }
            }
        })
        .detach();

    let (send_death, recv_death) = smol::channel::unbounded::<anyhow::Error>();

    // VPN mode
    let mut _nuunuu = None;
    if stdio_vpn {
        let mux = mux.clone();
        let send_death = send_death.clone();
        let stats = stats.clone();
        _nuunuu = Some(smolscale::spawn(async move {
            if let Err(err) = run_vpn(stats, mux).await {
                drop(send_death.try_send(err));
            }
        }));
    }
    scope
        .run(
            async {
                loop {
                    let (conn_host, conn_reply) = recv_socks5_conn
                        .recv()
                        .await
                        .context("cannot get socks5 connect request")?;
                    let mux = &mux;
                    let send_death = send_death.clone();
                    scope
                        .spawn(async move {
                            let start = Instant::now();
                            let remote = (&mux).open_conn(Some(conn_host)).await;
                            match remote {
                                Ok(remote) => {
                                    let sess_stats = mux.get_session().latest_stat();
                                    if let Some(stat) = sess_stats {
                                        log::debug!(
                                            "opened connection in {} ms; loss = {:.2}%",
                                            start.elapsed().as_millis(),
                                            stat.total_loss * 100.0
                                        );
                                    };
                                    conn_reply.send(remote).await?;
                                    Ok::<(), anyhow::Error>(())
                                }
                                Err(err) => {
                                    send_death
                                        .send(anyhow::anyhow!(
                                            "conn open error {} in {}s",
                                            err,
                                            start.elapsed().as_secs_f64()
                                        ))
                                        .await?;
                                    Ok(())
                                }
                            }
                        })
                        .detach();
                }
            }
            .or(async {
                let e = recv_death.recv().await?;
                anyhow::bail!(e)
            })
            .or(async {
                loop {
                    let stat_send = recv_get_stats.recv().await?;
                    let stats = mux.get_session().all_stats();
                    drop(stat_send.send(stats).await);
                }
            }),
        )
        .await
}

async fn infal<T, E>(v: Result<T, E>) -> T {
    if let Ok(v) = v {
        v
    } else {
        smol::future::pending().await
    }
}

/// authenticates a muxed session
async fn authenticate_session(
    session: &sosistab::mux::Multiplex,
    token: &crate::cache::Token,
) -> anyhow::Result<()> {
    let mut auth_conn = session.open_conn(None).await?;
    log::debug!("sending auth info...");
    aioutils::write_pascalish(
        &mut auth_conn,
        &(
            &token.unblinded_digest,
            &token.unblinded_signature,
            &token.level,
        ),
    )
    .await?;
    let _: u8 = aioutils::read_pascalish(&mut auth_conn).await?;
    Ok(())
}
