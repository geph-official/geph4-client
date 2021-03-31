use crate::{cache::ClientCache, main_connect::ConnectOpt};
use crate::{stats::StatCollector, vpn::run_vpn};
use anyhow::Context;
use binder_transport::ExitDescriptor;
use getsess::get_session;
use smol::channel::{Receiver, Sender};
use smol::prelude::*;
use smol_timeout::TimeoutExt;
use sosistab::mux::Multiplex;
use std::time::Duration;
use std::{sync::Arc, time::Instant};

mod getsess;

/// An "actor" that manages a Geph tunnel
#[derive(Clone)]
pub struct TunnelManager {
    open_socks5_conn: Sender<(String, Sender<sosistab::mux::RelConn>)>,
    get_stats: Sender<Sender<im::Vector<sosistab::SessionStat>>>,
    _task: Arc<smol::Task<anyhow::Result<()>>>,
}

impl TunnelManager {
    /// Creates a new TunnelManager
    pub fn new(stats: Arc<StatCollector>, cfg: ConnectOpt, ccache: Arc<ClientCache>) -> Self {
        // Sets up channels to communicate with the background task
        let (send, recv) = smol::channel::unbounded();
        let (send_stats, recv_stats) = smol::channel::unbounded();
        TunnelManager {
            open_socks5_conn: send,
            get_stats: send_stats,
            _task: Arc::new(smolscale::spawn(tunnel_actor(
                stats, cfg, ccache, recv, recv_stats,
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
    pub async fn get_stats(&self) -> anyhow::Result<im::Vector<sosistab::SessionStat>> {
        let (send, recv) = smol::channel::bounded(1);
        self.get_stats.send(send).await?;
        Ok(recv.recv().await?)
    }
}

/// Background task of a TunnelManager
async fn tunnel_actor(
    stats: Arc<StatCollector>,
    cfg: ConnectOpt,
    ccache: Arc<ClientCache>,
    recv_socks5_conn: Receiver<(String, Sender<sosistab::mux::RelConn>)>,
    recv_get_stats: Receiver<Sender<im::Vector<sosistab::SessionStat>>>,
) -> anyhow::Result<()> {
    loop {
        let cfg = cfg.clone();
        // Run until a failure happens, log the error, then restart
        if let Err(err) = tunnel_actor_once(
            stats.clone(),
            cfg,
            ccache.clone(),
            recv_socks5_conn.clone(),
            recv_get_stats.clone(),
        )
        .await
        {
            log::warn!("tunnel_actor restarting: {:#?}", err);
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    }
}

async fn tunnel_actor_once(
    stats: Arc<StatCollector>,
    cfg: ConnectOpt,
    ccache: Arc<ClientCache>,
    recv_socks5_conn: Receiver<(String, Sender<sosistab::mux::RelConn>)>,
    recv_get_stats: Receiver<Sender<im::Vector<sosistab::SessionStat>>>,
) -> anyhow::Result<()> {
    stats.set_exit_descriptor(None);
    let exit_info = get_closest_exit(cfg.exit_server.clone(), &ccache).await?;

    let session = if cfg.use_tcp {
        get_session(exit_info.clone(), &ccache, cfg.use_bridges, true).await?
    } else {
        get_session(exit_info.clone(), &ccache, cfg.use_bridges, false).await?
    };

    let tunnel_mux = Arc::new(sosistab::mux::Multiplex::new(session));

    // Now let's authenticate
    let token = ccache.get_auth_token().await?;
    authenticate_session(&tunnel_mux, &token)
        .timeout(Duration::from_secs(5))
        .await
        .ok_or_else(|| anyhow::anyhow!("authentication timed out"))??;
    log::info!(
        "TUNNEL_MANAGER MAIN LOOP for exit_host={}, use_bridges={}, use_tcp={}",
        cfg.exit_server,
        cfg.use_bridges,
        cfg.use_tcp
    );

    stats.set_exit_descriptor(Some(exit_info));

    // Set up a watchdog to keep the connection alive
    let _watchdog = smolscale::spawn(watchdog_loop(tunnel_mux.clone()));

    let (send_death, recv_death) = smol::channel::unbounded::<anyhow::Error>();

    // VPN mode
    let mut _vpn_task = None;
    if cfg.stdio_vpn {
        let mux = tunnel_mux.clone();
        let send_death = send_death.clone();
        let stats = stats.clone();
        _vpn_task = Some(smolscale::spawn(async move {
            if let Err(err) = run_vpn(stats, mux).await {
                drop(send_death.try_send(err));
            }
        }));
    }

    let mux1 = tunnel_mux.clone();
    async move {
        loop {
            let (conn_host, conn_reply) = recv_socks5_conn
                .recv()
                .await
                .context("cannot get socks5 connect request")?;
            let mux = tunnel_mux.clone();
            let send_death = send_death.clone();
            smolscale::spawn(async move {
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
            let stats = mux1.get_session().all_stats();
            drop(stat_send.send(stats).await);
        }
    })
    .await
}

async fn get_closest_exit(
    destination_exit: String,
    ccache: &ClientCache,
) -> anyhow::Result<ExitDescriptor> {
    // find the exit
    let mut exits = ccache.get_exits().await.context("can't get exits")?;
    if exits.is_empty() {
        anyhow::bail!("no exits found")
    }
    // sort exits by similarity to request and returns most similar
    exits.sort_by(|a, b| {
        strsim::damerau_levenshtein(&a.hostname, &destination_exit)
            .cmp(&strsim::damerau_levenshtein(&b.hostname, &destination_exit))
    });
    Ok(exits[0].clone())
}

async fn watchdog_loop(tunnel_mux: Arc<Multiplex>) {
    loop {
        smol::Timer::after(Duration::from_secs(200)).await;
        if tunnel_mux
            .open_conn(None)
            .timeout(Duration::from_secs(60))
            .await
            .is_none()
        {
            log::warn!("watchdog conn failed!");
        }
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
