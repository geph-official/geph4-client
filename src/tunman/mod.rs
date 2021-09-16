use crate::tunman::reroute::rerouter_once;
use crate::{
    activity::notify_activity, cache::ClientCache, main_connect::ConnectOpt,
    tunman::tunnelctx::TunnelCtx,
};
use crate::{activity::wait_activity, vpn::run_vpn};
use anyhow::Context;
use geph4_binder_transport::ExitDescriptor;
use getsess::get_session;
use parking_lot::RwLock;
use smol::channel::{Receiver, Sender};
use smol::prelude::*;
use smol_timeout::TimeoutExt;
use sosistab::Multiplex;
use std::net::SocketAddr;
use std::time::Duration;
use std::{sync::Arc, time::Instant};

mod getsess;
mod reroute;
mod tunnelctx;

/// The state of the tunnel.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TunnelState {
    Connecting,
    Connected { exit: String },
}

/// An "actor" that manages a Geph tunnel
#[derive(Clone)]
pub struct TunnelManager {
    current_state: Arc<RwLock<TunnelState>>,
    open_socks5_conn: Sender<(String, Sender<sosistab::RelConn>)>,
    _task: Arc<smol::Task<anyhow::Result<()>>>,
}

impl TunnelManager {
    /// Creates a new TunnelManager
    pub fn new(cfg: ConnectOpt, ccache: Arc<ClientCache>) -> Self {
        // Sets up channels to communicate with the background task
        let (send, recv) = smol::channel::unbounded();
        let current_state = Arc::new(RwLock::new(TunnelState::Connecting));
        TunnelManager {
            current_state: current_state.clone(),
            open_socks5_conn: send,
            _task: Arc::new(smolscale::spawn(tunnel_actor(
                cfg,
                ccache,
                recv,
                current_state,
            ))),
        }
    }

    /// Opens a connection
    pub async fn connect(&self, remote: &str) -> anyhow::Result<sosistab::RelConn> {
        let (send, recv) = smol::channel::bounded(1);
        self.open_socks5_conn
            .send((remote.to_string(), send))
            .await?;
        Ok(recv.recv().await?)
    }

    /// Obtains the current state.
    pub fn current_state(&self) -> TunnelState {
        self.current_state.read().clone()
    }

    // /// Gets session statistics
    // pub async fn get_stats(&self) -> anyhow::Result<im::Vector<sosistab::SessionStat>> {
    //     let (send, recv) = smol::channel::bounded(1);
    //     self.get_stats.send(send).await?;
    //     Ok(recv.recv().await?)
    // }
}

/// Background task of a TunnelManager
async fn tunnel_actor(
    cfg: ConnectOpt,
    ccache: Arc<ClientCache>,
    recv_socks5_conn: Receiver<(String, Sender<sosistab::RelConn>)>,
    current_state: Arc<RwLock<TunnelState>>,
) -> anyhow::Result<()> {
    loop {
        let cfg = cfg.clone();
        // Run until a failure happens, log the error, then restart
        if let Err(err) = tunnel_actor_once(
            cfg,
            ccache.clone(),
            recv_socks5_conn.clone(),
            current_state.clone(),
        )
        .await
        {
            log::warn!("tunnel_actor restarting: {:?}", err);
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    }
}

async fn tunnel_actor_once(
    cfg: ConnectOpt,
    ccache: Arc<ClientCache>,
    recv_socks5_conn: Receiver<(String, Sender<sosistab::RelConn>)>,
    current_state: Arc<RwLock<TunnelState>>,
) -> anyhow::Result<()> {
    *current_state.write() = TunnelState::Connecting;
    notify_activity();
    let selected_exit = get_closest_exit(cfg.exit_server.clone(), &ccache).await?;
    let ctx = TunnelCtx {
        opt: cfg.clone(),
        ccache,
        recv_socks5_conn,
        current_state,
        selected_exit,
    };

    let protosess = get_session(ctx.clone(), None).await?;

    let protosess_remaddr = protosess.remote_addr();

    let tunnel_mux = Arc::new(protosess.multiplex());

    // Now let's authenticate
    if ctx.opt.override_connect.is_none() {
        let token = ctx.ccache.get_auth_token().await?;
        authenticate_session(&tunnel_mux, &token)
            .timeout(Duration::from_secs(15))
            .await
            .ok_or_else(|| anyhow::anyhow!("authentication timed out"))??;
    }
    log::info!("TUNNEL_MANAGER MAIN LOOP through {}", protosess_remaddr);
    *ctx.current_state.write() = TunnelState::Connected {
        exit: ctx.selected_exit.hostname.clone(),
    };

    // Set up a watchdog to keep the connection alive
    let watchdog_fut = smolscale::spawn(watchdog_loop(
        ctx.clone(),
        protosess_remaddr,
        tunnel_mux.clone(),
    ));

    let (send_death, recv_death) = smol::channel::unbounded::<anyhow::Error>();

    // VPN mode
    let mut _vpn_task = None;
    if cfg.stdio_vpn {
        let mux = tunnel_mux.clone();
        let send_death = send_death.clone();
        _vpn_task = Some(smolscale::spawn(async move {
            if let Err(err) = run_vpn(mux).await.context("run_vpn failed") {
                drop(send_death.try_send(err));
            }
        }));
    }

    let mux1 = tunnel_mux.clone();
    async {
        loop {
            let (conn_host, conn_reply) = ctx
                .recv_socks5_conn
                .recv()
                .await
                .context("cannot get socks5 connect request")?;
            let mux = mux1.clone();
            let send_death = send_death.clone();
            smolscale::spawn(async move {
                let start = Instant::now();
                let remote = (&mux).open_conn(Some(conn_host)).await;
                match remote {
                    Ok(remote) => {
                        log::debug!("opened connection in {} ms", start.elapsed().as_millis(),);

                        conn_reply.send(remote).await.context("conn_reply failed")?;
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
        let e = recv_death.recv().await.context("death received")?;
        anyhow::bail!(e)
    })
    .or(watchdog_fut)
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

async fn watchdog_loop(
    ctx: TunnelCtx,
    bridge_addr: SocketAddr,
    tunnel_mux: Arc<Multiplex>,
) -> anyhow::Result<()> {
    // We first request the ID of the other multiplex.
    let other_id = {
        let mut conn = tunnel_mux.open_conn(Some("!id".into())).await?;
        let mut buf = [0u8; 32];
        conn.read_exact(&mut buf).await.context("!id failed")?;
        buf
    };
    loop {
        wait_activity(Duration::from_secs(600)).await;
        let start = Instant::now();
        if tunnel_mux
            .open_conn(None)
            .timeout(Duration::from_secs(15))
            .await
            .is_none()
        {
            log::warn!("watchdog conn failed! rerouting...");
            rerouter_once(ctx.clone(), bridge_addr, &tunnel_mux, other_id)
                .timeout(Duration::from_secs(15))
                .await
                .context("rerouter timed out")??;
            log::warn!("rerouting done.");
        } else {
            log::debug!("** watchdog completed in {:?} **", start.elapsed());
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    }
}

/// authenticates a muxed session
async fn authenticate_session(
    session: &sosistab::Multiplex,
    token: &crate::cache::Token,
) -> anyhow::Result<()> {
    let mut auth_conn = session.open_conn(None).await?;
    log::debug!("sending auth info...");
    geph4_aioutils::write_pascalish(
        &mut auth_conn,
        &(
            &token.unblinded_digest,
            &token.unblinded_signature,
            &token.level,
        ),
    )
    .await?;
    log::debug!("sent auth info!");
    let _: u8 = geph4_aioutils::read_pascalish(&mut auth_conn).await?;
    Ok(())
}
