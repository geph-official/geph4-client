use crate::vpn::run_vpn;
use crate::{
    activity::{notify_activity, timeout_multiplier},
    cache::ClientCache,
    main_connect::ConnectOpt,
};
use anyhow::Context;
use binder_transport::ExitDescriptor;
use getsess::get_session;
use smol::channel::{Receiver, Sender};
use smol::prelude::*;
use smol_timeout::TimeoutExt;
use sosistab::Multiplex;
use std::time::Duration;
use std::{sync::Arc, time::Instant};

use self::reroute::rerouter_loop;

mod getsess;
mod reroute;

/// An "actor" that manages a Geph tunnel
#[derive(Clone)]
pub struct TunnelManager {
    open_socks5_conn: Sender<(String, Sender<sosistab::RelConn>)>,
    _task: Arc<smol::Task<anyhow::Result<()>>>,
}

impl TunnelManager {
    /// Creates a new TunnelManager
    pub fn new(cfg: ConnectOpt, ccache: Arc<ClientCache>) -> Self {
        // Sets up channels to communicate with the background task
        let (send, recv) = smol::channel::unbounded();
        TunnelManager {
            open_socks5_conn: send,
            _task: Arc::new(smolscale::spawn(tunnel_actor(cfg, ccache, recv))),
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
) -> anyhow::Result<()> {
    loop {
        let cfg = cfg.clone();
        // Run until a failure happens, log the error, then restart
        if let Err(err) = tunnel_actor_once(cfg, ccache.clone(), recv_socks5_conn.clone()).await {
            log::warn!("tunnel_actor restarting: {:?}", err);
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    }
}

async fn tunnel_actor_once(
    cfg: ConnectOpt,
    ccache: Arc<ClientCache>,
    recv_socks5_conn: Receiver<(String, Sender<sosistab::RelConn>)>,
) -> anyhow::Result<()> {
    notify_activity();
    let exit_info = get_closest_exit(cfg.exit_server.clone(), &ccache).await?;

    let protosess = if cfg.use_tcp {
        get_session(&exit_info, &ccache, cfg.use_bridges, true).await?
    } else {
        get_session(&exit_info, &ccache, cfg.use_bridges, false).await?
    };

    let tunnel_mux = Arc::new(protosess.multiplex());

    // Now let's authenticate
    let token = ccache.get_auth_token().await?;
    authenticate_session(&tunnel_mux, &token)
        .timeout(Duration::from_secs(15))
        .await
        .ok_or_else(|| anyhow::anyhow!("authentication timed out"))??;
    log::info!(
        "TUNNEL_MANAGER MAIN LOOP for exit_host={}, use_bridges={}, use_tcp={}",
        cfg.exit_server,
        cfg.use_bridges,
        cfg.use_tcp
    );

    // Set up a watchdog to keep the connection alive
    let _watchdog = smolscale::spawn(watchdog_loop(tunnel_mux.clone()));

    // Set up a session rerouter
    let rerouter_fut = rerouter_loop(
        &tunnel_mux,
        &exit_info,
        &ccache,
        cfg.use_bridges,
        cfg.use_tcp,
    );

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
    async move {
        loop {
            let (conn_host, conn_reply) = recv_socks5_conn
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
    .or(rerouter_fut)
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
        smol::Timer::after(Duration::from_secs(10).mul_f64(timeout_multiplier())).await;
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
    session: &sosistab::Multiplex,
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
    log::debug!("sent auth info!");
    let _: u8 = aioutils::read_pascalish(&mut auth_conn).await?;
    Ok(())
}
