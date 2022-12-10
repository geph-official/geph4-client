use crate::tunnel::EndpointSource;

use super::{
    activity::{notify_activity, wait_activity},
    getsess::get_session,
    TunnelCtx,
};
use anyhow::Context;
use async_trait::async_trait;
use geph4_protocol::{
    binder::protocol::BlindToken,
    client_exit::{ClientExitClient, CLIENT_EXIT_PSEUDOHOST},
    VpnMessage,
};

use nanorpc::{JrpcRequest, JrpcResponse, RpcTransport};
// use parking_lot::RwLock;
use smol::{
    channel::{Receiver, Sender},
    io::BufReader,
    prelude::*,
};
use smol_timeout::TimeoutExt;
use sosistab2::MuxStream;

use std::{
    sync::{atomic::Ordering, Arc},
    time::Duration,
    time::Instant,
};

/// Background task of a TunnelManager
pub(crate) async fn tunnel_actor(ctx: TunnelCtx) -> anyhow::Result<()> {
    loop {
        // Run until a failure happens, log the error, then restart
        if let Err(err) = tunnel_actor_once(ctx.clone()).await {
            log::warn!("tunnel_actor restarting: {:?}", err);
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    }
}

async fn tunnel_actor_once(ctx: TunnelCtx) -> anyhow::Result<()> {
    let ctx1 = ctx.clone();
    ctx.vpn_client_ip.store(0, Ordering::Relaxed);
    notify_activity();

    let tunnel_mux = get_session(ctx.clone()).await?;

    if let EndpointSource::Binder(binder_tunnel_params) = ctx.endpoint {
        // authenticate
        let token = binder_tunnel_params.ccache.get_auth_token().await?.1;
        authenticate_session(&tunnel_mux, &token)
            .timeout(Duration::from_secs(15))
            .await
            .ok_or_else(|| anyhow::anyhow!("authentication timed out"))??;
    }

    // negotiate vpn
    // let client_id: u128 = rand::random();
    // log::info!("negotiating VPN with client id {}...", client_id);
    // let vpn_client_ip = loop {
    //     log::debug!("trying...");
    //     let hello = VpnMessage::ClientHello { client_id };
    //     tunnel_mux
    //         .send_urel(bincode::serialize(&hello)?.as_slice())
    //         .await?;
    //     let resp = tunnel_mux.recv_urel().timeout(Duration::from_secs(1)).await;
    //     if let Some(resp) = resp {
    //         let resp = resp?;
    //         let resp: VpnMessage = bincode::deserialize(&resp)?;
    //         match resp {
    //             VpnMessage::ServerHello { client_ip, .. } => break client_ip,
    //             _ => continue,
    //         }
    //     }
    // };
    // log::info!("negotiated IP address {}!", vpn_client_ip);
    log::info!("TUNNEL_ACTOR MAIN LOOP!");

    ctx.vpn_client_ip.store(12345, Ordering::Relaxed);

    let (send_death, recv_death) = smol::channel::unbounded();

    connection_handler_loop(ctx1.clone(), tunnel_mux.clone(), send_death)
        .or(async {
            // kill the whole session if any one connection fails
            let e = recv_death.recv().await.context("death received")?;
            anyhow::bail!(e)
        })
        .or(watchdog_loop(ctx1.clone(), tunnel_mux.clone()))
        // .or(vpn_up_loop(tunnel_mux.clone(), ctx.recv_vpn_outgoing))
        // .or(vpn_down_loop(tunnel_mux, ctx.send_vpn_incoming))
        .await
}

/// authenticates a muxed session
async fn authenticate_session(
    session: &sosistab2::Multiplex,
    token: &BlindToken,
) -> anyhow::Result<()> {
    let tport = MuxStreamTransport::new(session.open_conn(CLIENT_EXIT_PSEUDOHOST).await?);
    let client = ClientExitClient::from(tport);
    if !client.validate(token.clone()).await? {
        anyhow::bail!("invalid authentication token")
    }
    Ok(())
}

struct MuxStreamTransport {
    write: smol::lock::Mutex<MuxStream>,
    read: smol::lock::Mutex<BufReader<MuxStream>>,
}

impl MuxStreamTransport {
    fn new(stream: MuxStream) -> Self {
        Self {
            write: stream.clone().into(),
            read: BufReader::new(stream).into(),
        }
    }
}

#[async_trait]
impl RpcTransport for MuxStreamTransport {
    type Error = anyhow::Error;

    async fn call_raw(&self, jrpc: JrpcRequest) -> anyhow::Result<JrpcResponse> {
        let mut write = self.write.lock().await;
        write.write_all(&serde_json::to_vec(&jrpc)?).await?;
        write.write_all(b"\n").await?;
        let mut in_line = String::new();
        let mut read = self.read.lock().await;
        read.read_line(&mut in_line).await?;
        let incoming: JrpcResponse = serde_json::from_str(&in_line)?;
        Ok(incoming)
    }
}

async fn vpn_up_loop(
    _mux: Arc<sosistab2::Multiplex>,
    _recv_outgoing: Receiver<VpnMessage>,
) -> anyhow::Result<()> {
    todo!()
    // loop {
    //     if let Ok(msg) = recv_outgoing.recv().await {
    //         mux.send_urel(&bincode::serialize(&msg)?[..]).await?;
    //     }
    // }
}

async fn vpn_down_loop(
    _mux: Arc<sosistab2::Multiplex>,
    _send_incoming: Sender<VpnMessage>,
) -> anyhow::Result<()> {
    todo!()
    // loop {
    //     let bts = mux.recv_urel().await.context("downstream failed")?;
    //     let msg = bincode::deserialize(&bts).context("invalid downstream data")?;
    //     send_incoming.try_send(msg)?;
    // }
}

// handles socks5 connection requests
async fn connection_handler_loop(
    ctx: TunnelCtx,
    mux: Arc<sosistab2::Multiplex>,
    send_death: Sender<anyhow::Error>,
) -> anyhow::Result<()> {
    loop {
        let (conn_host, conn_reply) = ctx
            .recv_socks5_conn
            .recv()
            .await
            .context("cannot get socks5 connect request")?;
        let mux = mux.clone();
        let send_death = send_death.clone();
        notify_activity();
        smolscale::spawn(async move {
            let start = Instant::now();
            let remote = mux
                .open_conn(&conn_host)
                .timeout(Duration::from_secs(10))
                .await;
            match remote {
                Some(Ok(remote)) => {
                    log::debug!(
                        "opened connection to {} in {} ms",
                        conn_host,
                        start.elapsed().as_millis(),
                    );

                    conn_reply.send(remote).await.context("conn_reply failed")?;
                    Ok::<(), anyhow::Error>(())
                }
                Some(Err(err)) => {
                    send_death
                        .send(anyhow::anyhow!(
                            "conn open error {} in {}s",
                            err,
                            start.elapsed().as_secs_f64()
                        ))
                        .await?;
                    Ok(())
                }
                None => {
                    send_death
                        .send(anyhow::anyhow!(
                            "conn timeout in {}s",
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

// keeps the connection alive
async fn watchdog_loop(
    _ctx: TunnelCtx,
    tunnel_mux: Arc<sosistab2::Multiplex>,
) -> anyhow::Result<()> {
    loop {
        wait_activity(Duration::from_secs(600)).await;
        let start = Instant::now();
        if tunnel_mux
            .open_conn(CLIENT_EXIT_PSEUDOHOST)
            .timeout(Duration::from_secs(10))
            .await
            .is_none()
        {
            log::warn!("watchdog conn failed! resetting...");
            anyhow::bail!("watchdog failed");
        } else {
            let ping = start.elapsed();
            log::debug!("** watchdog completed in {:?} **", ping);

            smol::Timer::after(Duration::from_secs(3)).await;
        }
    }
}
