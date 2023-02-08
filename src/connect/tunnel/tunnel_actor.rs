use crate::connect::{
    stats::{StatItem, STATS_GATHERER, STATS_RECV_BYTES, STATS_SEND_BYTES},
    tunnel::{ConnectionStatus, EndpointSource},
};

use super::{
    activity::{notify_activity, wait_activity},
    getsess::get_session,
    TunnelCtx,
};
use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use geph4_protocol::{
    binder::protocol::BlindToken,
    client_exit::{ClientExitClient, CLIENT_EXIT_PSEUDOHOST},
};
use std::{net::Ipv4Addr, time::SystemTime};

use nanorpc::{JrpcRequest, JrpcResponse, RpcTransport};

use smol::{
    channel::{Receiver, Sender},
    io::BufReader,
    prelude::*,
};
use smol_timeout::TimeoutExt;
use sosistab2::{Multiplex, MuxStream, Pipe};

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

async fn print_stats_loop(mux: Arc<Multiplex>) {
    for _ctr in 0u64.. {
        if let Some(pipe) = mux.last_recv_pipe() {
            log::info!("RECV-CONN {} / PROT {} ", pipe.peer_addr(), pipe.protocol(),);
        }
        smol::Timer::after(Duration::from_secs(30)).await;
    }
}

async fn tunnel_actor_once(ctx: TunnelCtx) -> anyhow::Result<()> {
    let ctx1 = ctx.clone();
    ctx.vpn_client_ip.store(0, Ordering::SeqCst);
    notify_activity();

    let tunnel_mux = get_session(ctx.clone()).await?;

    if let EndpointSource::Binder(binder_tunnel_params) = ctx.endpoint.clone() {
        // authenticate
        let token = binder_tunnel_params.ccache.get_auth_token().await?.1;
        let ipv4 = authenticate_session(&tunnel_mux, &token)
            .timeout(Duration::from_secs(60))
            .await
            .ok_or_else(|| anyhow::anyhow!("authentication timed out"))??;
        log::info!("VPN private IP assigned: {ipv4}");
        ctx.vpn_client_ip.store(ipv4.into(), Ordering::SeqCst);
    } else {
        ctx.vpn_client_ip.store(12345, Ordering::SeqCst);
    }

    log::info!("TUNNEL_ACTOR MAIN LOOP!");
    *ctx.connect_status.write() = ConnectionStatus::Connected {
        protocol: "sosistab2".into(),
        address: "dynamic".into(),
    };
    let ctx2 = ctx.clone();
    scopeguard::defer!({
        *ctx2.connect_status.write() = ConnectionStatus::Connecting;
    });

    let (send_death, recv_death) = smol::channel::unbounded();
    let _lala = smolscale::spawn(print_stats_loop(tunnel_mux.clone()));
    connection_handler_loop(ctx1.clone(), tunnel_mux.clone(), send_death)
        .or(async {
            // kill the whole session if any one connection fails
            let e = recv_death.recv().await.context("death received")?;
            anyhow::bail!(e)
        })
        .or(watchdog_loop(ctx1.clone(), tunnel_mux.clone()))
        .or(vpn_loop(
            tunnel_mux.clone(),
            ctx.send_vpn_incoming,
            ctx.recv_vpn_outgoing,
        ))
        .await
}

/// authenticates a muxed session
async fn authenticate_session(
    session: &sosistab2::Multiplex,
    token: &BlindToken,
) -> anyhow::Result<Ipv4Addr> {
    let tport = MuxStreamTransport::new(session.open_conn(CLIENT_EXIT_PSEUDOHOST).await?);
    let client = ClientExitClient::from(tport);
    if !client.validate(token.clone()).await? {
        anyhow::bail!("invalid authentication token")
    }
    let addr = client
        .get_vpn_ipv4()
        .await?
        .context("server did not provide VPN address")?;
    Ok(addr)
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

async fn vpn_loop(
    mux: Arc<sosistab2::Multiplex>,
    send_incoming: Sender<Bytes>,
    recv_outgoing: Receiver<Bytes>,
) -> anyhow::Result<()> {
    let wire = mux.open_conn(CLIENT_EXIT_PSEUDOHOST).await?;
    let uploop = async {
        loop {
            let to_send = recv_outgoing.recv().await?;
            wire.send_urel(stdcode::serialize(&vec![to_send])?.into())
                .await?;
        }
    };
    let dnloop = async {
        loop {
            let received = wire.recv_urel().await?;
            let received: Vec<Bytes> = stdcode::deserialize(&received)?;
            for received in received {
                send_incoming.send(received).await?;
            }
        }
    };
    uploop.race(dnloop).await
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
                .timeout(Duration::from_secs(60))
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
        let start = Instant::now();
        if tunnel_mux
            .open_conn(CLIENT_EXIT_PSEUDOHOST)
            .timeout(Duration::from_secs(30))
            .await
            .is_none()
        {
            log::warn!("watchdog conn failed! resetting...");
            anyhow::bail!("watchdog failed");
        } else {
            let ping = start.elapsed();
            let pipe = tunnel_mux.last_recv_pipe().context("no pipe")?;
            let item = StatItem {
                time: SystemTime::now(),
                endpoint: pipe.peer_addr().into(),
                protocol: pipe.protocol().into(),
                ping,
                send_bytes: STATS_SEND_BYTES.load(Ordering::Relaxed),
                recv_bytes: STATS_RECV_BYTES.load(Ordering::Relaxed),
            };
            STATS_GATHERER.push(item.clone());
            log::debug!("** watchdog completed in {:?} **", ping);
        }

        let timer = smol::Timer::after(Duration::from_secs(10));
        wait_activity(Duration::from_secs(600)).await;
        timer.await;
    }
}
