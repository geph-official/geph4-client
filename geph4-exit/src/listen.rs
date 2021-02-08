use std::{
    net::SocketAddr,
    sync::{atomic::AtomicUsize, Arc},
    time::Duration,
};

use crate::ALLOCATOR;
use binder_transport::BinderClient;
use smol::prelude::*;
use smolscale::OnError;

mod control;
mod session;
/// the root context
pub struct RootCtx {
    stat_client: Arc<statsd::Client>,
    exit_hostname: String,
    binder_client: Arc<dyn BinderClient>,
    bridge_secret: String,
    signing_sk: ed25519_dalek::Keypair,
    sosistab_sk: x25519_dalek::StaticSecret,

    session_count: AtomicUsize,
    raw_session_count: AtomicUsize,
    conn_count: AtomicUsize,

    free_limit: u32,
    port_whitelist: bool,

    google_proxy: Option<SocketAddr>,

    nursery: smolscale::NurseryHandle,
}

impl RootCtx {
    fn new_sess(self: &Arc<Self>, sess: sosistab::Session) -> SessCtx {
        let new_nurs = smolscale::Nursery::new();
        let new_hand = new_nurs.handle();
        self.nursery.spawn(OnError::Ignore, |_| new_nurs.wait());
        SessCtx {
            root: self.clone(),
            sess,
            nursery: new_hand,
        }
    }
}

/// per-session context
pub struct SessCtx {
    root: Arc<RootCtx>,
    sess: sosistab::Session,

    nursery: smolscale::NurseryHandle,
}

/// the main listening loop
#[allow(clippy::clippy::too_many_arguments)]
pub async fn main_loop<'a>(
    stat_client: statsd::Client,
    exit_hostname: &'a str,
    binder_client: Arc<dyn BinderClient>,
    bridge_secret: &'a str,
    signing_sk: ed25519_dalek::Keypair,
    sosistab_sk: x25519_dalek::StaticSecret,
    free_limit: u32,
    google_proxy: Option<SocketAddr>,
    port_whitelist: bool,
) -> anyhow::Result<()> {
    let nursery = smolscale::Nursery::new();
    let ctx = Arc::new(RootCtx {
        stat_client: Arc::new(stat_client),
        exit_hostname: exit_hostname.to_string(),
        binder_client,
        bridge_secret: bridge_secret.to_string(),
        signing_sk,
        sosistab_sk,
        session_count: AtomicUsize::new(0),
        raw_session_count: AtomicUsize::new(0),
        conn_count: AtomicUsize::new(0),
        free_limit,
        port_whitelist,
        google_proxy,
        nursery: nursery.handle(),
    });

    // control protocol listener
    let control_prot_listen = smol::net::TcpListener::bind("[::0]:28080").await?;
    // future that governs the control protocol
    let control_prot_fut = async {
        loop {
            let ctx = ctx.clone();
            let sp = ctx.nursery.clone();
            let (client, _) = control_prot_listen.accept().await?;
            let claddr = client.peer_addr()?;
            sp.spawn(
                OnError::ignore_with(move |e| {
                    log::warn!("control protocol for {} died with {:?}", claddr, e)
                }),
                |_| control::handle_control(ctx, client),
            );
        }
    };
    let exit_hostname2 = exit_hostname.to_string();
    let bridge_pkt_key = move |bridge_group: &str| {
        format!(
            "raw_flow.{}.{}",
            exit_hostname2.replace(".", "-"),
            bridge_group.replace(".", "-")
        )
    };
    // future that governs the "self bridge"
    let ctx1 = ctx.clone();
    let stat = ctx1.stat_client.clone();
    let self_bridge_fut = async {
        let flow_key = bridge_pkt_key("SELF");
        let stat2 = stat.clone();
        let fk2 = flow_key.clone();
        let sosis_listener = sosistab::Listener::listen(
            "[::0]:19831",
            ctx1.sosistab_sk.clone(),
            move |len, _| {
                if fastrand::f32() < 0.05 {
                    stat.count(&flow_key, len as f64 * 20.0)
                }
            },
            move |len, _| {
                if fastrand::f32() < 0.05 {
                    stat2.count(&fk2, len as f64 * 20.0)
                }
            },
        )
        .await;
        log::debug!("sosis_listener initialized");
        loop {
            let sess = sosis_listener
                .accept_session()
                .await
                .ok_or_else(|| anyhow::anyhow!("can't accept from sosistab"))?;
            let ctx1 = ctx1.clone();
            let sp = ctx1.nursery.clone();
            sp.spawn(OnError::Ignore, move |_| {
                session::handle_session(ctx1.new_sess(sess))
            });
        }
    };
    // future that uploads gauge statistics
    let stat_client = ctx.stat_client.clone();
    let gauge_fut = async {
        let key = format!("session_count.{}", exit_hostname.replace(".", "-"));
        let rskey = format!("raw_session_count.{}", exit_hostname.replace(".", "-"));
        let memkey = format!("bytes_allocated.{}", exit_hostname.replace(".", "-"));
        let connkey = format!("conn_count.{}", exit_hostname.replace(".", "-"));
        loop {
            let session_count = ctx.session_count.load(std::sync::atomic::Ordering::Relaxed);
            stat_client.gauge(&key, session_count as f64);
            let raw_session_count = ctx
                .raw_session_count
                .load(std::sync::atomic::Ordering::Relaxed);
            stat_client.gauge(&rskey, raw_session_count as f64);
            let memory_usage = ALLOCATOR.allocated();
            stat_client.gauge(&memkey, memory_usage as f64);
            let conn_count = ctx.conn_count.load(std::sync::atomic::Ordering::Relaxed);
            stat_client.gauge(&connkey, conn_count as f64);
            smol::Timer::after(Duration::from_secs(5)).await;
        }
    };
    // race
    smol::future::race(control_prot_fut, self_bridge_fut)
        .or(gauge_fut)
        .or(nursery.wait())
        .await
}
