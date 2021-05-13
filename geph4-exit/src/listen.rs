use std::{
    net::SocketAddr,
    sync::{atomic::AtomicUsize, Arc},
    time::{Duration, Instant},
};

use crate::vpn;
use binder_transport::BinderClient;

use dashmap::DashMap;
use jemalloc_ctl::epoch;
use smol::{channel::Sender, prelude::*};

use sosistab::Session;
use x25519_dalek::StaticSecret;

mod control;
mod session;
/// the root context
pub struct RootCtx {
    pub stat_client: Arc<statsd::Client>,
    pub exit_hostname: String,
    binder_client: Arc<dyn BinderClient>,
    bridge_secret: String,
    signing_sk: ed25519_dalek::Keypair,
    sosistab_sk: x25519_dalek::StaticSecret,

    session_count: AtomicUsize,
    raw_session_count: AtomicUsize,
    pub conn_count: AtomicUsize,
    pub control_count: AtomicUsize,

    free_limit: u32,
    pub port_whitelist: bool,

    pub google_proxy: Option<SocketAddr>,
    // pub conn_tasks: Mutex<cached::SizedCache<u128, smol::Task<Option<()>>>>,
    pub sess_replacers: DashMap<[u8; 32], Sender<Session>>,
}

impl RootCtx {
    fn new_sess(self: &Arc<Self>, sess: sosistab::Session) -> SessCtx {
        SessCtx {
            root: self.clone(),
            sess,
        }
    }

    async fn listen_udp(
        &self,
        sk: Option<StaticSecret>,
        addr: SocketAddr,
        flow_key: &str,
    ) -> std::io::Result<sosistab::Listener> {
        let stat = self.stat_client.clone();
        let stat2 = self.stat_client.clone();
        let flow_key = flow_key.to_owned();
        let fk2 = flow_key.clone();
        let long_sk = if let Some(sk) = sk {
            sk
        } else {
            self.sosistab_sk.clone()
        };
        sosistab::Listener::listen_udp(
            addr,
            long_sk,
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
        .await
    }

    async fn listen_tcp(
        &self,
        sk: Option<StaticSecret>,
        addr: SocketAddr,
        flow_key: &str,
    ) -> std::io::Result<sosistab::Listener> {
        let stat = self.stat_client.clone();
        let stat2 = self.stat_client.clone();
        let flow_key = flow_key.to_owned();
        let fk2 = flow_key.clone();
        let long_sk = if let Some(sk) = sk {
            sk
        } else {
            self.sosistab_sk.clone()
        };
        sosistab::Listener::listen_tcp(
            addr,
            long_sk,
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
        .await
    }
}

async fn idlejitter(ctx: Arc<RootCtx>) {
    let key = format!("idlejitter.{}", ctx.exit_hostname.replace(".", "-"));
    const INTERVAL: Duration = Duration::from_millis(10);
    loop {
        let start = Instant::now();
        smol::Timer::after(INTERVAL).await;
        let elapsed = start.elapsed();
        if rand::random::<f32>() < 0.1 {
            ctx.stat_client.timer(&key, elapsed.as_secs_f64() * 1000.0);
        }
    }
}

/// per-session context
pub struct SessCtx {
    root: Arc<RootCtx>,
    sess: sosistab::Session,
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
        control_count: AtomicUsize::new(0),
        sess_replacers: Default::default(),
    });

    let _idlejitter = smolscale::spawn(idlejitter(ctx.clone()));

    let _vpn = smolscale::spawn(vpn::transparent_proxy_helper(ctx.clone()));

    // control protocol listener
    let control_prot_listen = smol::net::TcpListener::bind("[::0]:28080").await?;
    // future that governs the control protocol
    let control_prot_fut = async {
        loop {
            let ctx = ctx.clone();
            let (client, _) = control_prot_listen.accept().await?;
            smolscale::spawn(control::handle_control(ctx, client)).detach();
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
    let self_bridge_fut = async {
        let flow_key = bridge_pkt_key("SELF");
        let udp_listen = ctx
            .listen_udp(None, "[::0]:19831".parse().unwrap(), &flow_key)
            .await
            .unwrap();
        let tcp_listen = ctx
            .listen_tcp(None, "[::0]:19831".parse().unwrap(), &flow_key)
            .await
            .unwrap();
        log::debug!("sosis_listener initialized");
        loop {
            let sess = udp_listen
                .accept_session()
                .race(tcp_listen.accept_session())
                .await
                .expect("can't accept from sosistab");
            let ctx1 = ctx1.clone();
            smolscale::spawn(session::handle_session(ctx1.new_sess(sess))).detach();
        }
    };
    // future that uploads gauge statistics
    let stat_client = ctx.stat_client.clone();
    let gauge_fut = async {
        let key = format!("session_count.{}", exit_hostname.replace(".", "-"));
        let rskey = format!("raw_session_count.{}", exit_hostname.replace(".", "-"));
        let memkey = format!("bytes_allocated.{}", exit_hostname.replace(".", "-"));
        let connkey = format!("conn_count.{}", exit_hostname.replace(".", "-"));
        let ctrlkey = format!("control_count.{}", exit_hostname.replace(".", "-"));
        let taskkey = format!("task_count.{}", exit_hostname.replace(".", "-"));
        let runtaskkey = format!("run_task_count.{}", exit_hostname.replace(".", "-"));
        let e = epoch::mib().unwrap();
        // let allocated = jemalloc_ctl::stats::allocated::mib().unwrap();
        let resident = jemalloc_ctl::stats::allocated::mib().unwrap();
        loop {
            e.advance().unwrap();

            let session_count = ctx.session_count.load(std::sync::atomic::Ordering::Relaxed);
            stat_client.gauge(&key, session_count as f64);
            let raw_session_count = ctx
                .raw_session_count
                .load(std::sync::atomic::Ordering::Relaxed);
            stat_client.gauge(&rskey, raw_session_count as f64);
            let memory_usage = resident.read().unwrap();
            stat_client.gauge(&memkey, memory_usage as f64);
            let conn_count = ctx.conn_count.load(std::sync::atomic::Ordering::Relaxed);
            stat_client.gauge(&connkey, conn_count as f64);
            let control_count = ctx.control_count.load(std::sync::atomic::Ordering::Relaxed);
            stat_client.gauge(&ctrlkey, control_count as f64);
            let task_count = smolscale::active_task_count();
            stat_client.gauge(&taskkey, task_count as f64);
            let running_count = smolscale::running_task_count();
            stat_client.gauge(&runtaskkey, running_count as f64);
            smol::Timer::after(Duration::from_secs(10)).await;
        }
    };
    // race
    smol::future::race(control_prot_fut, self_bridge_fut)
        .or(gauge_fut)
        .await
}
