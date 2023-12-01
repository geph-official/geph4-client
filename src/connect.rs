use std::{sync::Arc, time::Duration};

use anyhow::Context;


use clone_macro::clone;
use futures_util::{future::select_all, FutureExt};

use itertools::Itertools;
use once_cell::sync::Lazy;

use parking_lot::RwLock;
use rand::Rng;
use smol::prelude::*;


use crate::{
    config::{get_conninfo_store, ConnectOpt},
    connect::tunnel::{BinderTunnelParams, ClientTunnel, EndpointSource, TunnelStatus},
    conninfo_store::ConnInfoStore,
};



mod dns;

mod port_forwarder;
mod socks5;

mod tunnel;

#[derive(Clone)]
pub struct ConnectContext {
    opt: ConnectOpt,
    conn_info: Arc<ConnInfoStore>,
    tunnel: Arc<ClientTunnel>,
}

static METRIC_SESSION_ID: Lazy<i64> = Lazy::new(|| {
    let mut rng = rand::thread_rng();
    rng.gen()
});

type StatusCallback = Box<dyn Fn(TunnelStatus) + Send + Sync + 'static>;
static TUNNEL_STATUS_CALLBACK: Lazy<RwLock<StatusCallback>> = Lazy::new(|| {
    RwLock::new(Box::new(|addr| {
        log::debug!("tunnel reported {:?} to dummy", addr);
    }))
});

pub async fn connect_loop(opt: ConnectOpt) -> anyhow::Result<()> {
    log::info!(
        "connect mode starting: exit = {:?}, force_protocol = {:?}, use_bridges = {}",
        opt.exit_server,
        opt.force_protocol,
        opt.use_bridges
    );

    let conn_info = Arc::new(
        get_conninfo_store(
            &opt.common,
            &opt.auth,
            opt.exit_server
                .as_ref()
                .context("no exit server provided")?,
        )
        .await?,
    );

    let endpoint = {
        if let Some(override_url) = opt.override_connect.clone() {
            EndpointSource::Independent {
                endpoint: override_url,
            }
        } else {
            EndpointSource::Binder(
                conn_info.clone(),
                BinderTunnelParams {
                    exit_server: opt.exit_server.clone(),
                    use_bridges: opt.use_bridges,
                    force_bridge: opt.force_bridge,
                    force_protocol: opt.force_protocol.clone(),
                },
            )
        }
    };

    let tunnel = ClientTunnel::new(endpoint, |_| {}).into();
    let ctx = ConnectContext {
        conn_info,
        tunnel,
        opt: opt.clone(),
    };

    let socks2http = smolscale::spawn(crate::socks2http::run_tokio(opt.http_listen, {
        let mut addr = opt.socks5_listen;
        addr.set_ip("127.0.0.1".parse().unwrap());
        addr
    }));

    let socks5 = smolscale::spawn(socks5::socks5_loop(ctx.clone()));

    let dns = smolscale::spawn(dns::dns_loop(ctx.clone(), opt.dns_listen));

    let forward_ports = opt
        .forward_ports
        .iter()
        .map(|v| smolscale::spawn(port_forwarder::port_forwarder(ctx.clone(), v.clone())))
        .collect_vec();

    let refresh = smolscale::spawn(clone!([ctx, opt], async move {
        if opt.override_connect.is_none() {
            loop {
                log::debug!("about to refresh...");
                if let Err(err) = ctx.conn_info.refresh().await {
                    log::warn!("error refreshing store: {:?}", err);
                }
                smol::Timer::after(Duration::from_secs(120)).await;
            }
        } else {
            smol::future::pending().await
        }
    }));

    socks2http
        .race(socks5)
        .race(dns)
        .race(refresh)
        .race(select_all(forward_ports).map(|s| s.0))
        .await
}
