use std::{sync::Arc, time::Duration};

use clone_macro::clone;
use futures_util::{future::select_all, FutureExt, TryFutureExt};

use itertools::Itertools;

use smol::prelude::*;
use smolscale::immortal::{Immortal, RespawnStrategy};

use crate::{config::ConnectOpt, connect::tunnel::ClientTunnel};

use crate::debugpack::DebugPack;
mod dns;

mod port_forwarder;
mod socks5;

mod stats;
mod tunnel;
mod vpn;

pub struct ConnectDaemon {
    ctx: ConnectContext,
    _task: Immortal,
}

impl ConnectDaemon {
    /// Starts a new ConnectClient. If initialization fails, returns an error.
    pub async fn start(opt: ConnectOpt) -> anyhow::Result<Self> {
        log::info!(
            "connect mode starting: exit = {:?}, force_protocol = {:?}, use_bridges = {}",
            opt.exit_server,
            opt.force_protocol,
            opt.use_bridges
        );

        let tunnel = ClientTunnel::new(opt.clone()).into();
        let ctx = ConnectContext {
            tunnel,
            opt: opt.clone(),
            debug: Arc::new(DebugPack::new(&opt.common.debugpack_path)?),
        };
        Ok(Self {
            ctx: ctx.clone(),
            _task: Immortal::respawn(
                RespawnStrategy::JitterDelay(Duration::from_secs(1), Duration::from_secs(5)),
                clone!([ctx], move || connect_loop(ctx.clone())
                    .map_err(|e| log::error!("connect_loop restart: {:?}", e))),
            ),
        })
    }

    /// Gets a handle to the debug pack from the outside.
    pub fn debug(&self) -> &DebugPack {
        &self.ctx.debug
    }
}

#[derive(Clone)]
pub struct ConnectContext {
    opt: ConnectOpt,

    tunnel: Arc<ClientTunnel>,
    debug: Arc<DebugPack>,
}

async fn connect_loop(ctx: ConnectContext) -> anyhow::Result<()> {
    let socks2http = smolscale::spawn(crate::socks2http::run_tokio(ctx.opt.http_listen, {
        let mut addr = ctx.opt.socks5_listen;
        addr.set_ip("127.0.0.1".parse().unwrap());
        addr
    }));

    let socks5 = smolscale::spawn(socks5::socks5_loop(ctx.clone()));

    let dns = smolscale::spawn(dns::dns_loop(ctx.clone(), ctx.opt.dns_listen));

    let forward_ports = ctx
        .opt
        .forward_ports
        .iter()
        .map(|v| smolscale::spawn(port_forwarder::port_forwarder(ctx.clone(), v.clone())))
        .chain(std::iter::once(smolscale::spawn(smol::future::pending()))) // ensures there's at least one
        .collect_vec();

    let vpn = smolscale::spawn(vpn::vpn_loop(ctx.clone()));

    let stats = smolscale::spawn(stats::serve_stats_loop(ctx.clone()));

    socks2http
        .race(socks5)
        .race(dns)
        .race(select_all(forward_ports).map(|s| s.0))
        .race(vpn)
        .race(stats)
        .await?;
    anyhow::bail!("somehow ran off the edge of a cliff")
}
