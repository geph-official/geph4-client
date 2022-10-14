use std::{convert::Infallible, ops::Deref, sync::Arc, time::Duration};

use async_compat::Compat;

use china::test_china;
use futures_util::future::select_all;
use geph4_protocol::{
    self,
    binder::client::CachedBinderClient,
    tunnel::{
        activity::wait_activity, BinderTunnelParams, ClientTunnel, ConnectionOptions,
        EndpointSource, TunnelStatus,
    },
};

use once_cell::sync::Lazy;

use parking_lot::RwLock;
use smol::{prelude::*, Task};

use crate::config::{get_cached_binder_client, ConnectOpt, Opt, CONFIG};

use crate::china;

mod dns;
mod port_forwarder;
mod socks5;
mod stats;
pub(crate) mod vpn;

/// Main function for `connect` subcommand
pub fn start_main_connect() {
    Lazy::force(&CONNECT_TASK);
}

/// The configured binder client
static CACHED_BINDER_CLIENT: Lazy<Arc<CachedBinderClient>> = Lazy::new(|| {
    Arc::new({
        let (common, auth) = match CONFIG.deref() {
            Opt::Connect(c) => (&c.common, &c.auth),
            _ => panic!(),
        };
        get_cached_binder_client(common, auth).unwrap()
    })
});

static CONNECT_CONFIG: Lazy<ConnectOpt> = Lazy::new(|| match CONFIG.deref() {
    Opt::Connect(c) => c.clone(),
    _ => panic!(),
});

static SHOULD_USE_BRIDGES: Lazy<bool> = Lazy::new(|| {
    smol::future::block_on(async {
        // Test china
        let is_china = test_china().await;
        match is_china {
            Err(e) => {
                log::warn!(
                    "could not tell whether or not we're in China ({}), so assuming that we are!",
                    e
                );
                true
            }
            Ok(true) => {
                log::info!("we are in CHINA :O");
                true
            }
            _ => {
                log::info!("not in China :)");
                CONNECT_CONFIG.use_bridges
            }
        }
    })
});

type StatusCallback = Box<dyn Fn(TunnelStatus) + Send + Sync + 'static>;
static TUNNEL_STATUS_CALLBACK: Lazy<RwLock<StatusCallback>> = Lazy::new(|| {
    RwLock::new(Box::new(|addr| {
        log::debug!("tunnel reported {:?} to dummy", addr);
    }))
});

static TUNNEL: Lazy<ClientTunnel> = Lazy::new(|| {
    let endpoint = {
        if let Some(override_url) = CONNECT_CONFIG.override_connect.clone() {
            EndpointSource::Independent {
                endpoint: override_url,
            }
        } else {
            EndpointSource::Binder(BinderTunnelParams {
                ccache: CACHED_BINDER_CLIENT.clone(),
                exit_server: CONNECT_CONFIG.exit_server.clone(),
                use_bridges: *SHOULD_USE_BRIDGES,
                force_bridge: CONNECT_CONFIG.force_bridge,
            })
        }
    };
    log::debug!("gonna construct the tunnel");
    ClientTunnel::new(
        ConnectionOptions {
            udp_shard_count: CONNECT_CONFIG.udp_shard_count,
            udp_shard_lifetime: CONNECT_CONFIG.udp_shard_lifetime,
            tcp_shard_count: CONNECT_CONFIG.tcp_shard_count,
            tcp_shard_lifetime: CONNECT_CONFIG.tcp_shard_lifetime,
            use_tcp: CONNECT_CONFIG.use_tcp,
        },
        endpoint,
        |status| TUNNEL_STATUS_CALLBACK.read()(status),
    )
});

static CONNECT_TASK: Lazy<Task<Infallible>> = Lazy::new(|| {
    /// Prints stats in a loop.
    async fn print_stats_loop() {
        loop {
            wait_activity(Duration::from_secs(200)).await;
            let stats = TUNNEL.get_stats().await;
            log::info!("** recv_loss = {:.2}% **", stats.last_loss * 100.0);
            smol::Timer::after(Duration::from_secs(30)).await;
        }
    }

    smolscale::spawn(async {
        // print out config file
        log::info!(
            "connect mode starting: exit = {:?}, use_tcp = {}, use_bridges = {}",
            CONNECT_CONFIG.exit_server,
            CONNECT_CONFIG.use_tcp,
            CONNECT_CONFIG.use_bridges
        );
        let stats_printer_fut = async {
            print_stats_loop().await;
            Ok(())
        };
        // http proxy
        let _socks2h = smolscale::spawn(Compat::new(crate::socks2http::run_tokio(
            CONNECT_CONFIG.http_listen,
            {
                let mut addr = CONNECT_CONFIG.socks5_listen;
                addr.set_ip("127.0.0.1".parse().unwrap());
                addr
            },
        )));

        // socks5 proxy
        let socks5_fut = smolscale::spawn(socks5::socks5_loop(
            CONNECT_CONFIG.socks5_listen,
            CONNECT_CONFIG.exclude_prc,
        ));
        // dns
        let dns_fut = if let Some(dns_listen) = CONNECT_CONFIG.dns_listen {
            log::debug!("starting dns...");
            smolscale::spawn(dns::dns_loop(dns_listen))
        } else {
            smolscale::spawn(smol::future::pending())
        };

        // port forwarders
        let port_forwarders: Vec<_> = CONNECT_CONFIG
            .forward_ports
            .iter()
            .map(|v| smolscale::spawn(port_forwarder::port_forwarder(v.clone())))
            .collect();
        if !port_forwarders.is_empty() {
            smolscale::spawn(select_all(port_forwarders)).await;
        }

        Lazy::force(&stats::STATS_THREAD);

        // ready, set, go!
        Lazy::force(&vpn::VPN_SHUFFLE_TASK);
        stats_printer_fut
            .race(socks5_fut)
            .race(dns_fut)
            .await
            .unwrap();
        panic!("something died")
    })
});
