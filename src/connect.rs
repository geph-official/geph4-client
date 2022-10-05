use std::{convert::Infallible, net::Ipv4Addr, net::SocketAddr, ops::Deref, time::Duration};

use anyhow::Context;
use async_compat::Compat;

use async_net::SocketAddrV4;
use china::test_china;
use futures_util::future::select_all;
use geph4_protocol::{
    self,
    tunnel::{
        activity::wait_activity, BinderTunnelParams, ClientTunnel, ConnectionOptions,
        EndpointSource,
    },
};

use once_cell::sync::Lazy;

use psl::Psl;

use smol::{prelude::*, Task};
use smol_timeout::TimeoutExt;

use crate::config::{ConnectOpt, Opt, CACHED_BINDER_CLIENT, CONFIG};

use crate::china;

mod dns;
mod port_forwarder;
pub(crate) mod vpn;

/// Main function for `connect` subcommand
pub fn start_main_connect() {
    Lazy::force(&CONNECT_TASK);
}

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
        let socks5_fut = socks5_loop(CONNECT_CONFIG.socks5_listen, CONNECT_CONFIG.exclude_prc);
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

        // ready, set, go!
        stats_printer_fut
            .race(socks5_fut)
            .race(dns_fut)
            .await
            .unwrap();
        panic!("something died")
    })
});

/// Handles a socks5 client from localhost
async fn handle_socks5(s5client: smol::net::TcpStream, exclude_prc: bool) -> anyhow::Result<()> {
    s5client.set_nodelay(true)?;
    use socksv5::v5::*;
    let _handshake = read_handshake(s5client.clone()).await?;
    write_auth_method(s5client.clone(), SocksV5AuthMethod::Noauth).await?;
    let request = read_request(s5client.clone()).await?;
    let port = request.port;
    let v4addr: Option<Ipv4Addr>;
    let addr: String = match &request.host {
        SocksV5Host::Domain(dom) => {
            v4addr = String::from_utf8_lossy(dom).parse().ok();
            format!("{}:{}", String::from_utf8_lossy(dom), request.port)
        }
        SocksV5Host::Ipv4(v4) => {
            let v4addr_inner = Ipv4Addr::new(v4[0], v4[1], v4[2], v4[3]);
            SocketAddr::V4(SocketAddrV4::new(
                {
                    v4addr = Some(v4addr_inner);
                    v4addr.unwrap()
                },
                request.port,
            ))
            .to_string()
        }
        _ => anyhow::bail!("not supported"),
    };

    let is_private = if let Some(v4addr) = v4addr {
        v4addr.is_private() || v4addr.is_loopback()
    } else {
        !psl::List
            .suffix(addr.split(':').next().unwrap().as_bytes())
            .map(|suf| suf.typ().is_some())
            .unwrap_or_default()
    };

    // true if the connection should not go through geph
    let must_direct = is_private
        || (exclude_prc
            && (china::is_chinese_host(addr.split(':').next().unwrap())
                || v4addr.map(china::is_chinese_ip).unwrap_or(false)));
    if must_direct {
        log::debug!("bypassing {}", addr);
        let conn = smol::net::TcpStream::connect(&addr).await?;
        write_request_status(
            s5client.clone(),
            SocksV5RequestStatus::Success,
            request.host,
            port,
        )
        .await?;
        smol::future::race(
            geph4_aioutils::copy_with_stats(conn.clone(), s5client.clone(), |_| ()),
            geph4_aioutils::copy_with_stats(s5client.clone(), conn.clone(), |_| ()),
        )
        .await?;
    } else {
        log::debug!("gonna use the tunnel now");
        let conn = TUNNEL
            .connect(&addr)
            .timeout(Duration::from_secs(10))
            .await
            .context("open connection timeout")??;
        write_request_status(
            s5client.clone(),
            SocksV5RequestStatus::Success,
            request.host,
            port,
        )
        .await?;
        smol::future::race(
            geph4_aioutils::copy_with_stats(conn.clone(), s5client.clone(), |_| {}),
            geph4_aioutils::copy_with_stats(s5client, conn, |_| {}),
        )
        .await?;
    }
    Ok(())
}

async fn socks5_loop(socks5_listen: SocketAddr, exclude_prc: bool) -> anyhow::Result<()> {
    let socks5_listener = smol::net::TcpListener::bind(socks5_listen)
        .await
        .context("cannot bind socks5")?;
    log::debug!("socks5 started");
    loop {
        let (s5client, _) = socks5_listener
            .accept()
            .await
            .context("cannot accept socks5")?;

        smolscale::spawn(async move { handle_socks5(s5client, exclude_prc).await }).detach()
    }
}
