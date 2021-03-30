use crate::{
    cache::ClientCache, plots::stat_derive, stats::StatCollector, tunman::TunnelManager, AuthOpt,
    CommonOpt,
};
use crate::{china, stats::GLOBAL_LOGGER};
use anyhow::Context;
use async_compat::Compat;
use chrono::prelude::*;
use smol_timeout::TimeoutExt;
use std::{
    net::Ipv4Addr,
    net::SocketAddr,
    net::SocketAddrV4,
    sync::Arc,
    time::{Duration, Instant},
};
use structopt::StructOpt;

#[derive(Debug, StructOpt, Clone)]
pub struct ConnectOpt {
    #[structopt(flatten)]
    common: CommonOpt,

    #[structopt(flatten)]
    auth: AuthOpt,

    #[structopt(long)]
    /// Whether or not to use bridges
    pub use_bridges: bool,

    #[structopt(long, default_value = "127.0.0.1:9910")]
    /// Where to listen for HTTP proxy connections
    http_listen: SocketAddr,
    #[structopt(long, default_value = "127.0.0.1:9909")]
    /// Where to listen for SOCKS5 connections
    socks5_listen: SocketAddr,
    #[structopt(long, default_value = "127.0.0.1:9809")]
    /// Where to listen for REST-based local connections
    stats_listen: SocketAddr,

    #[structopt(long)]
    /// Where to listen for proxied DNS requests. Optional.
    dns_listen: Option<SocketAddr>,

    #[structopt(long, default_value = "us-hio-01.exits.geph.io")]
    /// Which exit server to connect to. If there isn't an exact match, the exit server with the most similar hostname is picked.
    pub exit_server: String,

    #[structopt(long)]
    /// Whether or not to exclude PRC domains
    exclude_prc: bool,

    #[structopt(long)]
    /// Whether or not to wait for VPN commands on stdio
    pub stdio_vpn: bool,

    #[structopt(long)]
    /// An endpoint to send test results. If set, will periodically do network testing.
    nettest_server: Option<SocketAddr>,

    #[structopt(long)]
    /// A name for this test instance.
    nettest_name: Option<String>,

    #[structopt(long)]
    /// Whether or not to force TCP mode.
    pub use_tcp: bool,

    #[structopt(long)]
    /// SSH-style local-remote port forwarding. For example, "0.0.0.0:8888:::example.com:22" will forward local port 8888 to example.com:22. Must be in form host:port:::host:port! May have multiple ones.
    forward_ports: Vec<String>,
}

/// Main function for `connect` subcommand
pub async fn main_connect(opt: ConnectOpt) -> anyhow::Result<()> {
    log::info!("connect mode started");

    // Start socks to http
    let _socks2h = smolscale::spawn(Compat::new(socks2http::run_tokio(opt.http_listen, {
        let mut addr = opt.socks5_listen;
        addr.set_ip("127.0.0.1".parse().unwrap());
        addr
    })));

    let stat_collector = Arc::new(StatCollector::default());
    // Create a database directory if doesn't exist
    let client_cache =
        ClientCache::from_opts(&opt.common, &opt.auth).context("cannot create ClientCache")?;
    // Create a tunnel_manager
    let tunnel_manager =
        TunnelManager::new(stat_collector.clone(), opt.clone(), Arc::new(client_cache));
    // Start port forwarders
    let _port_forwarders: Vec<_> = opt
        .forward_ports
        .iter()
        .map(|v| smolscale::spawn(port_forwarder(tunnel_manager.clone(), v.clone())))
        .collect();

    if let Some(dns_listen) = opt.dns_listen {
        log::debug!("starting dns...");
        smolscale::spawn(crate::dns::dns_loop(dns_listen, tunnel_manager.clone())).detach();
    }
    if let Some(nettest_server) = opt.nettest_server {
        log::info!("Network testing enabled at {}!", nettest_server);
        smolscale::spawn(crate::nettest::nettest(
            opt.nettest_name.unwrap(),
            nettest_server,
        ))
        .detach();
    }

    // Enter the stats loop
    let stat_listener = smol::net::TcpListener::bind(opt.stats_listen)
        .await
        .context("cannot bind stats")?;
    let scollect = stat_collector.clone();

    let _stat: smol::Task<anyhow::Result<()>> = {
        let tunnel_manager = tunnel_manager.clone();
        smolscale::spawn(async move {
            loop {
                let (stat_client, _) = stat_listener.accept().await?;
                let scollect = scollect.clone();
                let tunnel_manager = tunnel_manager.clone();
                smolscale::spawn(async move {
                    drop(
                        async_h1::accept(stat_client, |req| {
                            handle_stats(scollect.clone(), &tunnel_manager, req)
                        })
                        .await,
                    );
                })
                .detach();
            }
        })
    };

    // Enter the socks5 loop
    let socks5_listener = smol::net::TcpListener::bind(opt.socks5_listen)
        .await
        .context("cannot bind socks5")?;

    let exclude_prc = opt.exclude_prc;

    loop {
        let (s5client, _) = socks5_listener
            .accept()
            .await
            .context("cannot accept socks5")?;
        let tunnel_manager = tunnel_manager.clone();
        let stat_collector = stat_collector.clone();
        smolscale::spawn(async move {
            handle_socks5(stat_collector, s5client, &tunnel_manager, exclude_prc).await
        })
        .detach()
    }
}

async fn port_forwarder(tunnel_manager: TunnelManager, desc: String) {
    let exploded = desc.split(":::").collect::<Vec<_>>();
    let listen_addr: SocketAddr = exploded[0].parse().expect("invalid port forwarding syntax");
    let listener = smol::net::TcpListener::bind(listen_addr)
        .await
        .expect("could not listen for port forwarding");
    loop {
        let (conn, _) = listener.accept().await.unwrap();
        let tunnel_manager = tunnel_manager.clone();
        let remote_addr = exploded[1].to_owned();
        smolscale::spawn(async move {
            let remote = tunnel_manager.connect(&remote_addr).await.ok()?;
            smol::future::race(
                smol::io::copy(remote.clone(), conn.clone()),
                smol::io::copy(conn, remote),
            )
            .await
            .ok()
        })
        .detach();
    }
}

use std::io::prelude::*;

/// Handles requests for the debug pack, proxy information, program termination, and general statistics
async fn handle_stats(
    stats: Arc<StatCollector>,
    tunnel_manager: &TunnelManager,
    _req: http_types::Request,
) -> http_types::Result<http_types::Response> {
    let mut res = http_types::Response::new(http_types::StatusCode::Ok);
    match _req.url().path() {
        "/debugpack" => {
            // Form a tar from the logs and sosistab trace
            let tar_buffer = Vec::new();
            let mut tar_build = tar::Builder::new(tar_buffer);
            let mut logs_buffer = Vec::new();
            {
                let logs = GLOBAL_LOGGER.read();
                for line in logs.iter() {
                    writeln!(logs_buffer, "{}", line)?;
                }
            }
            // Obtain sosistab trace
            let detail = tunnel_manager
                .get_stats()
                .timeout(Duration::from_secs(1))
                .await;
            if let Some(detail) = detail {
                let detail = detail?;
                let mut sosistab_buf = Vec::new();
                writeln!(sosistab_buf, "time,last_recv,total_recv,total_loss,ping")?;
                if let Some(first) = detail.get(0) {
                    let first_time = first.time;
                    for item in detail.iter() {
                        writeln!(
                            sosistab_buf,
                            "{},{},{},{},{}",
                            item.time
                                .duration_since(first_time)
                                .unwrap_or_default()
                                .as_secs_f64(),
                            item.high_recv,
                            item.total_recv,
                            item.total_loss,
                            item.smooth_ping,
                        )?;
                    }
                }
                let mut sosis_header = tar::Header::new_gnu();
                sosis_header.set_mode(0o666);
                sosis_header.set_size(sosistab_buf.len() as u64);
                tar_build.append_data(
                    &mut sosis_header,
                    "sosistab-trace.csv",
                    sosistab_buf.as_slice(),
                )?;
            }
            let mut logs_header = tar::Header::new_gnu();
            logs_header.set_mode(0o666);
            logs_header.set_size(logs_buffer.len() as u64);
            tar_build.append_data(&mut logs_header, "logs.txt", logs_buffer.as_slice())?;
            let result = tar_build.into_inner()?;
            res.insert_header("content-type", "application/tar");
            res.insert_header(
                "content-disposition",
                format!(
                    "attachment; filename=\"geph4-debug-{}.tar\"",
                    Local::now().to_rfc3339()
                ),
            );
            res.set_body(result);
            Ok(res)
        }
        "/proxy.pac" => {
            // Serves a Proxy Auto-Configuration file
            res.set_body("function FindProxyForURL(url, host){return 'PROXY 127.0.0.1:9910';}");
            Ok(res)
        }
        "/rawstats" => {
            // Serves all the stats as json
            let detail = tunnel_manager.get_stats().await?;
            res.set_body(serde_json::to_string(&detail)?);
            res.set_content_type(http_types::mime::JSON);
            Ok(res)
        }
        "/deltastats" => {
            // Serves all the delta stats as json
            let detail = tunnel_manager.get_stats().await?;
            let body_str = smol::unblock(move || {
                let detail = stat_derive(&detail);
                serde_json::to_string(&detail)
            })
            .await?;
            res.set_body(body_str);
            res.set_content_type(http_types::mime::JSON);
            Ok(res)
        }
        "/kill" => std::process::exit(0),
        _ => {
            // Serves general statistics
            let detail = tunnel_manager
                .get_stats()
                .timeout(Duration::from_millis(100))
                .await;
            if let Some(Ok(details)) = detail {
                if let Some(detail) = details.last() {
                    stats.set_latency(detail.smooth_ping);
                    // Compute loss
                    let midpoint_stat = details[details.len() / 2];
                    let delta_high = detail
                        .high_recv
                        .saturating_sub(midpoint_stat.high_recv)
                        .max(1) as f64;
                    let delta_total = detail
                        .total_recv
                        .saturating_sub(midpoint_stat.total_recv)
                        .max(1) as f64;
                    let loss = 1.0 - (delta_total / delta_high).min(1.0).max(0.0);
                    stats.set_loss(loss * 100.0)
                }
            }
            let jstats = serde_json::to_string(&stats)?;
            res.set_body(jstats);
            res.set_content_type(http_types::mime::JSON);
            Ok(res)
        }
    }
}

/// Handles a socks5 client from localhost
async fn handle_socks5(
    stats: Arc<StatCollector>,
    s5client: smol::net::TcpStream,
    tunnel_manager: &TunnelManager,
    exclude_prc: bool,
) -> anyhow::Result<()> {
    s5client.set_nodelay(true)?;
    use socksv5::v5::*;
    let _handshake = read_handshake(s5client.clone()).await?;
    write_auth_method(s5client.clone(), SocksV5AuthMethod::Noauth).await?;
    let request = read_request(s5client.clone()).await?;
    let port = request.port;
    let v4addr: Option<Ipv4Addr>;
    let addr: String = match &request.host {
        SocksV5Host::Domain(dom) => {
            v4addr = String::from_utf8_lossy(&dom).parse().ok();
            format!("{}:{}", String::from_utf8_lossy(&dom), request.port)
        }
        SocksV5Host::Ipv4(v4) => SocketAddr::V4(SocketAddrV4::new(
            {
                v4addr = Some(Ipv4Addr::new(v4[0], v4[1], v4[2], v4[3]));
                v4addr.unwrap()
            },
            request.port,
        ))
        .to_string(),
        _ => anyhow::bail!("not supported"),
    };
    write_request_status(
        s5client.clone(),
        SocksV5RequestStatus::Success,
        request.host,
        port,
    )
    .await?;
    let must_direct = exclude_prc
        && (china::is_chinese_host(addr.split(':').next().unwrap())
            || v4addr.map(china::is_chinese_ip).unwrap_or(false));
    if must_direct {
        log::debug!("bypassing {}", addr);
        let conn = smol::net::TcpStream::connect(&addr).await?;
        smol::future::race(
            aioutils::copy_with_stats(conn.clone(), s5client.clone(), |_| ()),
            aioutils::copy_with_stats(s5client.clone(), conn.clone(), |_| ()),
        )
        .await?;
    } else {
        let conn = tunnel_manager.connect(&addr).await?;
        smol::future::race(
            aioutils::copy_with_stats(conn.clone(), s5client.clone(), |n| {
                stats.incr_total_rx(n as u64)
            }),
            aioutils::copy_with_stats(s5client, conn, |n| stats.incr_total_tx(n as u64)),
        )
        .await?;
    }
    Ok(())
}
