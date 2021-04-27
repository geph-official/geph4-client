use crate::{
    activity::{notify_activity, wait_activity},
    cache::ClientCache,
    stats::{global_sosistab_stats, GLOBAL_LOGGER},
    tunman::TunnelManager,
    AuthOpt, CommonOpt,
};
use crate::{china, plots::stat_derive};
use anyhow::Context;
use async_compat::Compat;
use async_net::IpAddr;
use china::is_chinese_ip;
use smol::prelude::*;
use smol_timeout::TimeoutExt;
use std::{
    collections::BTreeMap, net::Ipv4Addr, net::SocketAddr, net::SocketAddrV4, path::PathBuf,
    sync::Arc, time::Duration,
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

    #[structopt(long)]
    /// Where to store a log file.
    log_file: Option<PathBuf>,
}

/// Main function for `connect` subcommand
pub async fn main_connect(mut opt: ConnectOpt) -> anyhow::Result<()> {
    // Register the logger first
    let _logger = if let Some(log_file) = &opt.log_file {
        let log_file = smol::fs::File::create(log_file)
            .await
            .context("cannot create log file")?;
        Some(smolscale::spawn(run_logger(log_file)))
    } else {
        None
    };

    log::info!("connect mode started");

    let _stats = smolscale::spawn(print_stats_loop());

    // Test china
    let is_china = test_china().await;
    match is_china {
        Err(e) => {
            log::warn!(
                "could not tell whether or not we're in China ({}), so assuming that we are!",
                e
            );
            opt.use_bridges = true;
        }
        Ok(true) => {
            log::info!("we are in CHINA :O");
            opt.use_bridges = true;
        }
        _ => {
            log::info!("not in China :)")
        }
    }

    // Start socks to http
    let _socks2h = smolscale::spawn(Compat::new(socks2http::run_tokio(opt.http_listen, {
        let mut addr = opt.socks5_listen;
        addr.set_ip("127.0.0.1".parse().unwrap());
        addr
    })));

    // Create a database directory if doesn't exist
    let client_cache =
        ClientCache::from_opts(&opt.common, &opt.auth).context("cannot create ClientCache")?;
    // Create a tunnel_manager
    let tunnel_manager = TunnelManager::new(opt.clone(), Arc::new(client_cache));
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
    let _stat: smol::Task<anyhow::Result<()>> = {
        smolscale::spawn(async move {
            loop {
                let (stat_client, _) = stat_listener.accept().await?;
                smolscale::spawn(async move {
                    drop(async_h1::accept(stat_client, handle_stats).await);
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
        smolscale::spawn(async move { handle_socks5(s5client, &tunnel_manager, exclude_prc).await })
            .detach()
    }
}

/// Returns whether or not we're in China.
async fn test_china() -> surf::Result<bool> {
    let response = surf::get("http://checkip.amazonaws.com")
        .recv_string()
        .timeout(Duration::from_secs(5))
        .await
        .ok_or_else(|| anyhow::anyhow!("checkip timeout"))??;
    let response = response.trim();
    let parsed: IpAddr = response.parse()?;
    match parsed {
        IpAddr::V4(inner) => Ok(is_chinese_ip(inner)),
        IpAddr::V6(_) => Err(anyhow::anyhow!("cannot tell for ipv6").into()),
    }
}

/// Prints stats in a loop.
async fn print_stats_loop() {
    let gather = global_sosistab_stats();
    loop {
        wait_activity().await;
        log::info!(
            "** STATS **: smooth_ping = {:.2}; recv_loss = {:.2}%",
            gather.get_last("smooth_ping").unwrap_or_default() * 1000.0,
            gather.get_last("recv_loss").unwrap_or_default() * 100.0
        );
        smol::Timer::after(Duration::from_secs(3)).await;
    }
}

/// Forwards ports using a particular description.
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

/// Runs a logger that writes to a particular file.
async fn run_logger(mut file: smol::fs::File) {
    let (send, recv) = smol::channel::unbounded();
    *GLOBAL_LOGGER.lock() = Some(send);
    loop {
        let log_line = recv.recv().await.unwrap();
        file.write_all(format!("{}\n", log_line).as_bytes())
            .await
            .unwrap();
        file.flush().await.unwrap();
    }
}

/// Handles requests for the debug pack, proxy information, program termination, and general statistics
async fn handle_stats(_req: http_types::Request) -> http_types::Result<http_types::Response> {
    let mut res = http_types::Response::new(http_types::StatusCode::Ok);
    match _req.url().path() {
        "/proxy.pac" => {
            // Serves a Proxy Auto-Configuration file
            res.set_body("function FindProxyForURL(url, host){return 'PROXY 127.0.0.1:9910';}");
            Ok(res)
        }
        "/rawstats" => Ok(res),
        "/deltastats" => {
            // Serves all the delta stats as json
            let body_str = smol::unblock(move || {
                let detail = stat_derive();
                serde_json::to_string(&detail)
            })
            .await?;
            res.set_body(body_str);
            res.set_content_type(http_types::mime::JSON);
            Ok(res)
        }
        "/kill" => std::process::exit(0),
        _ => {
            // Serves all the stats as json
            let gather = global_sosistab_stats();
            let mut stats: BTreeMap<String, f32> = BTreeMap::new();
            stats.insert(
                "total_tx".into(),
                gather.get_last("total_sent_bytes").unwrap_or_default(),
            );
            stats.insert(
                "total_rx".into(),
                gather.get_last("total_recv_bytes").unwrap_or_default(),
            );
            stats.insert(
                "latency".into(),
                gather.get_last("raw_ping").unwrap_or_default(),
            );
            stats.insert(
                "loss".into(),
                gather.get_last("recv_loss").unwrap_or_default(),
            );
            res.set_body(serde_json::to_string(&stats)?);
            res.set_content_type(http_types::mime::JSON);
            Ok(res)
        }
    }
}

/// Handles a socks5 client from localhost
async fn handle_socks5(
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
            aioutils::copy_with_stats(conn.clone(), s5client.clone(), |_| {
                notify_activity();
            }),
            aioutils::copy_with_stats(s5client, conn, |_| {
                notify_activity();
            }),
        )
        .await?;
    }
    Ok(())
}
