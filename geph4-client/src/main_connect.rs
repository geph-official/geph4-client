use crate::{
    activity::{notify_activity, wait_activity},
    cache::ClientCache,
    stats::global_sosistab_stats,
    tunman::{TunnelManager, TunnelState},
    AuthOpt, CommonOpt,
};
use crate::{china, plots::stat_derive};
use anyhow::Context;
use async_compat::Compat;
use async_net::IpAddr;
use china::is_chinese_ip;
use http_types::{Method, Request, Url};
use once_cell::sync::Lazy;
use psl::Psl;
use smol::prelude::*;

use std::{
    collections::BTreeMap, net::Ipv4Addr, net::SocketAddr, net::SocketAddrV4, path::PathBuf,
    process::Stdio, sync::Arc, time::Duration,
};
use structopt::StructOpt;

#[derive(Debug, StructOpt, Clone)]
pub struct ConnectOpt {
    #[structopt(flatten)]
    pub common: CommonOpt,

    #[structopt(flatten)]
    pub auth: AuthOpt,

    #[structopt(long)]
    /// Whether or not to use bridges
    pub use_bridges: bool,

    #[structopt(long)]
    /// Overrides everything else, forcing connection to a particular sosistab URL (of the form pk@host:port). This also disables any form of authentication.
    pub override_connect: Option<String>,

    #[structopt(long)]
    /// Force a particular bridge
    pub force_bridge: Option<Ipv4Addr>,

    #[structopt(long, default_value = "8")]
    /// Number of local UDP ports to use per session. This works around situations where unlucky ECMP routing sends flows down a congested path even when other paths exist, by "averaging out" all the possible routes.
    pub udp_shard_count: usize,

    #[structopt(long, default_value = "60")]
    /// Lifetime of a single UDP port. Geph will switch to a different port within this many seconds.
    pub udp_shard_lifetime: u64,

    #[structopt(long, default_value = "4")]
    /// Number of TCP connections to use per session. This works around lossy links, per-connection rate limiting, etc.
    pub tcp_shard_count: usize,

    #[structopt(long, default_value = "1000")]
    /// Lifetime of a single TCP connection. Geph will switch to a different TCP connection within this many seconds.
    pub tcp_shard_lifetime: u64,

    #[structopt(long, default_value = "127.0.0.1:9910")]
    /// Where to listen for HTTP proxy connections
    pub http_listen: SocketAddr,
    #[structopt(long, default_value = "127.0.0.1:9909")]
    /// Where to listen for SOCKS5 connections
    pub socks5_listen: SocketAddr,
    #[structopt(long, default_value = "127.0.0.1:9809")]
    /// Where to listen for REST-based local connections
    pub stats_listen: SocketAddr,

    #[structopt(long)]
    /// Where to listen for proxied DNS requests. Optional.
    pub dns_listen: Option<SocketAddr>,

    #[structopt(long, default_value = "us-hio-01.exits.geph.io")]
    /// Which exit server to connect to. If there isn't an exact match, the exit server with the most similar hostname is picked.
    pub exit_server: String,

    #[structopt(long)]
    /// Whether or not to exclude PRC domains
    pub exclude_prc: bool,

    #[structopt(long)]
    /// Whether or not to wait for VPN commands on stdio
    pub stdio_vpn: bool,

    #[structopt(long)]
    /// Whether or not to force TCP mode.
    pub use_tcp: bool,

    #[structopt(long)]
    /// SSH-style local-remote port forwarding. For example, "0.0.0.0:8888:::example.com:22" will forward local port 8888 to example.com:22. Must be in form host:port:::host:port! May have multiple ones.
    pub forward_ports: Vec<String>,

    #[structopt(long)]
    /// Where to store a log file.
    pub log_file: Option<PathBuf>,
}

impl ConnectOpt {
    /// Should we use bridges?
    pub async fn should_use_bridges(&self) -> bool {
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
                self.use_bridges
            }
        }
    }
}

/// Main function for `connect` subcommand
pub async fn main_connect(opt: ConnectOpt) -> anyhow::Result<()> {
    // We *recursively* call Geph again if GEPH_RECURSIVE is not set.
    // This means we start a child process with the same arguments, and pipe its stderr to the log file directly.
    // This ensures that 1. we can capture *all* stderr no matter what, 2. we can restart the daemon no matter what (even when panics/OOM/etc happen), and keep logs of what happened
    if std::env::var("GEPH_RECURSIVE").is_err() {
        static IP_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
            regex::Regex::new(r#"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"#).unwrap()
        });
        let mut log_file = if let Some(path) = opt.log_file.as_ref() {
            Some(
                smol::fs::File::create(path)
                    .await
                    .context("cannot create log file")?,
            )
        } else {
            None
        };
        // infinitely loop around
        let my_path = std::env::current_exe()?;
        std::env::set_var("GEPH_RECURSIVE", "1");
        scopeguard::defer!(std::env::remove_var("GEPH_RECURSIVE"));
        loop {
            let args = std::env::args().collect::<Vec<_>>();
            let mut child = smol::process::Command::new(&my_path)
                .args(&args[1..])
                .stderr(Stdio::piped())
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .spawn()
                .context("cannot spawn child")?;

            let mut stdout = smol::io::BufReader::new(child.stderr.take().unwrap());
            let mut line = String::new();
            loop {
                if stdout.read_line(&mut line).await? == 0 {
                    // we've gotten to the end
                    log::debug!("child process ended, checking status code!");
                    let output = child.output().await?;
                    let scode = output.status.code().unwrap_or(200);
                    if scode != 0 {
                        if let Some(log_file) = log_file.as_mut() {
                            log_file
                                .write_all(b"------------------- RESTART -------------------\n")
                                .await?;
                        }
                        log::error!("***** ABNORMAL RESTART (status code {}) *****", scode);
                        break;
                    } else {
                        log::info!("Exiting normally.");
                        std::process::exit(0);
                    }
                } else {
                    eprint!("{}", line);
                    if let Some(log_file) = log_file.as_mut() {
                        let line = IP_REGEX.replace_all(&line, "[redacted]");
                        let stripped_line =
                            strip_ansi_escapes::strip(line.as_bytes()).unwrap_or_default();
                        log_file
                            .write_all(&stripped_line)
                            .await
                            .context("cannot write to log file")?;
                    }
                    line.clear();
                }
            }
        }
    }

    log::info!("connect mode started");

    // Make sure that username and password are given
    if opt.override_connect.is_none()
        && (opt.auth.username.is_empty() || opt.auth.password.is_empty())
    {
        anyhow::bail!("must provide both username and password")
    }

    let _stats = smolscale::spawn(print_stats_loop());

    // Start socks to http
    let _socks2h = smolscale::spawn(Compat::new(crate::socks2http::run_tokio(
        opt.http_listen,
        {
            let mut addr = opt.socks5_listen;
            addr.set_ip("127.0.0.1".parse().unwrap());
            addr
        },
    )));

    // Create a database directory if doesn't exist
    let client_cache = ClientCache::from_opts(&opt.common, &opt.auth)
        .await
        .context("cannot create ClientCache")?;
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
    // Enter the stats loop
    let stat_listener = smol::net::TcpListener::bind(opt.stats_listen)
        .await
        .context("cannot bind stats")?;
    let _stat: smol::Task<anyhow::Result<()>> = {
        let tman = tunnel_manager.clone();
        smolscale::spawn(async move {
            loop {
                let (stat_client, _) = stat_listener.accept().await?;
                let tman = tman.clone();
                smolscale::spawn(async move {
                    drop(
                        async_h1::accept(stat_client, move |req| {
                            let tman = tman.clone();
                            async move { handle_stats(tman, req).await }
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
        smolscale::spawn(async move { handle_socks5(s5client, &tunnel_manager, exclude_prc).await })
            .detach()
    }
}

/// Returns whether or not we're in China.
#[cached::proc_macro::cached(result = true)]
async fn test_china() -> http_types::Result<bool> {
    let req = Request::new(
        Method::Get,
        Url::parse("http://checkip.amazonaws.com").unwrap(),
    );
    let connect_to = geph4_aioutils::resolve("checkip.amazonaws.com:80").await?;

    let response = {
        let connection =
            smol::net::TcpStream::connect(connect_to.get(0).context("no addrs for checkip")?)
                .await?;
        async_h1::connect(connection, req)
            .await?
            .body_string()
            .await?
    };
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
        wait_activity(Duration::from_secs(200)).await;
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

/// Handles requests for the debug pack, proxy information, program termination, and general statistics
async fn handle_stats(
    tman: TunnelManager,
    req: http_types::Request,
) -> http_types::Result<http_types::Response> {
    let mut res = http_types::Response::new(http_types::StatusCode::Ok);
    match req.url().path() {
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
            if tman.current_state() != TunnelState::Connecting {
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
                    gather.get_last("smooth_ping").unwrap_or_default(),
                );
                stats.insert(
                    "loss".into(),
                    gather.get_last("recv_loss").unwrap_or_default(),
                );
                res.set_body(serde_json::to_string(&stats)?);
                res.set_content_type(http_types::mime::JSON);
            }
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
    notify_activity();
    s5client.set_nodelay(true)?;
    use socksv5::v5::*;
    let _handshake = read_handshake(s5client.clone()).await?;
    write_auth_method(s5client.clone(), SocksV5AuthMethod::Noauth).await?;
    let request = read_request(s5client.clone()).await?;
    let port = request.port;
    let v4addr: Option<Ipv4Addr>;

    let is_private: bool;

    let addr: String = match &request.host {
        SocksV5Host::Domain(dom) => {
            v4addr = String::from_utf8_lossy(dom).parse().ok();
            is_private = psl::List.suffix(dom).is_none();
            format!("{}:{}", String::from_utf8_lossy(dom), request.port)
        }
        SocksV5Host::Ipv4(v4) => {
            let v4addr_inner = Ipv4Addr::new(v4[0], v4[1], v4[2], v4[3]);
            is_private = v4addr_inner.is_private() || v4addr_inner.is_loopback();
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
    write_request_status(
        s5client.clone(),
        SocksV5RequestStatus::Success,
        request.host,
        port,
    )
    .await?;

    let must_direct = is_private
        || (exclude_prc
            && (china::is_chinese_host(addr.split(':').next().unwrap())
                || v4addr.map(china::is_chinese_ip).unwrap_or(false)));
    if must_direct {
        log::debug!("bypassing {}", addr);
        let conn = smol::net::TcpStream::connect(&addr).await?;
        smol::future::race(
            geph4_aioutils::copy_with_stats(conn.clone(), s5client.clone(), |_| ()),
            geph4_aioutils::copy_with_stats(s5client.clone(), conn.clone(), |_| ()),
        )
        .await?;
    } else {
        let conn = tunnel_manager.connect(&addr).await?;
        smol::future::race(
            geph4_aioutils::copy_with_stats(conn.clone(), s5client.clone(), |_| {
                notify_activity();
            }),
            geph4_aioutils::copy_with_stats(s5client, conn, |_| {
                notify_activity();
            }),
        )
        .await?;
    }
    Ok(())
}
