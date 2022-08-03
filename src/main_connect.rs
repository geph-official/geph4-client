use std::{
    net::Ipv4Addr, net::SocketAddr, path::PathBuf, process::Stdio, sync::Arc, time::Duration,
};

use anyhow::Context;
use async_compat::Compat;
use async_net::TcpStream;
use china::test_china;
use futures_util::future::select_all;
use geph4_protocol::EndpointSource;
use geph4_protocol::{self, tunnel::ClientTunnel, BinderTunnelParams, ConnectionOptions};
use http_types::{Method, Request};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use smol::prelude::*;
use structopt::StructOpt;
use tap::Tap;

use crate::socks5::socks5_loop;
use crate::vpn::{run_vpn, stdio_vpn};
use crate::{china, port_forwarder::port_forwarder};
use crate::{stats::print_stats_loop, vpn::VPN_FD, AuthOpt, CommonOpt};

#[derive(Debug, StructOpt, Clone, Deserialize, Serialize)]
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

    #[structopt(long, default_value = "5")]
    /// Number of local UDP ports to use per session. This works around situations where unlucky ECMP routing sends flows down a congested path even when other paths exist, by "averaging out" all the possible routes.
    pub udp_shard_count: usize,

    #[structopt(long, default_value = "1")]
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
    /// Whether or not to stick to the same set of bridges
    pub sticky_bridges: bool,

    #[structopt(long)]
    /// Use this file descriptor for direct access to the VPN tun device.
    pub vpn_tun_fd: Option<i32>,

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

pub static TUNNEL: Lazy<RwLock<Option<Arc<ClientTunnel>>>> = Lazy::new(|| RwLock::new(None));

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
    // print out config file
    log::info!(
        "exit = {}, use_tcp = {}, use_bridges = {}",
        opt.exit_server,
        opt.use_tcp,
        opt.use_bridges
    );

    #[cfg(unix)]
    if let Some(fd) = opt.vpn_tun_fd {
        log::info!("setting VPN file descriptor to {}", fd);
        use std::os::unix::prelude::FromRawFd;
        VPN_FD
            .set(smol::Async::new(unsafe { std::fs::File::from_raw_fd(fd) })?)
            .expect("cannot set VPN file descriptor");
    }
    // We *recursively* call Geph again if GEPH_RECURSIVE is not set.
    // This means we start a child process with the same arguments, and pipe its stderr to the log file directly.
    // This ensures that 1. we can capture *all* stderr no matter what,
    // 2. we can restart the daemon no matter what (even when panics/OOM/etc happen),
    // and keep logs of what happened
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

                        // Attempt to kill any possible other Geph
                        let res = kill_existing_geph(opt.stats_listen).await;
                        log::debug!("kill resulted in {:?}", res);
                        break;
                    } else {
                        log::info!("Exiting normally.");
                        std::process::exit(0);
                    }
                } else {
                    log::debug!("{}", line);
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
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    }

    log::info!("connect mode started");

    // Make sure that username and password are given
    if opt.override_connect.is_none()
        && (opt.auth.username.is_empty() || opt.auth.password.is_empty())
    {
        anyhow::bail!("must provide both username and password")
    }

    // start a tunnel and connect
    let endpoint = {
        if let Some(override_url) = opt.override_connect.clone() {
            EndpointSource::Independent {
                endpoint: override_url,
            }
        } else {
            let cbc = crate::to_cached_binder_client(&opt.common, &opt.auth).await?;
            EndpointSource::Binder(BinderTunnelParams {
                ccache: Arc::new(cbc),
                exit_server: opt.exit_server.clone(),
                use_bridges: opt.use_bridges,
                force_bridge: opt.force_bridge,
                sticky_bridges: opt.sticky_bridges,
            })
        }
    };

    let tunnel = Arc::new(
        ClientTunnel::new(
            ConnectionOptions {
                udp_shard_count: opt.udp_shard_count,
                udp_shard_lifetime: opt.udp_shard_lifetime,
                tcp_shard_count: opt.tcp_shard_count,
                tcp_shard_lifetime: opt.tcp_shard_lifetime,
                use_tcp: opt.use_tcp,
            },
            endpoint,
        )
        .await?,
    );

    let client_ip = tunnel.return_connected().await?;

    {
        // put tunnel into global variable
        let mut t = TUNNEL.write();
        *t = Some(tunnel.clone());
    }
    // stats server
    let stats_fut = crate::stats::serve_stats(tunnel.clone(), opt.stats_listen);
    // print stats
    let stats_printer_fut = async {
        print_stats_loop(tunnel.clone()).await;
        Ok(())
    };
    // http proxy
    let _socks2h = smolscale::spawn(Compat::new(crate::socks2http::run_tokio(
        opt.http_listen,
        {
            let mut addr = opt.socks5_listen;
            addr.set_ip("127.0.0.1".parse().unwrap());
            addr
        },
    )));

    // socks5 proxy
    let socks5_fut = socks5_loop(tunnel.clone(), opt.socks5_listen, opt.exclude_prc);
    // dns
    let dns_fut = if let Some(dns_listen) = opt.dns_listen {
        log::debug!("starting dns...");
        smolscale::spawn(crate::dns::dns_loop(dns_listen, tunnel.clone()))
    } else {
        smolscale::spawn(smol::future::pending())
    };

    // run vpn
    let vpn_fut = if opt.stdio_vpn {
        smolscale::spawn(run_vpn(tunnel.clone()).or(stdio_vpn(client_ip)))
    } else {
        smolscale::spawn(run_vpn(tunnel.clone()))
    };

    // port forwarders
    let port_forwarders: Vec<_> = opt
        .forward_ports
        .iter()
        .map(|v| smolscale::spawn(port_forwarder(tunnel.clone(), v.clone())))
        .collect();
    if !port_forwarders.is_empty() {
        smolscale::spawn(select_all(port_forwarders)).await;
    }

    // ready, set, go!
    async { stats_fut.await }
        .race(async { stats_printer_fut.await })
        .race(async { socks5_fut.await })
        .race(async { dns_fut.await })
        .race(async { vpn_fut.await })
        .await
}

/// Kills geph at a particular port.
async fn kill_existing_geph(stats_addr: SocketAddr) -> anyhow::Result<()> {
    let conn = TcpStream::connect(
        stats_addr.tap_mut(|addr| addr.set_ip(Ipv4Addr::new(127, 0, 0, 1).into())),
    )
    .await?;
    async_h1::connect(conn, Request::new(Method::Get, "/kill"))
        .await
        .map_err(|e| e.into_inner())?;
    Ok(())
}
