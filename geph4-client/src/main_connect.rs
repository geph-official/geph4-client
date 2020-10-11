use crate::{
    cache::ClientCache, kalive::Keepalive, prelude::*, stats::StatCollector, AuthOpt, CommonOpt,
    GEXEC,
};
use scopeguard::defer;
use smol::prelude::*;
use std::{net::Ipv4Addr, net::SocketAddr, net::SocketAddrV4, sync::Arc};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct ConnectOpt {
    #[structopt(flatten)]
    common: CommonOpt,

    #[structopt(flatten)]
    auth: AuthOpt,

    #[structopt(long)]
    /// whether or not to use bridges
    use_bridges: bool,

    #[structopt(long, default_value = "127.0.0.1:9909")]
    /// where to listen for SOCKS5 connections
    socks5_listen: SocketAddr,

    #[structopt(long, default_value = "127.0.0.1:9910")]
    /// where to listen for HTTP proxy connections
    http_listen: SocketAddr,

    #[structopt(long, default_value = "127.0.0.1:9809")]
    /// where to listen for REST-based local connections
    stats_listen: SocketAddr,

    #[structopt(long, default_value = "sg-sgp-test-01.exits.geph.io")]
    /// which exit server to connect to. If there isn't an exact match, the exit server with the most similar hostname is picked.
    exit_server: String,
}

pub async fn main_connect(opt: ConnectOpt) -> anyhow::Result<()> {
    log::info!("connect mode started");
    let stat_collector = Arc::new(StatCollector::default());
    // create a db directory if doesn't exist
    let client_cache = ClientCache::from_opts(&opt.common, &opt.auth)?;
    // create a kalive
    let keepalive = Keepalive::new(
        stat_collector.clone(),
        &opt.exit_server,
        opt.use_bridges,
        Arc::new(client_cache),
    );
    // enter the socks5 loop
    let socks5_listener = smol::net::TcpListener::bind(opt.socks5_listen).await?;
    let stat_listener = smol::net::TcpListener::bind(opt.stats_listen).await?;
    let http_listener = smol::net::TcpListener::bind(opt.http_listen).await?;
    let scollect = stat_collector.clone();
    // scope
    let scope = smol::Executor::new();
    let _stat: smol::Task<anyhow::Result<()>> = scope.spawn(async {
        loop {
            let (stat_client, _) = stat_listener.accept().await?;
            let scollect = scollect.clone();
            GEXEC
                .spawn(async move {
                    drop(
                        async_h1::accept(stat_client, |req| handle_stat(scollect.clone(), req))
                            .await,
                    );
                })
                .detach();
        }
    });
    let _http: smol::Task<anyhow::Result<()>> = scope.spawn(async {
        let my_scope = smol::Executor::new();
        my_scope
            .run(async {
                loop {
                    let (http_client, _) = http_listener.accept().await?;
                    my_scope
                        .spawn(handle_http(stat_collector.clone(), http_client, &keepalive))
                        .detach();
                }
            })
            .await
    });
    scope
        .run(async {
            loop {
                let (s5client, _) = socks5_listener.accept().await?;
                scope
                    .spawn(handle_socks5(stat_collector.clone(), s5client, &keepalive))
                    .detach()
            }
        })
        .await
}

/// Handle a request for stats
async fn handle_stat(
    stats: Arc<StatCollector>,
    _req: http_types::Request,
) -> http_types::Result<http_types::Response> {
    let mut res = http_types::Response::new(http_types::StatusCode::Ok);
    match _req.url().as_str() {
        "/proxy.pac" => {
            res.set_body("function FindProxyForURL(url, host){return 'PROXY 127.0.0.1:9809';}");
            Ok(res)
        }
        _ => {
            let jstats = serde_json::to_string(&stats)?;
            res.set_body(jstats);
            res.insert_header("Content-Type", "application/json");
            Ok(res)
        }
    }
}

/// Handle a socks5 client from localhost.
async fn handle_socks5(
    stats: Arc<StatCollector>,
    s5client: smol::net::TcpStream,
    keepalive: &Keepalive,
) -> anyhow::Result<()> {
    stats.incr_open_conns();
    defer!(stats.decr_open_conns());
    use socksv5::v5::*;
    let _handshake = read_handshake(s5client.clone()).await?;
    write_auth_method(s5client.clone(), SocksV5AuthMethod::Noauth).await?;
    let request = read_request(s5client.clone()).await?;
    let port = request.port;
    let addr: String = match &request.host {
        SocksV5Host::Domain(dom) => format!("{}:{}", String::from_utf8_lossy(&dom), request.port),
        SocksV5Host::Ipv4(v4) => SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(v4[0], v4[1], v4[2], v4[3]),
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
    let conn = keepalive.connect(&addr).await?;
    smol::future::race(
        copy_with_stats(conn.clone(), s5client.clone(), |n| {
            stats.incr_total_rx(n as u64)
        }),
        copy_with_stats(s5client, conn, |n| stats.incr_total_tx(n as u64)),
    )
    .await?;
    Ok(())
}

/// Handle a HTTP client from localhost.
async fn handle_http(
    stats: Arc<StatCollector>,
    hclient: smol::net::TcpStream,
    keepalive: &Keepalive,
) -> anyhow::Result<()> {
    // Rely on "squid" remotely
    let conn = keepalive.connect("127.0.0.1:3128").await?;
    smol::future::race(
        copy_with_stats(conn.clone(), hclient.clone(), |n| {
            stats.incr_total_rx(n as u64)
        }),
        copy_with_stats(hclient, conn, |n| stats.incr_total_tx(n as u64)),
    )
    .await?;
    Ok(())
}

async fn copy_with_stats(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    mut on_write: impl FnMut(usize),
) -> std::io::Result<()> {
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let n = reader.read(&mut buffer).await?;
        if n == 0 {
            return Ok(());
        }
        on_write(n);
        writer.write_all(&buffer[..n]).await?;
    }
}
