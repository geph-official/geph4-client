use crate::{GEXEC, cache::ClientCache, kalive::Keepalive, persist::KVDatabase, prelude::*, stats::StatCollector};
use std::{net::Ipv4Addr, net::SocketAddr, net::SocketAddrV4, path::PathBuf, sync::Arc};
use structopt::StructOpt;
use scopeguard::defer;
use smol::prelude::*;

#[derive(Debug, StructOpt)]
pub struct ConnectOpt {
    #[structopt(long, default_value = "https://www.netlify.com/v4/")]
    /// HTTP(S) address of the binder, FRONTED
    binder_http_front: String,

    #[structopt(long, default_value = "loving-bell-981479.netlify.app")]
    /// HTTP(S) actual host of the binder
    binder_http_host: String,

    #[structopt(
        long,
        default_value = "124526f4e692b589511369687498cce57492bf4da20f8d26019c1cc0c80b6e4b",
        parse(from_str = str_to_x25519_pk)
    )]
    /// x25519 master key of the binder
    binder_master: x25519_dalek::PublicKey,

    #[structopt( 
        long,
        default_value = "4e01116de3721cc702f4c260977f4a1809194e9d3df803e17bb90db2a425e5ee",
        parse(from_str = str_to_mizaru_pk)
    )]
    /// mizaru master key of the binder, for FREE
    binder_mizaru_free: mizaru::PublicKey,

    #[structopt(
        long,
        default_value = "44ab86f527fbfb5a038cc51a49e0467be6eb532c4b9c6cb5cdb430926c95bdab",
        parse(from_str = str_to_mizaru_pk)
    )]
    /// mizaru master key of the binder, for PLUS
    binder_mizaru_plus: mizaru::PublicKey,

    #[structopt(long)]
    /// whether or not to use bridges
    use_bridges: bool,

    #[structopt(
        long,
        default_value = "auto",
        parse(from_str = str_to_path)
    )]
    /// where to store Geph's credential cache. The default value of "auto", meaning a platform-specific path that Geph gets to pick.
    credential_cache: PathBuf,

    #[structopt(long, default_value = "127.0.0.1:9909")]
    /// where to listen for SOCKS5 connections
    socks5_listen: SocketAddr,

    #[structopt(long, default_value = "127.0.0.1:9809")]
    /// where to listen for REST-based local connections
    stats_listen: SocketAddr,

    #[structopt(long, default_value="sg-sgp-test-01.exits.geph.io")]
    /// which exit server to connect to. If there isn't an exact match, the exit server with the most similar hostname is picked.
    exit_server: String,

    #[structopt(long)]
    /// username
    username: String,

    #[structopt(long)]
    /// password
    password: String,
}

pub async fn main_connect(opt: ConnectOpt) -> anyhow::Result<()> {
    let stat_collector = Arc::new(StatCollector::default());
    let binder_client = Arc::new(binder_transport::HttpClient::new(
        opt.binder_master,
        opt.binder_http_front.to_string(),
        &[("Host".to_string(), opt.binder_http_host)],
    ));
    // create a db directory if doesn't exist
    let _ = std::fs::create_dir_all(&opt.credential_cache);
    let database = Arc::new(KVDatabase::open(&opt.credential_cache)?);
    let client_cache = ClientCache::new(
        &opt.username,
        &opt.password,
        opt.binder_mizaru_free.clone(),
        opt.binder_mizaru_plus.clone(),
        binder_client.clone(),
        database.clone(),
    );
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
    let scollect = stat_collector.clone();
    // scope
    let scope = smol::Executor::new();
    let _stat: smol::Task<anyhow::Result<()>> = scope.spawn(async {
        loop {
            let (stat_client, _)  = stat_listener.accept().await?;
            let scollect = scollect.clone();
            GEXEC.spawn(async move {
                drop(async_h1::accept(stat_client, |req| handle_stat(scollect.clone(), req)).await);
            }).detach();
        }
    });
    scope
        .run(async {
            loop {
                let (s5client, _) = socks5_listener.accept().await?;
                scope.spawn(handle_socks5(stat_collector.clone(), s5client, &keepalive)).detach()
            }
        })
        .await
}

/// Handle a request for stats
async fn handle_stat(stats: Arc<StatCollector>, _req: http_types::Request) -> http_types::Result<http_types::Response> {
    let mut res = http_types::Response::new(http_types::StatusCode::Ok);
    let jstats = serde_json::to_string(&stats)?;
    res.set_body(jstats);
    res.insert_header("Content-Type", "application/json");
    Ok(res)
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
        copy_with_stats(conn.clone(), s5client.clone(), |n| stats.incr_total_rx(n as u64)),
        copy_with_stats(s5client, conn, |n| stats.incr_total_tx(n as u64)),
    )
    .await?;
    Ok(())
}

async fn copy_with_stats(mut reader: impl AsyncRead + Unpin, mut writer: impl AsyncWrite + Unpin, mut on_write: impl FnMut(usize)) -> std::io::Result<()>{
    let mut buffer = [0u8; 128*1024];
    loop {
        let n = reader.read(&mut buffer).await?;
        if n == 0 {
            return Ok(())
        }
        on_write(n);
        writer.write_all(&buffer[..n]).await?;
    }
}