use std::{convert::TryInto, net::Ipv4Addr, net::SocketAddrV4, path::PathBuf, sync::Arc};

use binder_transport::{BinderClient, BinderRequestData, BinderResponse, ExitDescriptor};
use env_logger::Env;
use serde::Serialize;
use smol::prelude::*;
use std::net::SocketAddr;
use std::time::Duration;
use structopt::StructOpt;
mod cache;
mod kalive;
mod persist;

fn str_to_path(src: &str) -> PathBuf {
    // if it's auto then generate
    if src == "auto" {
        let mut config_dir = dirs::config_dir().unwrap();
        config_dir.push("geph4-credentials");
        config_dir
    } else {
        PathBuf::from(src)
    }
}

fn str_to_x25519_pk(src: &str) -> x25519_dalek::PublicKey {
    let raw_bts = hex::decode(src).unwrap();
    let raw_bts: [u8; 32] = raw_bts.as_slice().try_into().unwrap();
    x25519_dalek::PublicKey::from(raw_bts)
}

fn str_to_mizaru_pk(src: &str) -> mizaru::PublicKey {
    let raw_bts = hex::decode(src).unwrap();
    let raw_bts: [u8; 32] = raw_bts.as_slice().try_into().unwrap();
    mizaru::PublicKey(raw_bts)
}

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(long, default_value = "http://binder-v4.geph.io:8964")]
    /// HTTP(S) address of the binder, FRONTED
    binder_http_front: String,

    #[structopt(long, default_value = "binder-v4.geph.io")]
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
}

fn main() -> anyhow::Result<()> {
    smol::block_on(main_async())
}

async fn main_async() -> anyhow::Result<()> {
    let opt: Opt = Opt::from_args();
    env_logger::from_env(Env::default().default_filter_or("info")).init();
    let version = env!("CARGO_PKG_VERSION");
    log::info!("geph4-client v{} starting...", version);
    let binder_client = Arc::new(binder_transport::HttpClient::new(
        opt.binder_master,
        opt.binder_http_front.to_string(),
        &[("Host".to_string(), opt.binder_http_host)],
    ));
    // create a db directory if doesn't exist
    let _ = std::fs::create_dir_all(&opt.credential_cache);
    let database = Arc::new(persist::KVDatabase::open(&opt.credential_cache)?);
    let client_cache = cache::ClientCache::new(
        "dorbie",
        "fc9dfc3d",
        opt.binder_mizaru_free.clone(),
        opt.binder_mizaru_plus.clone(),
        binder_client.clone(),
        database.clone(),
    );
    // create a kalive
    let keepalive = kalive::Keepalive::new(
        "sg-sgp-test-01.exits.geph.io",
        false,
        Arc::new(client_cache),
    );
    // enter the socks5 loop
    let socks5_listener = smol::net::TcpListener::bind(opt.socks5_listen).await?;
    // scope
    let scope = smol::Executor::new();
    scope
        .run(async {
            loop {
                let (s5client, _) = socks5_listener.accept().await?;
                scope.spawn(handle_socks5(s5client, &keepalive)).detach()
            }
        })
        .await
}

/// Handle a socks5 client from localhost.
async fn handle_socks5(
    s5client: smol::net::TcpStream,
    keepalive: &kalive::Keepalive,
) -> anyhow::Result<()> {
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
        smol::io::copy(conn.clone(), s5client.clone()),
        smol::io::copy(s5client, conn),
    )
    .await?;
    Ok(())
}

/// Obtains a vector of exits, given a binder client.
async fn get_exits(binder_client: Arc<dyn BinderClient>) -> anyhow::Result<Vec<ExitDescriptor>> {
    let res = smol::unblock(move || {
        binder_client.request(BinderRequestData::GetExits, Duration::from_secs(1))
    })
    .await?;
    match res {
        binder_transport::BinderResponse::GetExitsResp(exits) => Ok(exits),
        other => anyhow::bail!("unexpected response {:?}", other),
    }
}

pub async fn write_pascalish<T: Serialize>(
    writer: &mut (impl AsyncWrite + Unpin),
    value: &T,
) -> anyhow::Result<()> {
    let serialized = bincode::serialize(value).unwrap();
    assert!(serialized.len() <= 65535);
    // write bytes
    writer
        .write_all(&(serialized.len() as u16).to_be_bytes())
        .await?;
    writer.write_all(&serialized).await?;
    Ok(())
}
