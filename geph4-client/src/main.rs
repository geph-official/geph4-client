use std::{net::Ipv4Addr, net::SocketAddrV4, sync::Arc};

use binder_transport::{BinderClient, BinderRequestData, ExitDescriptor};
use env_logger::Env;
use serde::Serialize;
use smol::prelude::*;
use std::net::SocketAddr;
use std::time::Duration;
use structopt::StructOpt;

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
        default_value = "124526f4e692b589511369687498cce57492bf4da20f8d26019c1cc0c80b6e4b"
    )]
    /// x25519 master key of the binder
    binder_master_pk: String,
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
        bincode::deserialize(&hex::decode(opt.binder_master_pk)?)?,
        opt.binder_http_front.to_string(),
        &[("Host".to_string(), opt.binder_http_host)],
    ));
    let exits = get_exits(binder_client).await?;
    log::warn!("just using the first exit as a test now");
    let sosistab_session = sosistab::connect(
        smol::net::resolve(format!("{}:19831", exits[0].hostname)).await?[0],
        exits[0].sosistab_key,
    )
    .await?;
    let sosimux = sosistab::mux::Multiplex::new(sosistab_session);
    log::info!("sosistab session established to {}", exits[0].hostname);
    let socks5_listener = smol::net::TcpListener::bind("127.0.0.1:9909").await?;
    let scope = smol::LocalExecutor::new();
    scope
        .run(async {
            loop {
                let (s5client, _) = socks5_listener.accept().await?;
                scope.spawn(handle_socks5(s5client, &sosimux)).detach();
            }
        })
        .await
}

/// Handle a socks5 client from localhost.
async fn handle_socks5(
    s5client: smol::net::TcpStream,
    sosimux: &sosistab::mux::Multiplex,
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
    log::info!("sending request for {}", addr);
    let mut conn = sosimux.open_conn().await?;
    write_pascalish(&mut conn, &addr).await?;
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

async fn write_pascalish<T: Serialize>(
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
