use rand::prelude::*;
use smol::prelude::*;
use socksv5::v5::*;
use std::net::{
    Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream, ToSocketAddrs, UdpSocket,
};

fn main() {
    env_logger::init();
    let mut badrng = rand::rngs::StdRng::seed_from_u64(0);
    let mut worstrng = rand::rngs::SmallRng::seed_from_u64(0);
    smol::block_on(async move {
        let long_sk = x25519_dalek::StaticSecret::new(&mut badrng);
        let listener = sosistab::Listener::listen("0.0.0.0:23456", long_sk).await;
        loop {
            let socket = listener.accept_session().await.unwrap();
            println!("accepted session");
            smol::spawn(async move {
                let mplex = sosistab::mux::Multiplex::new(socket);
                loop {
                    let conn = mplex.accept_conn().await.unwrap();
                    smol::spawn(async move {
                        if let Err(e) = handle(conn).await {
                            eprintln!("Error in handle: {}", e);
                        }
                    })
                    .detach();
                }
            })
            .detach()
        }
    });
}

async fn handle(mut conn: sosistab::mux::RelConn) -> anyhow::Result<()> {
    let handshake = read_handshake(conn.clone()).await?;
    write_auth_method(conn.clone(), SocksV5AuthMethod::Noauth).await?;
    let request = read_request(conn.clone()).await?;
    let port = request.port;
    let addr = match &request.host {
        SocksV5Host::Domain(dom) => {
            let sss = String::from_utf8_lossy(&dom).to_string();
            smol::unblock(move || format!("{}:{}", sss, port).to_socket_addrs())
                .await?
                .next()
                .ok_or(anyhow::anyhow!("bad"))?
        }
        SocksV5Host::Ipv4(v4) => SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(v4[0], v4[1], v4[2], v4[3]),
            request.port,
        )),
        _ => anyhow::bail!("not supported"),
    };
    write_request_status(
        conn.clone(),
        SocksV5RequestStatus::Success,
        request.host,
        port,
    )
    .await?;
    let remote = async_dup::Arc::new(smol::Async::<TcpStream>::connect(addr).await?);
    eprintln!("remote {} connected", addr);
    let upload = smol::io::copy(conn.clone(), remote.clone());
    let download = smol::io::copy(remote, conn.clone());
    drop(smol::future::race(upload, download).await);
    Ok(())
}
