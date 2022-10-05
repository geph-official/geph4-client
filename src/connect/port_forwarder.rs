use std::net::SocketAddr;

use super::TUNNEL;

/// Forwards ports using a particular description.
pub async fn port_forwarder(desc: String) {
    let exploded = desc.split(":::").collect::<Vec<_>>();
    let listen_addr: SocketAddr = exploded[0].parse().expect("invalid port forwarding syntax");
    let listener = smol::net::TcpListener::bind(listen_addr)
        .await
        .expect("could not listen for port forwarding");
    loop {
        let (conn, _) = listener.accept().await.unwrap();

        let remote_addr = exploded[1].to_owned();
        smolscale::spawn(async move {
            let remote = TUNNEL.connect(&remote_addr).await.ok()?;
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
