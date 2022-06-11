use std::{net::SocketAddr, sync::Arc};

use geph4_protocol::ClientTunnel;

use crate::fd_semaphore::acquire_fd;

/// Forwards ports using a particular description.
pub async fn port_forwarder(tun: Arc<ClientTunnel>, desc: String) {
    let exploded = desc.split(":::").collect::<Vec<_>>();
    let listen_addr: SocketAddr = exploded[0].parse().expect("invalid port forwarding syntax");
    let listener = smol::net::TcpListener::bind(listen_addr)
        .await
        .expect("could not listen for port forwarding");
    loop {
        let (conn, _) = listener.accept().await.unwrap();
        let _ticket = acquire_fd().await;
        if let Ok(_ticket) = _ticket {
            let tun = tun.clone();
            let remote_addr = exploded[1].to_owned();
            smolscale::spawn(async move {
                let _ticket = _ticket;
                let remote = tun.connect(&remote_addr).await.ok()?;
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
}
