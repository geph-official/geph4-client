use std::net::SocketAddr;

use super::ConnectContext;

/// Forwards ports using a particular description.
pub async fn port_forwarder(ctx: ConnectContext, desc: String) -> anyhow::Result<()> {
    let exploded = desc.split(":::").collect::<Vec<_>>();
    let listen_addr: SocketAddr = exploded[0].parse().expect("invalid port forwarding syntax");
    let listener = smol::net::TcpListener::bind(listen_addr)
        .await
        .expect("could not listen for port forwarding");
    loop {
        let (conn, _) = listener.accept().await?;

        let remote_addr = exploded[1].to_owned();
        let ctx = ctx.clone();
        smolscale::spawn(async move {
            let remote = ctx.tunnel.connect_stream(&remote_addr).await.ok()?;
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
