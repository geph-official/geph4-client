use smol::net::{TcpListener, TcpStream, UdpSocket};
use smol::prelude::*;
use std::net::SocketAddr;

use crate::run_command;

/// A RAII struct that represents a port forwarder
pub struct Forwarder {
    local_udp: UdpSocket,
    local_tcp: TcpListener,
    remote_addr: SocketAddr,

    iptables: bool,
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        if self.iptables {
            run_command(&format!(
            "iptables -t nat -D PREROUTING -p udp --dport {} -j DNAT --to-destination {}:{};iptables -t nat -D PREROUTING -p tcp --dport {} -j DNAT --to-destination {}:{}; ",
            self.local_udp.local_addr().unwrap().port(),
            self.remote_addr.ip(), self.remote_addr.port(),
            self.local_tcp.local_addr().unwrap().port(),
            self.remote_addr.ip(), self.remote_addr.port()
            ));
        }
    }
}

impl Forwarder {
    /// Creates a new forwarder.
    pub fn new(
        local_udp: UdpSocket,
        local_tcp: TcpListener,
        remote_addr: SocketAddr,
        iptables: bool,
    ) -> Self {
        if iptables {
            run_command(&format!(
            "iptables -t nat -A PREROUTING -p udp --dport {} -j DNAT --to-destination {}:{};iptables -t nat -A PREROUTING -p tcp --dport {} -j DNAT --to-destination {}:{}; ",
            local_udp.local_addr().unwrap().port(),
            remote_addr.ip(), remote_addr.port(),
            local_tcp.local_addr().unwrap().port(),
            remote_addr.ip(), remote_addr.port()
            ));
        }
        let tcp_task = smolscale::spawn(tcp_forward(local_tcp.clone(), remote_addr));
        Self {
            local_udp,
            local_tcp,
            remote_addr,
            iptables,
        }
    }
}

async fn tcp_forward(local_tcp: TcpListener, remote_addr: SocketAddr) {
    loop {
        let (client, _) = local_tcp.accept().await.expect("tcp accept failed");
        smolscale::spawn(async move {
            let remote = TcpStream::connect(remote_addr).await;
            match remote {
                Err(err) => {
                    log::warn!("failed to open connection to {}: {:?}", remote_addr, err);
                }
                Ok(remote) => {
                    // two-way copy
                    let upload = aioutils::copy_with_stats(client.clone(), remote.clone(), |_| ());
                    let download = aioutils::copy_with_stats(remote, client, |_| ());
                    let _ = upload.race(download).await;
                }
            }
        })
        .detach();
    }
}
