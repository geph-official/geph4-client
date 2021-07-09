use std::net::SocketAddr;

use smol::net::{TcpListener, UdpSocket};

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
    pub fn new(local_udp: UdpSocket, local_tcp: TcpListener, remote_addr: SocketAddr, iptables: bool) -> Self {
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
        Self{local_udp, local_tcp, remote_addr, iptables}
    }
}

async fn tcp_forward(local_tcp: TcpListener, remote_addr: SocketAddr) {

}