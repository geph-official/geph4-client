use by_address::ByAddress;
use smol::prelude::*;
use smol::{
    net::{TcpListener, TcpStream},
    Async,
};
use std::{net::SocketAddr, sync::Arc};

use crate::{mmsg::recv_from_many, nat::NatTable, run_command, AsyncUdpSocket};

/// A RAII struct that represents a port forwarder
pub struct Forwarder {
    local_udp: AsyncUdpSocket,
    local_tcp: TcpListener,
    remote_addr: SocketAddr,

    iptables: bool,

    _tcp_task: smol::Task<()>,
    _udp_task: smol::Task<()>,
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        if self.iptables {
            run_command(&format!(
            "iptables -t nat -D PREROUTING -p udp --dport {} -j DNAT --to-destination {}:{};iptables -t nat -D PREROUTING -p tcp --dport {} -j DNAT --to-destination {}:{}; ",
            self.local_udp.get_ref().local_addr().unwrap().port(),
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
        local_udp: AsyncUdpSocket,
        local_tcp: TcpListener,
        remote_addr: SocketAddr,
        iptables: bool,
    ) -> Self {
        if iptables {
            run_command(&format!(
            "iptables -t nat -A PREROUTING -p udp --dport {} -j DNAT --to-destination {}:{};iptables -t nat -A PREROUTING -p tcp --dport {} -j DNAT --to-destination {}:{}; ",
            local_udp.get_ref().local_addr().unwrap().port(),
            remote_addr.ip(), remote_addr.port(),
            local_tcp.local_addr().unwrap().port(),
            remote_addr.ip(), remote_addr.port()
            ));
        }
        let tcp_task = smolscale::spawn(tcp_forward(local_tcp.clone(), remote_addr));
        let udp_task = smolscale::spawn(udp_forward(local_udp.clone(), remote_addr));
        Self {
            local_udp,
            local_tcp,
            remote_addr,
            iptables,
            _tcp_task: tcp_task,
            _udp_task: udp_task,
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

// the tricky part: UDP natting
async fn udp_forward(local_udp: AsyncUdpSocket, remote_addr: SocketAddr) {
    let mut nat_table: NatTable<ByAddress<Arc<NatEntry>>> = NatTable::new(3000);
    let mut buf = [0u8; 2048];
    loop {
        let (n, client_addr) = local_udp
            .recv_from(&mut buf)
            .await
            .expect("cannot read from local_udp");
        let buf = &buf[..n];
        let entry = nat_table.addr_to_item(client_addr, || {
            // bind everything now
            let newly_bound = async_dup::Arc::new(
                std::iter::from_fn(|| Some(fastrand::u32(1000..65536)))
                    .take(100000)
                    .find_map(|port| {
                        Async::<std::net::UdpSocket>::bind(
                            format!("[::0]:{}", port).parse::<SocketAddr>().unwrap(),
                        )
                        .ok()
                    })
                    .expect("could not find a free port after 10000 tries"),
            );
            newly_bound
                .get_ref()
                .connect(remote_addr)
                .expect("cannot 'connect' UDP");
            ByAddress(Arc::new(NatEntry {
                socket: newly_bound.clone(),
                _task: smolscale::spawn(udp_forward_downstream(
                    client_addr,
                    local_udp.clone(),
                    newly_bound,
                )),
            }))
        });
        if let Err(err) = entry.socket.send(buf).await {
            log::error!("cannot send through entry {:?}", err)
        }
    }
}

// one task
async fn udp_forward_downstream(
    client_addr: SocketAddr,
    local_udp: AsyncUdpSocket,
    remote_udp: AsyncUdpSocket,
) {
    let mut bufs = [[0u8; 2048]; 128];
    let mut bufs: Vec<&mut [u8]> = bufs.iter_mut().map(|f| f.as_mut()).collect();
    loop {
        match recv_from_many(&remote_udp, &mut bufs).await {
            Err(err) => {
                log::error!("error in downstream {:?}", err)
            }
            Ok(nn) => {
                for ((n, _), buf) in nn.into_iter().zip(bufs.iter()) {
                    let _ = local_udp.send_to(&buf[..n], client_addr).await;
                }
            }
        }
    }
}

struct NatEntry {
    socket: AsyncUdpSocket,
    _task: smol::Task<()>,
}
