use std::{collections::HashSet, net::Ipv4Addr, ops::Deref, sync::Arc, time::Duration};

use bytes::Bytes;
use cidr::{Cidr, Ipv4Cidr};
use libc::{c_void, SOL_IP, SO_ORIGINAL_DST};
use lru::LruCache;
use once_cell::sync::Lazy;
use os_socketaddr::OsSocketAddr;
use parking_lot::{Mutex, RwLock};
use pnet_packet::{
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet,
};
use smol::channel::Sender;
use smol_timeout::TimeoutExt;
use std::os::unix::io::AsRawFd;
use tundevice::TunDevice;
use vpn_structs::Message;

/// Runs the transparent proxy helper
pub async fn transparent_proxy_helper() -> anyhow::Result<()> {
    // always run on port 10000
    let listener = smol::net::TcpListener::bind("0.0.0.0:10000").await.unwrap();
    loop {
        let (client, _) = listener.accept().await.unwrap();
        smolscale::spawn(async move {
            client.set_nodelay(true).ok()?;
            let client_fd = client.as_raw_fd();
            let original_dest = unsafe {
                let raw_addr = OsSocketAddr::new();
                if libc::getsockopt(
                    client_fd,
                    SOL_IP,
                    SO_ORIGINAL_DST,
                    raw_addr.as_ptr() as *mut c_void,
                    (&mut std::mem::size_of::<libc::sockaddr>()) as *mut usize as *mut u32,
                ) != 0
                {
                    log::warn!("cannot get SO_ORIGINAL_DST, aborting");
                    return None;
                };
                let lala = raw_addr.into_addr();
                if let Some(lala) = lala {
                    lala
                } else {
                    log::warn!("SO_ORIGINAL_DST is not an IP address, aborting");
                    return None;
                }
            };
            let remote = smol::net::TcpStream::connect(original_dest)
                .timeout(Duration::from_secs(60))
                .await?
                .ok()?;
            remote.set_nodelay(true).ok()?;
            smol::future::race(
                aioutils::copy_with_stats(remote.clone(), client.clone(), |_| ()),
                aioutils::copy_with_stats(client.clone(), remote.clone(), |_| ()),
            )
            .await
            .ok()?;
            Some(())
        })
        .detach();
    }
}

/// Handles a VPN session
pub async fn handle_vpn_session(
    mux: &sosistab::mux::Multiplex,
    exit_hostname: String,
    stat_client: Arc<statsd::Client>,
    port_whitelist: bool,
) -> anyhow::Result<()> {
    Lazy::force(&INCOMING_PKT_HANDLER);
    log::debug!("handle_vpn_session entered");
    scopeguard::defer!(log::debug!("handle_vpn_session exited"));
    let assigned_ip: Lazy<AssignedIpv4Addr> = Lazy::new(|| IpAddrAssigner::global().assign());
    let (send_down, recv_down) = smol::channel::bounded(10);
    let key = format!("exit_usage.{}", exit_hostname.replace(".", "-"));
    let down_loop = async {
        loop {
            let bts: Bytes = recv_down.recv().await?;
            stat_client.sampled_count(&key, bts.len() as f64, 0.1);
            let pkt = Ipv4Packet::new(&bts).expect("don't send me invalid IPv4 packets!");
            assert_eq!(pkt.get_destination(), assigned_ip.addr());
            let msg = Message::Payload(bts);
            mux.send_urel(bincode::serialize(&msg).unwrap().into())
                .await?;
        }
    };
    let up_loop = async {
        loop {
            let bts = mux.recv_urel().await?;
            let msg: Message = bincode::deserialize(&bts)?;
            match msg {
                Message::ClientHello { .. } => {
                    mux.send_urel(
                        bincode::serialize(&Message::ServerHello {
                            client_ip: *assigned_ip.clone(),
                            gateway: "100.64.0.1".parse().unwrap(),
                        })
                        .unwrap()
                        .into(),
                    )
                    .await?;
                }
                Message::Payload(bts) => {
                    stat_client.sampled_count(&key, bts.len() as f64, 0.1);
                    let pkt = Ipv4Packet::new(&bts);
                    if let Some(pkt) = pkt {
                        // source must be correct and destination must not be banned
                        if pkt.get_source() != assigned_ip.addr()
                            || pkt.get_destination().is_loopback()
                            || pkt.get_destination().is_private()
                            || pkt.get_destination().is_unspecified()
                            || pkt.get_destination().is_broadcast()
                        {
                            continue;
                        }
                        // must not be blacklisted
                        let port = {
                            match pkt.get_next_level_protocol() {
                                IpNextHeaderProtocols::Tcp => {
                                    TcpPacket::new(&pkt.payload()).map(|v| v.get_destination())
                                }
                                IpNextHeaderProtocols::Udp => {
                                    UdpPacket::new(&pkt.payload()).map(|v| v.get_destination())
                                }
                                _ => None,
                            }
                        };
                        if let Some(port) = port {
                            if crate::lists::BLACK_PORTS.contains(&port) {
                                continue;
                            }
                            if port_whitelist && !crate::lists::WHITE_PORTS.contains(&port) {
                                continue;
                            }
                        }
                        RAW_TUN.write_raw(bts).await;
                        INCOMING_MAP
                            .write()
                            .put(assigned_ip.addr(), send_down.clone());
                    }
                }
                _ => anyhow::bail!("message in invalid context"),
            }
        }
    };
    smol::future::race(up_loop, down_loop).await
}

/// Mapping for incoming packets
static INCOMING_MAP: Lazy<RwLock<LruCache<Ipv4Addr, Sender<Bytes>>>> =
    Lazy::new(|| RwLock::new(LruCache::new(1000)));

/// Incoming packet handler
static INCOMING_PKT_HANDLER: Lazy<smol::Task<()>> = Lazy::new(|| {
    smolscale::spawn(async {
        loop {
            let pkt = RAW_TUN
                .read_raw()
                .await
                .expect("cannot read from tun device");
            let parsed = Ipv4Packet::new(&pkt);
            let dest = Ipv4Packet::new(&pkt)
                .map(|pkt| INCOMING_MAP.read().peek(&pkt.get_destination()).cloned());
            if let Some(Some(dest)) = dest {
                let _ = dest.try_send(pkt);
            } else {
                log::warn!(
                    "can't route to {}, no handler",
                    parsed
                        .map(|p| p.get_destination().to_string())
                        .unwrap_or_else(|| String::from("NOPARSE"))
                );
            }
        }
    })
});

/// The raw TUN device.
static RAW_TUN: Lazy<TunDevice> = Lazy::new(|| {
    log::info!("initializing tun-geph");
    let dev =
        TunDevice::new_from_os("tun-geph").expect("could not initiate 'tun-geph' tun device!");
    dev.assign_ip("100.64.0.1/10");
    smol::future::block_on(dev.write_raw(Bytes::from_static(b"hello world")));
    dev
});

/// Global IpAddr assigner
static CGNAT_IPASSIGN: Lazy<IpAddrAssigner> =
    Lazy::new(|| IpAddrAssigner::new("100.64.0.0/10".parse().unwrap()));

/// An IP address assigner
pub struct IpAddrAssigner {
    cidr: Ipv4Cidr,
    table: Arc<Mutex<HashSet<Ipv4Addr>>>,
}

impl IpAddrAssigner {
    /// Creates a new address assigner.
    pub fn new(cidr: Ipv4Cidr) -> Self {
        Self {
            cidr,
            table: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Get the global CGNAT instance.
    pub fn global() -> &'static Self {
        &CGNAT_IPASSIGN
    }

    /// Assigns a new IP address.
    pub fn assign(&self) -> AssignedIpv4Addr {
        loop {
            for elem in self.cidr.iter().skip(16) {
                let mut tab = self.table.lock();
                if !tab.contains(&elem) {
                    tab.insert(elem);
                    log::debug!("assigned {}", elem);
                    return AssignedIpv4Addr::new(self.table.clone(), elem);
                }
            }
        }
    }
}

/// An assigned IP address. Derefs to std::net::Ipv4Addr and acts as a smart-pointer that deassigns the IP address when no longer needed.
#[derive(Clone, Debug)]
pub struct AssignedIpv4Addr {
    inner: Arc<AssignedIpv4AddrInner>,
}

impl AssignedIpv4Addr {
    fn new(table: Arc<Mutex<HashSet<Ipv4Addr>>>, addr: Ipv4Addr) -> Self {
        Self {
            inner: Arc::new(AssignedIpv4AddrInner { table, addr }),
        }
    }
    pub fn addr(&self) -> Ipv4Addr {
        self.inner.addr
    }
}

impl PartialEq for AssignedIpv4Addr {
    fn eq(&self, other: &Self) -> bool {
        self.inner.addr.eq(&other.inner.addr)
    }
}

impl Eq for AssignedIpv4Addr {}

impl PartialOrd for AssignedIpv4Addr {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.inner.addr.partial_cmp(&other.inner.addr)
    }
}

impl Ord for AssignedIpv4Addr {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.inner.addr.cmp(&other.inner.addr)
    }
}

impl Deref for AssignedIpv4Addr {
    type Target = Ipv4Addr;

    fn deref(&self) -> &Self::Target {
        &self.inner.addr
    }
}

#[derive(Debug)]
struct AssignedIpv4AddrInner {
    addr: Ipv4Addr,
    table: Arc<Mutex<HashSet<Ipv4Addr>>>,
}

impl Drop for AssignedIpv4AddrInner {
    fn drop(&mut self) {
        log::debug!("dropped {}", self.addr);
        if !self.table.lock().remove(&self.addr) {
            panic!("AssignedIpv4Addr double free?! {}", self.addr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgnat() {
        let assigner = IpAddrAssigner::new("100.64.0.0/10".parse().unwrap());
        let mut assigned = Vec::new();
        for _ in 0..2 {
            assigned.push(assigner.assign());
        }
        dbg!(assigned);
    }
}
