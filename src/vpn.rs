use std::{
    collections::HashMap,
    io::Stdin,
    io::Write,
    num::NonZeroU32,
    sync::atomic::AtomicU32,
    sync::{atomic::Ordering, Arc},
};

use anyhow::Context;
use async_net::Ipv4Addr;
use bytes::Bytes;
use flume::{self};
use geph4_protocol::{activity::notify_activity, Vpn, VpnMessage, VpnStdio};
use governor::{Quota, RateLimiter};
use once_cell::sync::{Lazy, OnceCell};
use parking_lot::RwLock;
use pnet_packet::{
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    tcp::{MutableTcpPacket, TcpFlags, TcpPacket},
    udp::MutableUdpPacket,
    udp::UdpPacket,
    MutablePacket, Packet,
};
use smol::Timer;
use smol::{channel::Receiver, prelude::*};
use std::time::Duration;
use tap::{Pipe, TapOptional};

/// The fd passed to us by the helper. This actually does work even though in general Async<File> does not, because tundevice FDs are not like file FDs.
pub static VPN_FD: OnceCell<smol::Async<std::fs::File>> = OnceCell::new();

// Up and down channels for iOS
pub static UP_CHANNEL: Lazy<(flume::Sender<Bytes>, flume::Receiver<Bytes>)> =
    Lazy::new(|| flume::bounded(100));
pub static DOWN_CHANNEL: Lazy<(flume::Sender<Bytes>, flume::Receiver<Bytes>)> =
    Lazy::new(|| flume::bounded(100));

#[derive(Clone)]
struct VpnContext<'a> {
    vpn: Arc<Vpn>,
    dns_nat: &'a RwLock<HashMap<u16, Ipv4Addr>>,
    client_ip: Ipv4Addr,
}

/// Vn stdio
pub async fn stdio_vpn(client_ip: Ipv4Addr) -> anyhow::Result<()> {
    log::debug!("STARTING VPN STDIO LOOP!");
    scopeguard::defer!(log::debug!("OH NO THE LOOP HAS DIED"));
    // send client ip to the vpn helper
    let msg = VpnStdio {
        verb: 1,
        body: format!("{}/10", client_ip).into(),
    };
    log::debug!("msg = {:?}", msg);
    {
        let mut stdout = std::io::stdout();
        msg.write_blocking(&mut stdout).unwrap();
        stdout.flush().unwrap();
    }

    stdio_vpn_up_loop().or(std_io_vpn_down_loop()).await
}

async fn std_io_vpn_down_loop() -> anyhow::Result<()> {
    log::debug!("STD_IO_VPN DOWN LOOP");
    let mut stdout = std::io::stdout();
    let mut buff = vec![];
    loop {
        if !buff.is_empty() {
            stdout.write_all(&buff)?;
            stdout.flush()?;
            // log::debug!("VPN flushing {} bytes", buff.len());
            buff.clear();
        }
        let bts = DOWN_CHANNEL.1.recv_async().await?;

        // either write to stdout or the FD
        if let Some(mut fd) = VPN_FD.get() {
            fd.write(&bts).await?;
        } else {
            let msg = VpnStdio { verb: 0, body: bts };
            msg.write_blocking(&mut buff)?;
        }
    }
}

async fn stdio_vpn_up_loop() -> anyhow::Result<()> {
    log::debug!("STD_IO_VPN UP LOOP");
    loop {
        let bts = if let Some(mut vpnfd) = VPN_FD.get() {
            let mut buf = [0; 2048];
            let n = vpnfd.read(&mut buf).await?;
            Bytes::copy_from_slice(&buf[..n])
        } else {
            let msg = STDIN.recv().await;
            msg.body
        };
        UP_CHANNEL.0.send(bts)?
    }
}

/// Runs a vpn session
pub async fn run_vpn(vpn: Arc<Vpn>) -> anyhow::Result<()> {
    // A mini-nat for DNS request
    let dns_nat = RwLock::new(HashMap::new());
    let ctx = VpnContext {
        vpn: vpn.clone(),
        dns_nat: &dns_nat,
        client_ip: vpn.client_ip,
    };
    vpn_up_loop(ctx.clone()).or(vpn_down_loop(ctx)).await
}

pub static EXTERNAL_FAKE_IP_U32: AtomicU32 = AtomicU32::new(0);

/// Up loop for vpn
async fn vpn_up_loop(ctx: VpnContext<'_>) -> anyhow::Result<()> {
    let limiter = RateLimiter::direct(
        Quota::per_second(NonZeroU32::new(500u32).unwrap())
            .allow_burst(NonZeroU32::new(100u32).unwrap()),
    );
    loop {
        let stdin_fut = async {
            let mut bts = UP_CHANNEL.1.recv_async().await.unwrap();
            // ACK decimation
            if ack_decimate(&bts).is_some() && limiter.check().is_err() {
                Ok(None)
            } else {
                // Fix source IP
                let source_ip_wrong = if let Some(pkt) = Ipv4Packet::new(&bts) {
                    let ip: Ipv4Addr = "123.123.123.123".parse().unwrap();
                    if pkt.get_source() != ctx.client_ip {
                        #[cfg(not(target_os = "linux"))]
                        EXTERNAL_FAKE_IP_U32.store(ip.into(), Ordering::Relaxed);

                        false
                    } else {
                        true
                    }
                } else {
                    log::debug!("EY EY EY NOT A PACKET?!");
                    false
                };
                if source_ip_wrong {
                    let mut mbts = bts.to_vec();
                    MutableIpv4Packet::new(&mut mbts)
                        .expect("cannot fail here")
                        .pipe(|mut pkt| pkt.set_source(ctx.client_ip));
                    fix_all_checksums(&mut mbts);
                    bts = mbts.into();
                }
                Ok::<Option<Bytes>, anyhow::Error>(Some(
                    fix_dns_dest(&bts, ctx.dns_nat).unwrap_or(bts),
                ))
            }
        };
        let body = stdin_fut.await.context("UP_CHANNEL failed")?;
        if let Some(body) = body {
            notify_activity();
            ctx.vpn.send_vpn(VpnMessage::Payload(body)).await?;
        }
    }
}

/// Down loop for vpn
async fn vpn_down_loop(ctx: VpnContext<'_>) -> anyhow::Result<()> {
    let mut count = 0u64;
    loop {
        let incoming = ctx.vpn.recv_vpn().await.context("downstream failed")?;
        // Timer::after(Duration::from_secs(1)).await;
        // let incoming = VpnMessage::Payload("labooooooooyah".as_bytes().into());
        count += 1;
        if count % 1000 == 1 {
            log::debug!("VPN received {} pkts ", count);
        }
        if let geph4_protocol::VpnMessage::Payload(bts) = incoming {
            let ip_u32 = EXTERNAL_FAKE_IP_U32.load(Ordering::Relaxed);
            let bts = if ip_u32 > 0 {
                let fake = Ipv4Addr::from(ip_u32);
                // log::debug!("{:?}", fake);
                let mut mbts = bts.to_vec();
                {
                    let pkt = MutableIpv4Packet::new(&mut mbts);
                    pkt.tap_some_mut(|pkt| pkt.set_destination(fake));
                }
                fix_all_checksums(&mut mbts);
                mbts.into()
            } else {
                bts
            };
            let bts = fix_dns_src(&bts, ctx.dns_nat).unwrap_or(bts);
            let _ = DOWN_CHANNEL.0.try_send(bts.clone()).is_ok();
            // if !success {
            //     log::debug!("sent VPN packet {} into down channel FAILED!!!!", count,);
            // }
        }
    }
}

/// returns ok if it's an ack that needs to be decimated
fn ack_decimate(bts: &[u8]) -> Option<u16> {
    let parsed = Ipv4Packet::new(bts)?;
    // log::warn!("******** VPN UP: {:?}", parsed);
    let parsed = TcpPacket::new(parsed.payload())?;
    let flags = parsed.get_flags();
    if flags & TcpFlags::ACK != 0 && flags & TcpFlags::SYN == 0 && parsed.payload().is_empty() {
        let hash = parsed.get_destination() ^ parsed.get_source();
        Some(hash)
    } else {
        None
    }
}

/// fixes dns destination
fn fix_dns_dest(bts: &[u8], nat: &RwLock<HashMap<u16, Ipv4Addr>>) -> Option<Bytes> {
    let dns_src_port = {
        let parsed = Ipv4Packet::new(bts)?;
        parsed.get_source();
        if parsed.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
            let parsed = UdpPacket::new(parsed.payload())?;
            if parsed.get_destination() == 53 {
                parsed.get_source()
            } else {
                return None;
            }
        } else {
            return None;
        }
    };
    let mut vv = bts.to_owned();
    let mut parsed = MutableIpv4Packet::new(&mut vv)?;
    nat.write().insert(dns_src_port, parsed.get_destination());
    parsed.set_destination(Ipv4Addr::new(1, 1, 1, 1));
    fix_all_checksums(&mut vv)?;
    Some(vv.into())
}

fn fix_all_checksums(bts: &mut [u8]) -> Option<()> {
    let mut ip_layer = MutableIpv4Packet::new(bts)?;
    let source = ip_layer.get_source();
    let dest = ip_layer.get_destination();

    if ip_layer.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
        let mut udp_layer = MutableUdpPacket::new(ip_layer.payload_mut())?;
        let udp_checksum =
            pnet_packet::udp::ipv4_checksum(&udp_layer.to_immutable(), &source, &dest);
        udp_layer.set_checksum(udp_checksum);
    } else if ip_layer.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
        let mut tcp_layer = MutableTcpPacket::new(ip_layer.payload_mut())?;
        let tcp_checksum =
            pnet_packet::tcp::ipv4_checksum(&tcp_layer.to_immutable(), &source, &dest);
        tcp_layer.set_checksum(tcp_checksum);
    }
    let ip_checksum = pnet_packet::ipv4::checksum(&ip_layer.to_immutable());
    ip_layer.set_checksum(ip_checksum);
    Some(())
}

/// fixes dns source
fn fix_dns_src(bts: &[u8], nat: &RwLock<HashMap<u16, Ipv4Addr>>) -> Option<Bytes> {
    let dns_src_port = {
        let parsed = Ipv4Packet::new(bts)?;
        // log::warn!("******** VPN DOWN: {:?}", parsed);
        if parsed.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
            let parsed = UdpPacket::new(parsed.payload())?;
            if parsed.get_source() == 53 {
                parsed.get_destination()
            } else {
                return None;
            }
        } else {
            return None;
        }
    };
    let mut vv = bts.to_owned();
    let mut parsed = MutableIpv4Packet::new(&mut vv)?;
    parsed.set_source(*nat.read().get(&dns_src_port)?);
    fix_all_checksums(&mut vv)?;
    Some(vv.into())
}

pub static STDIN: Lazy<AtomicStdin> = Lazy::new(AtomicStdin::new);

/// A type that wraps stdin and provides atomic packet recv operations to prevent cancellations from messing things up.
pub struct AtomicStdin {
    incoming: Receiver<VpnStdio>,
    _task: smol::Task<Option<()>>,
}

impl AtomicStdin {
    fn new() -> Self {
        static STDIN: Lazy<async_dup::Arc<async_dup::Mutex<smol::Unblock<Stdin>>>> =
            Lazy::new(|| {
                async_dup::Arc::new(async_dup::Mutex::new(smol::Unblock::with_capacity(
                    65536,
                    std::io::stdin(),
                )))
            });
        let (send_incoming, incoming) = smol::channel::bounded(100);
        let _task = smolscale::spawn(async move {
            let mut stdin = STDIN.clone();
            loop {
                let msg = VpnStdio::read(&mut stdin).await.unwrap();
                let _ = send_incoming.send(msg).await;
            }
        });
        Self { incoming, _task }
    }

    async fn recv(&self) -> VpnStdio {
        self.incoming.recv().await.unwrap()
    }
}
