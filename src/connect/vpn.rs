#[cfg(target_os = "linux")]
mod linux_routing;

#[cfg(target_os = "macos")]
mod macos_routing;

#[cfg(windows)]
mod windows_routing;

use std::{
    convert::Infallible, io::BufWriter, num::NonZeroU32, sync::Arc, thread::JoinHandle,
    time::Duration,
};
use std::{
    io::BufReader,
    sync::atomic::{AtomicU32, Ordering},
};

use std::io::{Read, Write};

#[cfg(unix)]
use std::os::unix::prelude::{AsRawFd, FromRawFd};

use anyhow::Context;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use bytes::Bytes;
use std::net::Ipv4Addr;

use geph_nat::GephNat;
use governor::{Quota, RateLimiter};
use once_cell::sync::Lazy;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::MutablePacket;
use pnet_packet::{
    ipv4::Ipv4Packet,
    tcp::{TcpFlags, TcpPacket},
    Packet,
};
use smol::prelude::*;

use crate::{config::VpnMode, connect::stats::STATS_RECV_BYTES};

use super::{stats::STATS_SEND_BYTES, CONNECT_CONFIG, TUNNEL};

/// The VPN shuffling task
pub static VPN_SHUFFLE_TASK: Lazy<JoinHandle<Infallible>> = Lazy::new(|| {
    #[cfg(unix)]
    /// Runs the VPN on a particular file-descriptor number.
    unsafe fn fd_vpn_loop(fd_num: i32) -> Infallible {
        let mut up_file = std::fs::File::from_raw_fd(fd_num);
        let mut down_file = std::fs::File::from_raw_fd(fd_num);
        let up_thread = std::thread::Builder::new()
            .name("vpn-up".into())
            .spawn(move || {
                let mut bts = [0u8; 65536];
                loop {
                    let n = up_file.read(&mut bts).expect("vpn up thread failed");

                    let to_send = Bytes::copy_from_slice(&bts[..n]);
                    #[cfg(target_os = "macos")]
                    let to_send = if to_send.len() >= 4 {
                        to_send.slice(4..)
                    } else {
                        continue;
                    };
                    log::trace!("vpn up {}", to_send.len());
                    vpn_upload(to_send);
                }
            })
            .unwrap();
        let dn_thread = std::thread::Builder::new()
            .name("vpn-dn".into())
            .spawn(move || loop {
                let bts = vpn_download_blocking();
                log::trace!("vpn dn {}", bts.len());
                #[cfg(target_os = "macos")]
                {
                    let mut buf = [0u8; 65536];
                    buf[4..][..bts.len()].copy_from_slice(&bts);
                    buf[3] = 0x02;
                    let _ = down_file.write(&buf[..bts.len() + 4]);
                }
                #[cfg(not(target_os = "macos"))]
                let _ = down_file.write(&bts).unwrap();
            })
            .unwrap();
        up_thread.join().unwrap();
        dn_thread.join().unwrap()
    }

    std::thread::Builder::new()
        .name("vpn".into())
        .spawn(|| {
            match CONNECT_CONFIG.vpn_mode {
                Some(VpnMode::Stdio) => {
                    // every packet is prepended with u16le length
                    std::thread::spawn(|| {
                        let mut stdin = BufReader::new(std::io::stdin().lock());
                        // upload
                        loop {
                            let len = stdin.read_u16::<LittleEndian>().unwrap() as usize;
                            let mut buffer = vec![0u8; len];
                            stdin.read_exact(&mut buffer).unwrap();
                            vpn_upload(buffer.into())
                        }
                    });
                    // download
                    let mut stdout = BufWriter::new(std::io::stdout().lock());
                    loop {
                        let down_pkt = vpn_download_blocking();
                        stdout
                            .write_u16::<LittleEndian>(down_pkt.len() as u16)
                            .unwrap();
                        stdout.write_all(&down_pkt).unwrap();
                        stdout.flush().unwrap();
                    }
                }
                Some(VpnMode::InheritedFd) => {
                    #[cfg(unix)]
                    {
                        // Read the file-descriptor number from an environment variable
                        let fd_num: i32 = std::env::var("GEPH_VPN_FD")
                    .ok()
                     .and_then(|e| e.parse().ok())
                    .expect(
                    "must set GEPH_VPN_FD to a file descriptor in order to use inherited-fd mode",
                    );
                        unsafe { fd_vpn_loop(fd_num) }
                    }
                    #[cfg(not(unix))]
                    {
                        panic!("cannot use inherited-fd mode on non-Unix systems")
                    }
                }
                Some(VpnMode::TunNoRoute | VpnMode::TunRoute) => {
                    #[cfg(unix)]
                    {
                        #[cfg(target_os = "macos")]
                        let device = {
                            use tun::Device;
                            let device = ::tun::platform::Device::new(
                                ::tun::Configuration::default().mtu(16384).up(),
                            )
                            .expect("could not initialize TUN device");
                            std::process::Command::new("ifconfig")
                                .arg(device.name())
                                .arg("100.64.89.64")
                                .arg("100.64.0.1")
                                .spawn()
                                .expect("cannot ifconfig")
                                .wait()
                                .expect("cannot wait");
                            device
                        };

                        #[cfg(not(target_os = "macos"))]
                        let device = ::tun::platform::Device::new(
                            ::tun::Configuration::default()
                                .name("tun-geph")
                                .address("100.64.89.64")
                                .netmask("255.255.255.0")
                                .destination("100.64.0.1")
                                .mtu(16384)
                                .up(),
                        )
                        .expect("could not initialize TUN device");
                        if CONNECT_CONFIG.vpn_mode == Some(VpnMode::TunRoute) {
                            #[cfg(target_os = "linux")]
                            {
                                linux_routing::setup_routing();
                            }
                            #[cfg(target_os = "macos")]
                            {
                                use tun::Device;
                                macos_routing::setup_routing(device.name());
                            }
                        }
                        unsafe { fd_vpn_loop(device.as_raw_fd()) }
                    }
                    #[cfg(not(unix))]
                    {
                        panic!("cannot use tun modes on non-Unix systems")
                    }
                }
                Some(VpnMode::WinDivert) => {
                    #[cfg(windows)]
                    {
                        windows_routing::start_routing()
                    }

                    #[cfg(not(windows))]
                    {
                        panic!("cannot use windivert mode outside windows")
                    }
                }
                None => {
                    log::info!("not starting VPN mode");
                    Lazy::force(&TUNNEL);
                    loop {
                        std::thread::park()
                    }
                }
            }
        })
        .unwrap()
});

/// Uploads a packet through the global VPN
pub fn vpn_upload(pkt: Bytes) {
    Lazy::force(&VPN_TASK);
    STATS_SEND_BYTES.fetch_add(pkt.len() as u64, Ordering::Relaxed);
    let _ = UP_CHANNEL.0.try_send(pkt);
}

/// Downloads a packet through the global VPN
pub async fn vpn_download() -> Bytes {
    log::trace!("called vpn_download");
    Lazy::force(&VPN_TASK);
    let pkt = DOWN_CHANNEL.1.recv_async().await.unwrap();
    STATS_RECV_BYTES.fetch_add(pkt.len() as u64, Ordering::Relaxed);
    pkt
}

/// Downloads a packet through the global VPN, blockingly
pub fn vpn_download_blocking() -> Bytes {
    Lazy::force(&VPN_TASK);
    let pkt = DOWN_CHANNEL.1.recv().unwrap();
    STATS_RECV_BYTES.fetch_add(pkt.len() as u64, Ordering::Relaxed);
    pkt
}

// Up and down channels
static UP_CHANNEL: Lazy<(flume::Sender<Bytes>, flume::Receiver<Bytes>)> =
    Lazy::new(|| flume::bounded(10000));
static DOWN_CHANNEL: Lazy<(flume::Sender<Bytes>, flume::Receiver<Bytes>)> =
    Lazy::new(|| flume::bounded(10000));

static VPN_TASK: Lazy<std::thread::JoinHandle<()>> = Lazy::new(|| {
    std::thread::spawn(|| {
        match std::panic::catch_unwind(|| {
            smol::future::block_on(async {
                loop {
                    log::info!("VPN task about to get client IP...");
                    let init_ip = TUNNEL.get_vpn_client_ip().await;
                    log::info!("VPN task initializing IP to {init_ip}");
                    let nat = Arc::new(GephNat::new(NAT_TABLE_SIZE, init_ip));
                    let ip_change_fut = async move {
                        loop {
                            let i = TUNNEL.get_vpn_client_ip().await;
                            if i != init_ip {
                                anyhow::bail!("new IP: {i}")
                            }
                            smol::Timer::after(Duration::from_secs(5)).await;
                        }
                    };
                    let res = vpn_up_loop(nat.clone())
                        .or(vpn_down_loop(nat))
                        .or(ip_change_fut)
                        .await;
                    log::warn!("vpn loops somehow died: {:?}", res);
                }
            })
        }) {
            Ok(inner) => log::error!("VPN Task loop returned?!! {:?}", inner),
            Err(e) => log::error!("VPN_TASK just panicked with {:?}", e),
        }
    })
});

const NAT_TABLE_SIZE: usize = 10000; // max size of the NAT table

/// Up loop for vpn
async fn vpn_up_loop(nat: Arc<GephNat>) -> anyhow::Result<()> {
    let limiter = RateLimiter::direct(
        Quota::per_second(NonZeroU32::new(500u32).unwrap())
            .allow_burst(NonZeroU32::new(100u32).unwrap()),
    );
    loop {
        let mut bts = UP_CHANNEL.1.recv_async().await.unwrap().to_vec();
        mangle_dns_up(&mut bts);
        // ACK decimation
        if ack_decimate(&bts).is_some() && limiter.check().is_err() {
            log::trace!("doing ack decimation!");
        } else {
            let mangled_msg = nat.mangle_upstream_pkt(&bts);

            if let Some(body) = mangled_msg {
                TUNNEL.send_vpn(body).await?
            };
        }
    }
}

static FAKE_DNS_SERVER: AtomicU32 = AtomicU32::new(0);
static REAL_DNS_SERVER: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

fn mangle_dns_up(pkt: &mut [u8]) {
    let pkt_dest: Option<Ipv4Addr> =
        pnet_packet::ipv4::Ipv4Packet::new(pkt).map(|parsed| parsed.get_destination());
    if let Some(_pkt_dest) = pkt_dest {
        let mut mangled = false;
        if let Some(mut ip_pkt) = pnet_packet::ipv4::MutableIpv4Packet::new(pkt) {
            if let Some(udp_pkt) = pnet_packet::udp::MutableUdpPacket::new(ip_pkt.payload_mut()) {
                if udp_pkt.get_destination() == 53 {
                    mangled = true;
                }
            }
            if mangled {
                FAKE_DNS_SERVER.store(ip_pkt.get_destination().into(), Ordering::SeqCst);
                ip_pkt.set_destination(REAL_DNS_SERVER);
            }
        }
        if mangled {
            fix_all_checksums(pkt);
        }
    }
}

fn mangle_dns_dn(pkt: &mut [u8]) {
    let mut mangled = false;
    if let Some(mut ip_pkt) = pnet_packet::ipv4::MutableIpv4Packet::new(pkt) {
        if let Some(udp_pkt) = pnet_packet::udp::MutableUdpPacket::new(ip_pkt.payload_mut()) {
            if udp_pkt.get_source() == 53 {
                mangled = true;
            }
        }
        if mangled {
            ip_pkt.set_source(FAKE_DNS_SERVER.load(Ordering::SeqCst).into())
        }
    }
    if mangled {
        fix_all_checksums(pkt);
    }
}

fn fix_all_checksums(bts: &mut [u8]) -> Option<()> {
    let mut ip_layer = pnet_packet::ipv4::MutableIpv4Packet::new(bts)?;
    let source = ip_layer.get_source();
    let destination = ip_layer.get_destination();
    // match on UDP vs TCP
    match ip_layer.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            // extract the payload and modify its checksum too
            let mut tcp_layer = pnet_packet::tcp::MutableTcpPacket::new(ip_layer.payload_mut())?;
            let tcp_checksum =
                pnet_packet::tcp::ipv4_checksum(&tcp_layer.to_immutable(), &source, &destination);
            tcp_layer.set_checksum(tcp_checksum)
        }
        IpNextHeaderProtocols::Udp => {
            // extract the payload and modify its checksum too
            let mut udp_layer = pnet_packet::udp::MutableUdpPacket::new(ip_layer.payload_mut())?;
            let udp_checksum =
                pnet_packet::udp::ipv4_checksum(&udp_layer.to_immutable(), &source, &destination);
            udp_layer.set_checksum(udp_checksum)
        }
        _ => (),
    }
    let ip_checksum = pnet_packet::ipv4::checksum(&ip_layer.to_immutable());
    ip_layer.set_checksum(ip_checksum);
    Some(())
}

/// Down loop for vpn
async fn vpn_down_loop(nat: Arc<GephNat>) -> anyhow::Result<()> {
    loop {
        let incoming = TUNNEL.recv_vpn().await.context("downstream failed")?;
        let mangled_incoming = nat.mangle_downstream_pkt(&incoming);
        if let Some(mangled_bts) = mangled_incoming {
            let mut mangled_bts = mangled_bts.to_vec();
            mangle_dns_dn(&mut mangled_bts);
            let _ = DOWN_CHANNEL.0.try_send(mangled_bts.into());
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
