#[cfg(target_os = "linux")]
mod linux_routing;

use std::{
    convert::Infallible,
    io::{Read, Write},
    num::NonZeroU32,
    sync::Arc,
    thread::JoinHandle,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::prelude::{AsRawFd, FromRawFd};

use anyhow::Context;

use bytes::Bytes;
use geph4_protocol::VpnMessage;
use geph_nat::GephNat;
use governor::{Quota, RateLimiter};
use once_cell::sync::Lazy;
use pnet_packet::{
    ipv4::Ipv4Packet,
    tcp::{TcpFlags, TcpPacket},
    Packet,
};
use smol::prelude::*;

use crate::config::VpnMode;

use super::{CONNECT_CONFIG, TUNNEL};

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
                let mut bts = [0u8; 2048];
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
                let bts = smol::future::block_on(vpn_download());
                log::trace!("vpn dn {}", bts.len());
                #[cfg(target_os = "macos")]
                {
                    let mut buf = [0u8; 4096];
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
                Some(VpnMode::InheritedFd) => {
                    // Read the file-descriptor number from an environment variable
                    let fd_num: i32 = std::env::var("GEPH_VPN_FD")
                    .ok()
                    .and_then(|e| e.parse().ok())
                    .expect(
                    "must set GEPH_VPN_FD to a file descriptor in order to use inherited-fd mode",
                );
                    #[cfg(unix)]
                    {
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
                                ::tun::Configuration::default().mtu(1280).up(),
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
                                .mtu(1280)
                                .up(),
                        )
                        .expect("could not initialize TUN device");
                        if CONNECT_CONFIG.vpn_mode == Some(VpnMode::TunRoute) {
                            #[cfg(target_os = "linux")]
                            {
                                linux_routing::setup_routing();
                            }
                            #[cfg(not(target_os = "linux"))]
                            {
                                panic!("cannot use tun-route on non-Linux, just yet")
                            }
                        }
                        unsafe { fd_vpn_loop(device.as_raw_fd()) }
                    }
                    #[cfg(not(unix))]
                    {
                        panic!("cannot use tun modes on non-Unix systems")
                    }
                }
                None => {
                    log::info!("not starting VPN mode");
                    loop {
                        std::thread::park()
                    }
                }
                _ => unimplemented!(),
            }
        })
        .unwrap()
});

/// Uploads a packet through the global VPN
pub fn vpn_upload(pkt: Bytes) {
    Lazy::force(&VPN_TASK);
    let _ = UP_CHANNEL.0.try_send(pkt);
}

/// Downloads a packet through the global VPN
pub async fn vpn_download() -> Bytes {
    Lazy::force(&VPN_TASK);
    DOWN_CHANNEL.1.recv_async().await.unwrap()
}

// Up and down channels
static UP_CHANNEL: Lazy<(flume::Sender<Bytes>, flume::Receiver<Bytes>)> =
    Lazy::new(|| flume::bounded(100));
static DOWN_CHANNEL: Lazy<(flume::Sender<Bytes>, flume::Receiver<Bytes>)> =
    Lazy::new(|| flume::bounded(100));

static VPN_TASK: Lazy<smol::Task<Infallible>> = Lazy::new(|| {
    smolscale::spawn(async {
        loop {
            let init_ip = TUNNEL.get_vpn_client_ip().await;
            let nat = Arc::new(GephNat::new(
                NAT_TABLE_SIZE,
                TUNNEL.get_vpn_client_ip().await,
            ));
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
});

const NAT_TABLE_SIZE: usize = 10000; // max size of the NAT table

/// Up loop for vpn
async fn vpn_up_loop(nat: Arc<GephNat>) -> anyhow::Result<()> {
    let limiter = RateLimiter::direct(
        Quota::per_second(NonZeroU32::new(500u32).unwrap())
            .allow_burst(NonZeroU32::new(100u32).unwrap()),
    );
    loop {
        let bts = UP_CHANNEL.1.recv_async().await.unwrap();
        // ACK decimation
        if ack_decimate(&bts).is_some() && limiter.check().is_err() {
            log::trace!("doing ack decimation!");
        } else {
            let mangled_msg = nat.mangle_upstream_pkt(&bts);

            if let Some(body) = mangled_msg {
                TUNNEL.send_vpn(VpnMessage::Payload(body)).await? // will this question mark make the whole function return if something fails?
            };
        }
    }
}

/// Down loop for vpn
async fn vpn_down_loop(nat: Arc<GephNat>) -> anyhow::Result<()> {
    let mut count = 0u64;
    loop {
        let incoming = TUNNEL.recv_vpn().await.context("downstream failed")?;
        count += 1;
        if count % 1000 == 1 {
            log::debug!("VPN received {} pkts ", count);
        }
        if let geph4_protocol::VpnMessage::Payload(bts) = incoming {
            let mangled_incoming = nat.mangle_downstream_pkt(&bts);
            if let Some(mangled_bts) = mangled_incoming {
                let _ = DOWN_CHANNEL.0.try_send(mangled_bts);
            } else {
                let _ = DOWN_CHANNEL.0.try_send(bts);
            }
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
