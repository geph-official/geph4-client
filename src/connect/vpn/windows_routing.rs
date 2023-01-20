use crate::config::CacheStaleGuard;
use crate::connect::tunnel::TunnelStatus;
use dashmap::DashSet;
use once_cell::sync::Lazy;
use pnet_packet::{ip::IpNextHeaderProtocols, MutablePacket};
use std::net::{IpAddr, Ipv4Addr};
use std::{
    convert::Infallible,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use crate::connect::{vpn::vpn_upload, TUNNEL, TUNNEL_STATUS_CALLBACK};

use super::vpn_download_blocking;

mod windivert;

static GEPH_OWN_ADDRS: Lazy<DashSet<IpAddr>> = Lazy::new(DashSet::new);

pub fn start_routing() -> Infallible {
    *TUNNEL_STATUS_CALLBACK.write() = Box::new(move |addr| {
        if let TunnelStatus::PreConnect { addr, protocol: _ } = addr {
            let addr = addr.ip();
            log::debug!("adding {addr} to the whitelist");
            GEPH_OWN_ADDRS.insert(addr);
        }
    });

    while !TUNNEL.status().connected() {
        log::debug!("waiting for tunnel to connect first...");
        std::thread::sleep(Duration::from_secs(1));
    }

    let _stale_guard = CacheStaleGuard::new();

    std::thread::spawn(upload_loop);
    download_loop()
}

static FAKE_DNS_SERVER: AtomicU32 = AtomicU32::new(0);
static REAL_DNS_SERVER: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

fn download_loop() -> Infallible {
    let handle = windivert::PacketHandle::open("false", -200).unwrap();
    loop {
        let mut pkt = vpn_download_blocking().to_vec();
        let mut mangled = false;
        if let Some(mut ip_pkt) = pnet_packet::ipv4::MutableIpv4Packet::new(&mut pkt) {
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
            fix_all_checksums(&mut pkt);
        }
        handle.inject(&pkt, false).expect("cannot inject");
    }
}

fn upload_loop() {
    let handle = windivert::PacketHandle::open("outbound and not loopback", -100).unwrap();
    loop {
        let pkt = handle.receive();
        match pkt {
            Ok(mut pkt) => {
                let pkt_dest: Option<Ipv4Addr> =
                    pnet_packet::ipv4::Ipv4Packet::new(&pkt).map(|parsed| parsed.get_destination());
                if let Some(pkt_dest) = pkt_dest {
                    let pkt_dest: IpAddr = pkt_dest.into();
                    let is_geph = GEPH_OWN_ADDRS.contains(&pkt_dest);
                    if is_geph {
                        // merely reinject
                        handle.inject(&pkt, true).expect("cannot inject");
                    } else {
                        // mangle the dns to 1.1.1.1
                        let mut mangled = false;
                        if let Some(mut ip_pkt) =
                            pnet_packet::ipv4::MutableIpv4Packet::new(&mut pkt)
                        {
                            if let Some(udp_pkt) =
                                pnet_packet::udp::MutableUdpPacket::new(ip_pkt.payload_mut())
                            {
                                if udp_pkt.get_destination() == 53 {
                                    mangled = true;
                                }
                            }
                            if mangled {
                                FAKE_DNS_SERVER
                                    .store(ip_pkt.get_destination().into(), Ordering::SeqCst);
                                ip_pkt.set_destination(REAL_DNS_SERVER);
                            }
                        }
                        if mangled {
                            fix_all_checksums(&mut pkt);
                        }
                        // pass to geph
                        vpn_upload(pkt.into());
                    }
                }
            }
            Err(err) => {
                log::error!("windivert error: {:?}", err);
                std::thread::sleep(Duration::from_secs(1));
            }
        }
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
