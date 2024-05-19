use crate::connect::ConnectContext;
use clone_macro::clone;
use dashmap::DashSet;
use once_cell::sync::Lazy;
use pnet_packet::{ip::IpNextHeaderProtocols, MutablePacket};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::{
    convert::Infallible,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

mod windivert;

static GEPH_OWN_ADDRS: Lazy<DashSet<IpAddr>> = Lazy::new(DashSet::new);

pub async fn start_routing(ctx: ConnectContext) -> anyhow::Result<()> {
    whitelist_once(&ctx).await?;
    let _bg_whitelist = smolscale::spawn(clone!([ctx], async move {
        loop {
            let _ = whitelist_once(&ctx).await;
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    }));

    // then wait for connection to become fully functional
    log::debug!("waiting for tunnel to become fully functional");
    ctx.tunnel.connect_stream("1.1.1.1:53").await?;

    let handle = Arc::new(windivert::PacketHandle::open(
        "outbound and not loopback",
        -100,
    )?);
    std::thread::spawn(clone!([ctx, handle], move || upload_loop(ctx, handle)));
    std::thread::spawn(clone!([ctx, handle], move || download_loop(ctx, handle)));
    smol::future::pending().await
}

async fn whitelist_once(ctx: &ConnectContext) -> anyhow::Result<()> {
    let bridge = ctx.conn_info.bridges().await?;
    for bridge in bridge {
        let addr = bridge.endpoint.ip();
        GEPH_OWN_ADDRS.insert(addr);
    }
    Ok(())
}

static FAKE_DNS_SERVER: AtomicU32 = AtomicU32::new(0);
static REAL_DNS_SERVER: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

fn download_loop(ctx: ConnectContext, handle: Arc<windivert::PacketHandle>) -> Infallible {
    loop {
        let mut pkt = smol::future::block_on(ctx.tunnel.recv_vpn())
            .unwrap()
            .to_vec();
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

fn upload_loop(ctx: ConnectContext, handle: Arc<windivert::PacketHandle>) {
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
                        let _ = smol::future::block_on(ctx.tunnel.send_vpn(&pkt));
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
