use std::{collections::HashMap, io::Stdin, num::NonZeroU32, sync::Arc, time::Duration};

use async_net::Ipv4Addr;
use bytes::Bytes;
use governor::Quota;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use pnet_packet::{
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    tcp::{TcpFlags, TcpPacket},
    udp::MutableUdpPacket,
    udp::UdpPacket,
    Packet,
};
use smol_timeout::TimeoutExt;
use vpn_structs::StdioMsg;

use crate::stats::StatCollector;

/// runs a vpn session
pub async fn run_vpn(
    stats: Arc<StatCollector>,
    mux: Arc<sosistab::mux::Multiplex>,
) -> anyhow::Result<()> {
    static STDIN: Lazy<async_dup::Arc<async_dup::Mutex<smol::Unblock<Stdin>>>> = Lazy::new(|| {
        async_dup::Arc::new(async_dup::Mutex::new(smol::Unblock::with_capacity(
            1024 * 1024,
            std::io::stdin(),
        )))
    });
    let mut stdin = STDIN.clone();
    // first we negotiate the vpn
    let client_id: u128 = rand::random();
    log::info!("negotiating VPN with client id {}...", client_id);
    let client_ip = loop {
        let hello = vpn_structs::Message::ClientHello { client_id };
        mux.send_urel(bincode::serialize(&hello)?.into()).await?;
        let resp = mux.recv_urel().timeout(Duration::from_secs(1)).await;
        if let Some(resp) = resp {
            let resp = resp?;
            let resp: vpn_structs::Message = bincode::deserialize(&resp)?;
            match resp {
                vpn_structs::Message::ServerHello { client_ip, .. } => break client_ip,
                _ => continue,
            }
        }
    };
    log::info!("negotiated IP address {}!", client_ip);
    let msg = StdioMsg {
        verb: 1,
        body: format!("{}/10", client_ip).as_bytes().to_vec().into(),
    };
    {
        use std::io::Write;
        let mut stdout = std::io::stdout();
        msg.write_blocking(&mut stdout)?;
        stdout.flush()?;
    }

    // a mini-nat for DNS request
    let dns_nat = RwLock::new(HashMap::new());
    let vpn_up_fut = {
        let mux = mux.clone();
        let stats = stats.clone();
        let dns_nat = &dns_nat;
        async move {
            let ack_rate_limits: Vec<_> = (0..16)
                .map(|_| {
                    governor::RateLimiter::direct(Quota::per_second(
                        NonZeroU32::new(500u32).unwrap(),
                    ))
                })
                .collect();
            loop {
                let msg = StdioMsg::read(&mut stdin).await?;
                // ACK decimation
                if let Some(hash) = ack_decimate(&msg.body) {
                    let limiter = &(ack_rate_limits[(hash % 16) as usize]);
                    if limiter.check().is_err() {
                        continue;
                    }
                }
                // fix dns
                let body = if let Some(body) = fix_dns_dest(&msg.body, dns_nat) {
                    body
                } else {
                    msg.body
                };
                stats.incr_total_tx(body.len() as u64);
                drop(
                    mux.send_urel(
                        bincode::serialize(&vpn_structs::Message::Payload(body))
                            .unwrap()
                            .into(),
                    )
                    .await,
                );
            }
        }
    };
    let vpn_down_fut = {
        let stats = stats.clone();
        let dns_nat = &dns_nat;
        async move {
            for count in 0u64.. {
                if count % 1000 == 1 {
                    let sess_stats = mux.get_session().latest_stat().unwrap();
                    log::debug!(
                        "VPN received {} pkts; ping {} ms, loss {}%",
                        count,
                        sess_stats.ping.as_millis(),
                        sess_stats.total_loss * 100.0,
                    );
                }
                let bts = mux.recv_urel().await?;
                if let vpn_structs::Message::Payload(bts) = bincode::deserialize(&bts)? {
                    stats.incr_total_rx(bts.len() as u64);
                    let bts = if let Some(bts) = fix_dns_src(&bts, dns_nat) {
                        bts
                    } else {
                        bts
                    };
                    let msg = StdioMsg { verb: 0, body: bts };
                    {
                        use std::io::Write;
                        let mut stdout = std::io::stdout();
                        msg.write_blocking(&mut stdout)?;
                        stdout.flush()?;
                    }
                }
            }
            unreachable!()
        }
    };
    smol::future::race(vpn_up_fut, vpn_down_fut).await
}

/// returns ok if it's an ack that needs to be decimated
fn ack_decimate(bts: &[u8]) -> Option<u16> {
    let parsed = Ipv4Packet::new(bts)?;
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
    let mut vv = bts.to_vec();
    let mut parsed = MutableIpv4Packet::new(&mut vv)?;
    nat.write().insert(dns_src_port, parsed.get_destination());
    parsed.set_destination(Ipv4Addr::new(74, 82, 42, 42));
    fix_all_checksums(&mut vv)?;
    Some(vv.into())
}

fn fix_all_checksums(bts: &mut [u8]) -> Option<()> {
    let mut ip_layer = MutableIpv4Packet::new(bts)?;
    let mut udp_raw = ip_layer.payload().to_vec();
    {
        let mut udp_layer = MutableUdpPacket::new(&mut udp_raw)?;
        let source = ip_layer.get_source();
        let dest = ip_layer.get_destination();
        let udp_checksum =
            pnet_packet::udp::ipv4_checksum(&udp_layer.to_immutable(), &source, &dest);
        udp_layer.set_checksum(udp_checksum);
    }
    ip_layer.set_payload(&udp_raw);
    let ip_checksum = pnet_packet::ipv4::checksum(&ip_layer.to_immutable());
    ip_layer.set_checksum(ip_checksum);
    Some(())
}

/// fixes dns source
fn fix_dns_src(bts: &[u8], nat: &RwLock<HashMap<u16, Ipv4Addr>>) -> Option<Bytes> {
    let dns_src_port = {
        let parsed = Ipv4Packet::new(bts)?;
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
    let mut vv = bts.to_vec();
    let mut parsed = MutableIpv4Packet::new(&mut vv)?;
    parsed.set_source(*nat.read().get(&dns_src_port)?);
    fix_all_checksums(&mut vv)?;
    Some(vv.into())
}
