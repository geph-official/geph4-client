use async_net::Ipv4Addr;
use bytes::Bytes;

use governor::{Quota, RateLimiter};
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
use smol::{channel::Receiver, prelude::*};
use smol_timeout::TimeoutExt;
use sosistab::mux::Multiplex;
use std::{collections::HashMap, io::Stdin, num::NonZeroU32, sync::Arc, time::Duration};
use vpn_structs::StdioMsg;

use crate::stats::StatCollector;
use std::io::Write;

#[derive(Clone, Copy)]
struct VpnContext<'a> {
    mux: &'a Multiplex,
    stats: &'a StatCollector,
    dns_nat: &'a RwLock<HashMap<u16, Ipv4Addr>>,
}

/// runs a vpn session
pub async fn run_vpn(
    stats: Arc<StatCollector>,
    mux: Arc<sosistab::mux::Multiplex>,
) -> anyhow::Result<()> {
    // first we negotiate the vpn
    let client_id: u128 = rand::random();
    log::info!("negotiating VPN with client id {}...", client_id);
    let client_ip = loop {
        let hello = vpn_structs::Message::ClientHello { client_id };
        mux.send_urel(bincode::serialize(&hello)?.into())?;
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
        let mut stdout = std::io::stdout();
        msg.write_blocking(&mut stdout).unwrap();
        stdout.flush().unwrap();
    }

    // a mini-nat for DNS request
    let dns_nat = RwLock::new(HashMap::new());
    let ctx = VpnContext {
        mux: &mux,
        stats: &stats,
        dns_nat: &dns_nat,
    };
    vpn_up_loop(ctx).or(vpn_down_loop(ctx)).await
}

/// up loop for vpn
async fn vpn_up_loop(ctx: VpnContext<'_>) -> anyhow::Result<()> {
    let limiter = RateLimiter::direct(Quota::per_second(NonZeroU32::new(500u32).unwrap()));
    loop {
        let stdin_fut = async {
            let msg = STDIN.recv().await;
            // ACK decimation
            if ack_decimate(&msg.body).is_some() && limiter.check().is_err() {
                Ok(None)
            } else {
                // fix dns
                let body = if let Some(body) = fix_dns_dest(&msg.body, ctx.dns_nat) {
                    body
                } else {
                    msg.body
                };
                Ok::<Option<Bytes>, anyhow::Error>(Some(body))
            }
        };
        let body = stdin_fut.await?;
        if let Some(body) = body {
            ctx.stats.incr_total_tx(body.len() as u64);
            drop(
                ctx.mux.send_urel(
                    bincode::serialize(&vpn_structs::Message::Payload(body))
                        .unwrap()
                        .into(),
                ),
            );
        }
    }
}

/// down loop for vpn
async fn vpn_down_loop(ctx: VpnContext<'_>) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout();
    let mut count = 0u64;
    let mut buff = Vec::with_capacity(32768);
    loop {
        buff.clear();
        let mut batch = Vec::with_capacity(64);
        batch.push(ctx.mux.recv_urel().await?);
        while let Ok(val) = ctx.mux.try_recv_urel() {
            batch.push(val);
        }
        // buffer
        let bsize = batch.len();
        for bts in batch {
            count += 1;
            if count % 1000 == 1 {
                let sess_stats = ctx.mux.get_session().latest_stat();
                if let Some(sess_stats) = sess_stats {
                    log::debug!(
                        "VPN received {} pkts (bsize={}); ping {} ms, loss {:.2}%",
                        count,
                        bsize,
                        sess_stats.ping.as_millis(),
                        sess_stats.total_loss * 100.0,
                    );
                }
            }
            if let vpn_structs::Message::Payload(bts) = bincode::deserialize(&bts)? {
                ctx.stats.incr_total_rx(bts.len() as u64);
                let bts = if let Some(bts) = fix_dns_src(&bts, ctx.dns_nat) {
                    bts
                } else {
                    bts
                };
                let msg = StdioMsg { verb: 0, body: bts };
                {
                    msg.write_blocking(&mut buff).unwrap();
                }
            }
        }
        {
            stdout.write_all(&buff).unwrap();
            stdout.flush().unwrap();
        }
    }
}

// /// returns ok if it's an ack that needs to be decimated
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
    parsed.set_destination(Ipv4Addr::new(1, 1, 1, 1));
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
    let mut vv = bts.to_vec();
    let mut parsed = MutableIpv4Packet::new(&mut vv)?;
    parsed.set_source(*nat.read().get(&dns_src_port)?);
    fix_all_checksums(&mut vv)?;
    Some(vv.into())
}

pub static STDIN: Lazy<AtomicStdin> = Lazy::new(AtomicStdin::new);

/// A type that wraps stdin and provides atomic packet recv operations to prevent cancellations from messing things up.
pub struct AtomicStdin {
    incoming: Receiver<StdioMsg>,
    _task: smol::Task<Option<()>>,
}

impl AtomicStdin {
    fn new() -> Self {
        static STDIN: Lazy<async_dup::Arc<async_dup::Mutex<smol::Unblock<Stdin>>>> =
            Lazy::new(|| {
                async_dup::Arc::new(async_dup::Mutex::new(smol::Unblock::with_capacity(
                    1024 * 1024,
                    std::io::stdin(),
                )))
            });
        let (send_incoming, incoming) = smol::channel::bounded(1000);
        let _task = smolscale::spawn(async move {
            let mut stdin = STDIN.clone();
            loop {
                let msg = StdioMsg::read(&mut stdin).await.unwrap();
                let _ = send_incoming.try_send(msg);
            }
        });
        Self { incoming, _task }
    }

    async fn recv(&self) -> StdioMsg {
        self.incoming.recv().await.unwrap()
    }
}
