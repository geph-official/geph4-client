use std::{convert::Infallible, io::Stdin, io::Write, num::NonZeroU32, sync::Arc};

use anyhow::Context;
use async_net::Ipv4Addr;

use bytes::Bytes;
use geph4_protocol::{VpnMessage, VpnStdio};
use geph_nat::GephNat;
use governor::{Quota, RateLimiter};
use once_cell::sync::{Lazy, OnceCell};
use pnet_packet::{
    ipv4::Ipv4Packet,
    tcp::{TcpFlags, TcpPacket},
    Packet,
};
use smol::{channel::Receiver, prelude::*};

use super::TUNNEL;

/// Uploads a packet through the global VPN
pub fn vpn_upload(pkt: Bytes) {
    let _ = UP_CHANNEL.0.try_send(pkt);
}

/// Downloads a packet through the global VPN
pub async fn vpn_download() -> Bytes {
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
            let nat = Arc::new(GephNat::new(
                NAT_TABLE_SIZE,
                TUNNEL.get_vpn_client_ip().await,
            ));
            let res = vpn_up_loop(nat.clone()).or(vpn_down_loop(nat)).await;
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
