use std::{io::Stdin, io::Write, num::NonZeroU32, sync::Arc};

use anyhow::Context;
use async_net::Ipv4Addr;

use bytes::Bytes;
use geph4_protocol::{tunnel::ClientTunnel, VpnMessage, VpnStdio};
use geph_nat::GephNat;
use governor::{Quota, RateLimiter};
use once_cell::sync::{Lazy, OnceCell};
use pnet_packet::{
    ipv4::Ipv4Packet,
    tcp::{TcpFlags, TcpPacket},
    Packet,
};
use smol::{channel::Receiver, prelude::*};

/// The fd passed to us by the helper. This actually does work even though in general Async<File> does not, because tundevice FDs are not like file FDs.
pub static VPN_FD: OnceCell<smol::Async<std::fs::File>> = OnceCell::new();

// Up and down channels for iOS
pub static UP_CHANNEL: Lazy<(flume::Sender<Bytes>, flume::Receiver<Bytes>)> =
    Lazy::new(|| flume::bounded(100));
pub static DOWN_CHANNEL: Lazy<(flume::Sender<Bytes>, flume::Receiver<Bytes>)> =
    Lazy::new(|| flume::bounded(100));

#[derive(Clone)]
struct VpnContext {
    vpn: Arc<ClientTunnel>,
    nat: Arc<GephNat>,
}

pub const NAT_TABLE_SIZE: usize = 10000; // max size of the NAT table

/// Runs a vpn session
pub async fn run_vpn(vpn: Arc<ClientTunnel>) -> anyhow::Result<()> {
    let nat = GephNat::new(
        NAT_TABLE_SIZE,
        vpn.get_vpn_client_ip().context("no vpn client ip")?,
    );
    let ctx = VpnContext {
        vpn: vpn.clone(),
        nat: Arc::new(nat),
    };
    vpn_up_loop(ctx.clone()).or(vpn_down_loop(ctx)).await
}

/// Up loop for vpn
async fn vpn_up_loop(ctx: VpnContext) -> anyhow::Result<()> {
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
            let mangled_msg = ctx.nat.mangle_upstream_pkt(&bts);

            if let Some(body) = mangled_msg {
                ctx.vpn.send_vpn(VpnMessage::Payload(body)).await? // will this question mark make the whole function return if something fails?
            };
        }
    }
}

/// Down loop for vpn
async fn vpn_down_loop(ctx: VpnContext) -> anyhow::Result<()> {
    let mut count = 0u64;
    loop {
        let incoming = ctx.vpn.recv_vpn().await.context("downstream failed")?;
        count += 1;
        if count % 1000 == 1 {
            log::debug!("VPN received {} pkts ", count);
        }
        if let geph4_protocol::VpnMessage::Payload(bts) = incoming {
            let mangled_incoming = ctx.nat.mangle_downstream_pkt(&bts);
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

/// Vpn stdio
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
