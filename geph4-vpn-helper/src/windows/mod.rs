use once_cell::sync::Lazy;
use parking_lot::{RwLock, RwLockWriteGuard};
use std::{
    collections::BTreeMap,
    io::Stdin,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::{ChildStdin, ChildStdout, Stdio},
    sync::Arc,
};
use vpn_structs::StdioMsg;
mod windivert;
use crate::windows::windivert::InternalError;
use defmac::defmac;
use env_logger::Env;
use governor::{Quota, RateLimiter};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::{ipv4::*, ipv6::*};
use pnet_packet::{MutablePacket, Packet};
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::num::NonZeroU32;
use std::time::{Duration, Instant};
use sysinfo::{ProcessExt, SystemExt};

/// A log rate limiter
static LOG_LIMITER: Lazy<Box<dyn Fn() -> bool + 'static + Send + Sync>> = Lazy::new(|| {
    let governor = RateLimiter::direct(Quota::per_second(NonZeroU32::new(10u32).unwrap()));
    Box::new(move || governor.check().is_ok())
});

/// A thread-safe process ID table.
#[derive(Clone, Debug, Default)]
struct ProcessTable {
    mapping: Arc<RwLock<BTreeMap<(u16, Prot), u32>>>,
}

impl ProcessTable {
    /// Adds an entry into the process table
    pub fn insert(&self, local_port: u16, protocol: Prot, process_id: u32) {
        if process_id == 4 {
            return;
        }
        let mut mapping = self.mapping.write();
        let exists = mapping.insert((local_port, protocol), process_id).is_some();
        // eprintln!("INSERT proc table with {}; {}", mapping.len(), exists);
        RwLockWriteGuard::unlock_fair(mapping);
    }

    /// Returns the process ID associated with this address and protocol. Returns None if no such process exists.
    pub fn get(&self, local_addr: SocketAddr, protocol: Prot) -> Option<u32> {
        self.mapping
            .read()
            .get(&(local_addr.port(), protocol))
            .cloned()
    }
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, PartialOrd, Ord, Debug)]
enum Prot {
    Tcp,
    Udp,
    Icmp,
}

static GLOBAL_TABLE: Lazy<ProcessTable> = Lazy::new(ProcessTable::default);

static GEPH_IP: Lazy<RwLock<Option<Ipv4Addr>>> = Lazy::new(|| RwLock::new(None));

static REAL_IP: Lazy<RwLock<Option<Ipv4Addr>>> = Lazy::new(|| RwLock::new(None));

pub fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("geph4_vpn_helper=debug,warn"))
        .init();
    std::thread::spawn(socket_loop);
    // sleep a little while to make sure we don't miss socket events
    std::thread::sleep(Duration::from_millis(300));
    // start child process
    let args: Vec<String> = std::env::args().collect();
    let child = std::process::Command::new(&args[1])
        .args(&args[2..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let geph_pid = child.id();
    let geph_stdout = child.stdout.unwrap();

    std::thread::spawn(|| download_loop(geph_stdout));

    // main loop handles packets
    upload_loop(child.stdin.unwrap())
}

fn download_loop(mut geph_stdout: ChildStdout) {
    let handle = windivert::PacketHandle::open("false", -200).unwrap();
    let mut geph_stdout = BufReader::with_capacity(1024 * 1024, geph_stdout);
    let (send, recv) = flume::unbounded();
    std::thread::spawn(move || loop {
        let mut batch = vec![recv.recv().unwrap()];
        while let Ok(v) = recv.try_recv() {
            batch.push(v);
            if batch.len() >= 200 {
                break;
            }
        }
        handle.inject_multi(&batch, false).unwrap();
        // thread_sleep(Duration::from_millis(5));
    });
    loop {
        // read a message from Geph
        let msg = StdioMsg::read_blocking(&mut geph_stdout).unwrap();
        match msg.verb {
            0 => {
                let mut packet = msg.body.to_vec();
                if LOG_LIMITER() {
                    log::debug!("Geph gave us packet of len {}", packet.len());
                }
                if fix_destination(&mut packet) {
                    send.send(packet).unwrap();
                }
            }
            _ => {
                // format of body is a.b.c.d/netmask
                let ip_with_mask = String::from_utf8_lossy(&msg.body);
                let ip_string = ip_with_mask.split('/').next().unwrap();
                let actual_ip: Ipv4Addr = ip_string.parse().unwrap();
                log::debug!("Geph assigned us GEPH_IP = {}", actual_ip);
                *GEPH_IP.write() = Some(actual_ip);
            }
        }
    }
}

static MIN_TIME_PERIOD: once_cell::sync::Lazy<winapi::shared::minwindef::UINT> =
    once_cell::sync::Lazy::new(|| unsafe {
        use std::mem;
        use winapi::um::{mmsystem::*, timeapi::timeGetDevCaps};

        let tc_size = mem::size_of::<TIMECAPS>() as u32;
        let mut tc = TIMECAPS {
            wPeriodMin: 0,
            wPeriodMax: 0,
        };

        if timeGetDevCaps(&mut tc as *mut TIMECAPS, tc_size) == TIMERR_NOERROR {
            tc.wPeriodMin
        } else {
            1
        }
    });

pub(crate) fn thread_sleep(duration: Duration) {
    unsafe {
        use winapi::um::timeapi::{timeBeginPeriod, timeEndPeriod};
        timeBeginPeriod(*MIN_TIME_PERIOD);
        std::thread::sleep(duration);
        timeEndPeriod(*MIN_TIME_PERIOD);
    }
}

#[cached::proc_macro::cached(time = 10)]
fn is_geph_pid(pid: u32) -> bool {
    static SYSTEM: Lazy<RwLock<sysinfo::System>> = Lazy::new(Default::default);
    dbg!(pid);
    SYSTEM.write().refresh_all();
    SYSTEM
        .read()
        .get_process(pid as usize)
        .map(|proc| dbg!(proc.exe().file_name().unwrap().to_string_lossy()) == "geph4-client.exe")
        .unwrap_or_default()
}

fn upload_loop(mut geph_stdin: ChildStdin) {
    let (send, recv) = flume::unbounded::<(Vec<u8>, Instant)>();
    let mut geph_stdin = BufWriter::with_capacity(1024 * 1024, geph_stdin);
    std::thread::spawn(move || {
        let handle = windivert::PacketHandle::open("false", -100).unwrap();
        loop {
            // we collect a vector of bytevectors
            let mut items = Vec::with_capacity(16);
            items.push(recv.recv().unwrap());
            while let Ok(item) = recv.try_recv() {
                items.push(item);
            }
            // if items.len() > 1 {
            //     eprintln!("upload {} items", items.len());
            // }
            let mut to_inject = Vec::with_capacity(items.len());
            for (mut pkt, time) in items {
                // println!("received outbound of length {}", pkt.len());
                let pkt_addrs = get_packet_addrs(&pkt);

                if let Some((pkt_addrs, prot)) = pkt_addrs {
                    let mut loop_iter = 0;
                    let process_id = loop {
                        let process_id = GLOBAL_TABLE.get(pkt_addrs.source_addr, prot);
                        if process_id.is_some() || time <= Instant::now() || prot == Prot::Icmp {
                            break process_id;
                        }
                        loop_iter += 1;
                        thread_sleep(Duration::from_millis(1));
                    };
                    if let Some(pid) = process_id {
                        let is_dns = pkt_addrs.destination_addr.port() == 53;
                        if is_geph_pid(pid) || (is_local_dest(&pkt) && !is_dns) {
                            to_inject.push(pkt);
                            continue;
                        }
                    }
                    let packet_source: Option<Ipv4Addr> =
                        pnet_packet::ipv4::Ipv4Packet::new(&pkt).map(|parsed| parsed.get_source());
                    if let Some(packet_source) = packet_source {
                        *REAL_IP.write() = Some(packet_source);
                    }

                    if fix_source(&mut pkt) {
                        if pkt.len() > 1280 {
                            log::debug!(
                                "dropping upstream way-too-big packet (src={:?}, prot={:?})",
                                packet_source,
                                prot
                            );
                            continue;
                        }
                        if LOG_LIMITER() {
                            log::debug!("stuffing non-Geph packet of length {}", pkt.len());
                        }
                        let msg = StdioMsg {
                            verb: 0,
                            body: pkt.into(),
                        };
                        let now = Instant::now();
                        msg.write_blocking(&mut geph_stdin).unwrap();
                    }
                }
            }
            if !to_inject.is_empty() {
                handle.inject_multi(&to_inject, true).unwrap();
            }
            geph_stdin.flush().unwrap();
            // thread_sleep(Duration::from_millis(1));
        }
    });
    let mut handle = windivert::PacketHandle::open("outbound and not loopback", 0).unwrap();
    loop {
        let pkt = handle.receive();
        match pkt {
            Ok(pkt) => {
                send.send((pkt, Instant::now() + Duration::from_millis(5)))
                    .unwrap();
            }
            Err(InternalError(122)) => eprintln!("dropping way-too-big packet"),
            Err(e) => panic!("{}", e),
        }
    }
}

/// loop that handles socket information for TCP
fn socket_loop() {
    let mut handle = windivert::SocketHandle::open("tcp or udp and not loopback", 0).unwrap();
    loop {
        let evt = handle.receive().unwrap();
        if evt.kind == windivert::SocketEvtType::Bind && evt.process_id != 4 {
            // println!(
            //     "capturing an outbound connection attempt from {} with process id {}",
            //     evt.local_addr, evt.process_id
            // );

            let protocol = if evt.is_tcp { Prot::Tcp } else { Prot::Udp };
            GLOBAL_TABLE.insert(evt.local_addr.port(), protocol, evt.process_id);
        }
    }
}

fn is_local_dest(packet: &[u8]) -> bool {
    let parsed = pnet_packet::ipv4::Ipv4Packet::new(packet);
    if let Some(parsed) = parsed {
        let dest: Ipv4Addr = parsed.get_destination();
        if dest.is_broadcast() || dest.is_link_local() || dest.is_private() || dest.is_loopback() {
            return true;
        }
    }
    false
}

fn fix_destination(packet: &mut [u8]) -> bool {
    let parsed = pnet_packet::ipv4::MutableIpv4Packet::new(packet);
    if let Some(mut parsed) = parsed {
        if let Some(real) = *REAL_IP.read() {
            // println!("before fixing destination it is {:#?}", parsed);
            parsed.set_destination(real);
            fix_all_checksums(packet);
            return true;
        }
    }
    false
}

fn fix_source(packet: &mut [u8]) -> bool {
    let parsed = pnet_packet::ipv4::MutableIpv4Packet::new(packet);
    if let Some(mut parsed) = parsed {
        if let Some(geph) = *GEPH_IP.read() {
            parsed.set_source(geph);
            // println!("fixed source for {:#?} (geph is {})", parsed, geph);
            fix_all_checksums(packet);
            return true;
        }
    }
    false
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

fn get_packet_addrs(packet: &[u8]) -> Option<(PacketAddrs, Prot)> {
    let source_addr: IpAddr;
    let destination_addr: IpAddr;
    let source_port: u16;
    let destination_port: u16;
    let protocol: Prot;

    defmac!(get_ports parsed, payload_protocol => {
    if payload_protocol == pnet_packet::ip::IpNextHeaderProtocols::Tcp {
        let inner = pnet_packet::tcp::TcpPacket::new(parsed.payload())?;
        source_port = inner.get_source();
        destination_port = inner.get_destination();
        protocol = Prot::Tcp;
    } else if payload_protocol == pnet_packet::ip::IpNextHeaderProtocols::Udp {
        let inner = pnet_packet::udp::UdpPacket::new(parsed.payload())?;
        source_port = inner.get_source();
        destination_port = inner.get_destination();
        protocol = Prot::Udp;
    } else if payload_protocol == pnet_packet::ip::IpNextHeaderProtocols::Icmp {
        source_port = 0;
        destination_port = 0;
        protocol = Prot::Icmp;
    } else {
        return None;
    }});

    if is_ipv4(packet) {
        let parsed = Ipv4Packet::new(packet)?;
        source_addr = parsed.get_source().into();
        destination_addr = parsed.get_destination().into();
        let payload_protocol = parsed.get_next_level_protocol();

        get_ports!(parsed, payload_protocol);
    } else {
        let parsed = Ipv6Packet::new(packet)?;
        source_addr = parsed.get_source().into();
        destination_addr = parsed.get_destination().into();
        let payload_protocol = parsed.get_next_header();

        get_ports!(parsed, payload_protocol);
    }
    Some((
        PacketAddrs {
            source_addr: SocketAddr::new(source_addr, source_port),
            destination_addr: SocketAddr::new(destination_addr, destination_port),
        },
        protocol,
    ))
}

#[derive(Debug)]
struct PacketAddrs {
    source_addr: SocketAddr,
    destination_addr: SocketAddr,
}

fn is_ipv4(packet: &[u8]) -> bool {
    Ipv4Packet::new(packet).unwrap().get_version() == 4
}
