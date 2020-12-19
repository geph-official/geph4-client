use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::{
    collections::BTreeMap,
    io::Stdin,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::{ChildStdin, ChildStdout, Stdio},
    sync::Arc,
};
use vpn_structs::StdioMsg;
mod windivert;
use defmac::defmac;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::{ipv4::*, ipv6::*};
use pnet_packet::{MutablePacket, Packet};
use std::io::prelude::*;
use std::time::{Duration, Instant};

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
        self.mapping
            .write()
            .insert((local_port, protocol), process_id);
    }

    /// Returns the process ID associated with this address and protocol. Returns None if no such process exists.
    pub fn get(&self, local_addr: SocketAddr, protocol: Prot) -> Option<u32> {
        let start_time = Instant::now();
        loop {
            let toret = self
                .mapping
                .read()
                .get(&(local_addr.port(), protocol))
                .cloned();
            if toret.is_none() && start_time.elapsed().as_micros() < 10000 {
                std::thread::sleep(Duration::from_micros(1000));
                continue;
            } else {
                return toret;
            }
        }
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

    // spin up a thread to handle flow information
    // std::thread::spawn(flow_loop);
    // spin up another thread to handle socket information
    std::thread::spawn(socket_loop);

    std::thread::spawn(|| download_loop(geph_stdout));

    // main loop handles packets
    upload_loop(geph_pid, child.stdin.unwrap())
}

fn download_loop(mut geph_stdout: ChildStdout) {
    let handle = windivert::PacketHandle::open("false", 0).unwrap();
    loop {
        // read a message from Geph
        let msg = StdioMsg::read_blocking(&mut geph_stdout).unwrap();
        match msg.verb {
            0 => {
                let mut packet = msg.body.to_vec();

                if fix_destination(&mut packet) {
                    handle.inject(&packet, false).unwrap();
                }
            }
            _ => {
                // format of body is a.b.c.d/netmask
                let ip_with_mask = String::from_utf8_lossy(&msg.body);
                let ip_string = ip_with_mask.split('/').next().unwrap();
                let actual_ip: Ipv4Addr = ip_string.parse().unwrap();
                // println!("Geph assigned us GEPH_IP = {}", actual_ip);
                *GEPH_IP.write() = Some(actual_ip);
            }
        }
    }
}

fn upload_loop(geph_pid: u32, mut geph_stdin: ChildStdin) {
    let handle = windivert::PacketHandle::open("outbound and not loopback", 0).unwrap();
    loop {
        let pkt = handle.receive();
        if let Ok(mut pkt) = pkt {
            // println!("received outbound of length {}", pkt.len());
            let pkt_addrs = get_packet_addrs(&pkt);

            if let Some((pkt_addrs, prot)) = pkt_addrs {
                let process_id = GLOBAL_TABLE.get(pkt_addrs.source_addr, prot);
                // println!(
                //     "outgoing packet to {} of length {} has process_id = {:?}",
                //     pkt_addrs.destination_addr,
                //     pkt.len(),
                //     process_id
                // );
                if let Some(pid) = process_id {
                    if pid == geph_pid {
                        handle.inject(&pkt, true).unwrap();
                        continue;
                    }
                }
                let packet_source: Option<Ipv4Addr> =
                    pnet_packet::ipv4::Ipv4Packet::new(&pkt).map(|parsed| parsed.get_source());
                if let Some(packet_source) = packet_source {
                    // println!("setting REAL_IP = {}", packet_source);
                    *REAL_IP.write() = Some(packet_source);
                }

                if fix_source(&mut pkt) {
                    let msg = StdioMsg {
                        verb: 0,
                        body: pkt.into(),
                    };
                    msg.write_blocking(&mut geph_stdin).unwrap();
                    geph_stdin.flush().unwrap();
                }
            }
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
