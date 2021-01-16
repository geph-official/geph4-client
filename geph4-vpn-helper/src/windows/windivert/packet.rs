use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::{iter::once, mem::MaybeUninit};

use super::{bindings, Handle, InternalError, Layer};
use std::collections::VecDeque;

pub struct PacketHandle {
    handle: Handle,
    buffer: VecDeque<Vec<u8>>,
}
//
// unsafe impl Sync for PacketHandle {}
//
// unsafe impl Send for PacketHandle {}

static LAST_RECV_ADDR: Lazy<Mutex<Option<bindings::WINDIVERT_ADDRESS>>> =
    Lazy::new(|| Mutex::new(None));

impl PacketHandle {
    pub fn open(filter: &str, priority: i16) -> Result<Self, InternalError> {
        let flag: u32 = 0;
        Ok(Self {
            handle: Handle::open(filter, Layer::Network, priority, flag as _)?,
            buffer: VecDeque::new(),
        })
    }

    pub fn receive(&mut self) -> Result<Vec<u8>, InternalError> {
        let mut packet: Vec<u8> = vec![0; 2048];
        let mut addr: MaybeUninit<bindings::WINDIVERT_ADDRESS> = MaybeUninit::uninit();
        let packet_len = self.handle.receive(Some(&mut packet), Some(&mut addr))?;
        let addr = unsafe { addr.assume_init() };
        packet.truncate(packet_len);
        *LAST_RECV_ADDR.lock() = Some(addr);
        Ok(packet)
    }

    pub fn inject(&self, packet: &[u8], is_outbound: bool) -> Result<(), InternalError> {
        if let Some(mut addr) = *LAST_RECV_ADDR.lock() {
            addr.set_Outbound(is_outbound as _);
            addr.set_Impostor(1);
            addr.set_IPChecksum(0);
            addr.set_TCPChecksum(0);
            addr.set_UDPChecksum(0);
            self.handle.send(packet, addr)?;
        // println!("injecting a packet of length {}", packet.len());
        } else {
            log::warn!("ignoring packet because we don't know how to inject");
        };
        Ok(())
    }

    pub fn inject_multi<P: AsRef<[u8]>>(
        &self,
        packets: &[P],
        is_outbound: bool,
    ) -> Result<(), InternalError> {
        if let Some(mut addr) = *LAST_RECV_ADDR.lock() {
            addr.set_Outbound(is_outbound as _);
            addr.set_Impostor(1);
            addr.set_IPChecksum(0);
            addr.set_TCPChecksum(0);
            addr.set_UDPChecksum(0);
            self.handle.send_multi(packets, addr)?;
        // println!("injecting a packet of length {}", packet.len());
        } else {
            log::warn!("ignoring packets because we don't know how to inject");
        };
        Ok(())
    }
}
