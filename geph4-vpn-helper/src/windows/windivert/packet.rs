use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::{iter::once, mem::MaybeUninit};

use super::{bindings, Handle, InternalError, Layer};

pub struct PacketHandle {
    handle: Handle,
}

static LAST_RECV_ADDR: Lazy<Mutex<Option<bindings::WINDIVERT_ADDRESS>>> =
    Lazy::new(|| Mutex::new(None));

impl PacketHandle {
    pub fn open(filter: &str, priority: i16) -> Result<Self, InternalError> {
        let flag: u32 = 0;
        Ok(Self {
            handle: Handle::open(filter, Layer::Network, priority, flag as _)?,
        })
    }

    pub fn receive(&self) -> Result<Vec<u8>, InternalError> {
        let mut packet: Vec<u8> = vec![0; 1500];
        let mut addr: MaybeUninit<bindings::WINDIVERT_ADDRESS> = MaybeUninit::uninit();
        let packet_len = self.handle.receive(Some(&mut packet), Some(&mut addr))?;
        let addr = unsafe { addr.assume_init() };
        packet.truncate(packet_len);
        *LAST_RECV_ADDR.lock() = Some(addr);
        Ok(packet)
    }

    pub fn inject(&self, packet: &[u8], is_outbound: bool) -> Result<(), InternalError> {
        if let Some(mut addr) = LAST_RECV_ADDR.lock().clone() {
            addr.set_Outbound(is_outbound as _);
            // addr.set_Impostor(1);
            // addr.set_IPChecksum(1);
            // addr.set_TCPChecksum(1);
            // addr.set_UDPChecksum(1);
            self.handle.send(packet, addr)?;
            // println!("injecting a packet of length {}", packet.len());
        }
        Ok(())
    }
}
