use super::{bindings, Handle, InternalError, Layer};
use std::convert::TryInto;
use std::{
    mem::MaybeUninit,
    net::{IpAddr, SocketAddr},
};

/// A handle for socket-layer events.
pub struct SocketHandle {
    handle: Handle,
}

impl SocketHandle {
    /// Opens a SocketHandle.
    pub fn open(filter: &str, priority: i16) -> Result<Self, InternalError> {
        let handle = Handle::open(
            filter,
            Layer::Socket,
            priority,
            (bindings::WINDIVERT_FLAG_SNIFF | bindings::WINDIVERT_FLAG_RECV_ONLY) as _,
        )?;
        Ok(Self { handle })
    }

    /// Receives a socket event.
    pub fn receive(&mut self) -> Result<SocketEvt, InternalError> {
        let mut addr: MaybeUninit<bindings::WINDIVERT_ADDRESS> = MaybeUninit::uninit();
        self.handle.receive(None, Some(&mut addr))?;
        let addr = unsafe { addr.assume_init() };

        // now we parse it. we parse the "flow" part of the union even though this is a socket handle because they are the same.
        let data = unsafe { addr.__bindgen_anon_1.Socket };
        let (local_addr, remote_addr) = parse_addr(&addr, &data);
        let evt_type = match addr.Event() as _ {
            bindings::WINDIVERT_EVENT_WINDIVERT_EVENT_SOCKET_ACCEPT => SocketEvtType::Accept,
            bindings::WINDIVERT_EVENT_WINDIVERT_EVENT_SOCKET_BIND => SocketEvtType::Bind,
            bindings::WINDIVERT_EVENT_WINDIVERT_EVENT_SOCKET_CLOSE => SocketEvtType::Close,
            bindings::WINDIVERT_EVENT_WINDIVERT_EVENT_SOCKET_CONNECT => SocketEvtType::Connect,
            bindings::WINDIVERT_EVENT_WINDIVERT_EVENT_SOCKET_LISTEN => SocketEvtType::Listen,
            _ => panic!("Non-socket event somehow got here..."),
        };

        let is_tcp = data.Protocol == 6;

        Ok(SocketEvt {
            kind: evt_type,
            local_addr,
            remote_addr,
            process_id: data.ProcessId,
            is_tcp,
        })
    }
}

/// An socket-related event
#[derive(Debug, Clone, Copy)]
pub struct SocketEvt {
    pub kind: SocketEvtType,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub process_id: u32,
    pub is_tcp: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SocketEvtType {
    Bind,
    Connect,
    Listen,
    Accept,
    Close,
}

pub fn parse_addr(
    addr: &bindings::WINDIVERT_ADDRESS,
    windivert_socket: &bindings::WINDIVERT_DATA_SOCKET,
) -> (SocketAddr, SocketAddr) {
    if addr.IPv6() == 1 {
        (
            SocketAddr::new(
                IpAddr::V6(to_u8(windivert_socket.LocalAddr).into()),
                windivert_socket.LocalPort,
            ),
            SocketAddr::new(
                IpAddr::V6(to_u8(windivert_socket.RemoteAddr).into()),
                windivert_socket.RemotePort,
            ),
        )
    } else {
        (
            SocketAddr::new(
                IpAddr::V4(windivert_socket.LocalAddr[0].into()),
                windivert_socket.LocalPort,
            ),
            SocketAddr::new(
                IpAddr::V4(windivert_socket.RemoteAddr[0].into()),
                windivert_socket.RemotePort,
            ),
        )
    }
}

fn to_u8(thirty_twos: [u32; 4]) -> [u8; 16] {
    let thirty_twos: Vec<u32> = thirty_twos.iter().rev().cloned().collect();
    let v: Vec<u8> = (0..16)
        .map(|i| thirty_twos[i / 4].to_be_bytes()[i % 4])
        .collect();
    v.try_into().unwrap()
}
