use std::{io, net::SocketAddr};

use bytes::{Bytes, BytesMut};

/// A trait that represents a datagram backhaul. This presents an interface similar to that of "PacketConn" in Go, and it is used to abstract over different kinds of datagram transports.
#[async_trait::async_trait]
pub trait Backhaul: Send + Sync {
    /// Waits for the next datagram
    async fn recv_from(&self) -> io::Result<(Bytes, SocketAddr)>;
    /// Sends a datagram
    async fn send_to(&self, to_send: Bytes, dest: SocketAddr) -> io::Result<()>;
}

#[async_trait::async_trait]
impl Backhaul for smol::net::UdpSocket {
    async fn recv_from(&self) -> io::Result<(Bytes, SocketAddr)> {
        let mut buf = BytesMut::with_capacity(2048);
        unsafe {
            buf.set_len(2048);
        }
        let (n, origin) = self.recv_from(&mut buf).await?;
        Ok((buf.freeze().slice(0..n), origin))
    }

    async fn send_to(&self, to_send: Bytes, dest: SocketAddr) -> io::Result<()> {
        self.send_to(&to_send, dest).await?;
        Ok(())
    }
}
