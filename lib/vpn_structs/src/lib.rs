use std::net::Ipv4Addr;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use smol::prelude::*;

/// VPN message
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    ClientHello {
        client_id: u128,
    },
    ServerHello {
        client_ip: Ipv4Addr,
        gateway: Ipv4Addr,
    },
    Payload(Bytes),
}

/// Stdio message
#[derive(Debug, Clone)]
pub struct StdioMsg {
    pub verb: u8,
    pub body: Bytes,
}

impl StdioMsg {
    /// Reads a new StdioMsg
    pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Self> {
        // first we read one byte
        let mut scratch_space = [0u8; 2];
        reader.read_exact(&mut scratch_space[..1]).await?;
        let verb = scratch_space[0];
        reader.read_exact(&mut scratch_space).await?;
        let length = u16::from_le_bytes(scratch_space);
        let mut bts = vec![0u8; length as usize];
        reader.read_exact(&mut bts).await?;
        Ok(StdioMsg {
            verb,
            body: bts.into(),
        })
    }

    /// Write out the StdioMsg
    pub async fn write<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> std::io::Result<()> {
        let mut buf: Vec<u8> = Vec::with_capacity(2048);
        buf.write_all(&[self.verb]).await?;
        buf.write_all(&(self.body.len() as u16).to_le_bytes())
            .await?;
        buf.write_all(&self.body).await?;
        writer.write_all(&buf).await?;
        Ok(())
    }
}
