use std::{convert::TryInto, time::Duration};

use async_dup::Arc;

use bytes::Bytes;
use c2_chacha::{stream_cipher::NewStreamCipher, stream_cipher::SyncStreamCipher, ChaCha8};

use parking_lot::Mutex;

use smol::prelude::*;
use smol::{io::BufReader, net::TcpStream};

mod client;
pub use client::*;
mod server;
pub use server::*;

use crate::crypt::NgAEAD;

const CONN_LIFETIME: Duration = Duration::from_secs(600);

const TCP_UP_KEY: &[u8; 32] = b"uploadtcp-----------------------";
const TCP_DN_KEY: &[u8; 32] = b"downloadtcp---------------------";

/// Wrapped TCP connection, with a send and receive obfuscation key.
#[derive(Clone)]
struct ObfsTCP {
    inner: TcpStream,
    buf_read: async_dup::Arc<async_dup::Mutex<BufReader<TcpStream>>>,
    send_chacha: Arc<Mutex<ChaCha8>>,
    recv_chacha: Arc<Mutex<ChaCha8>>,
}

impl ObfsTCP {
    /// creates an ObfsTCP given a shared secret and direction
    fn new(ss: blake3::Hash, is_server: bool, inner: TcpStream) -> Self {
        let up_chacha = Arc::new(Mutex::new(
            ChaCha8::new_var(
                blake3::keyed_hash(&TCP_UP_KEY, ss.as_bytes()).as_bytes(),
                &[0; 8],
            )
            .unwrap(),
        ));
        let dn_chacha = Arc::new(Mutex::new(
            ChaCha8::new_var(
                blake3::keyed_hash(&TCP_DN_KEY, ss.as_bytes()).as_bytes(),
                &[0; 8],
            )
            .unwrap(),
        ));
        let buf_read = async_dup::Arc::new(async_dup::Mutex::new(BufReader::with_capacity(
            65536,
            inner.clone(),
        )));
        if is_server {
            Self {
                inner,
                buf_read,
                send_chacha: dn_chacha,
                recv_chacha: up_chacha,
            }
        } else {
            Self {
                inner,
                buf_read,
                send_chacha: up_chacha,
                recv_chacha: dn_chacha,
            }
        }
    }

    async fn write(&self, msg: &[u8]) -> std::io::Result<()> {
        assert!(msg.len() <= 2048);
        let mut buf = [0u8; 2048];
        let buf = &mut buf[..msg.len()];
        buf.copy_from_slice(&msg);
        self.send_chacha.lock().apply_keystream(buf);
        let mut inner = self.inner.clone();
        inner.write_all(buf).await?;
        inner.flush().await?;
        Ok(())
    }

    async fn read_exact(&self, buf: &mut [u8]) -> std::io::Result<()> {
        self.buf_read.lock().read_exact(buf).await?;
        self.recv_chacha.lock().apply_keystream(buf);
        Ok(())
    }
}

async fn read_encrypted<R: AsyncRead + Unpin>(
    decrypt: NgAEAD,
    rdr: &mut R,
) -> anyhow::Result<Bytes> {
    // read the length first
    let mut length_buf = vec![0u8; NgAEAD::overhead() + 2];
    rdr.read_exact(&mut length_buf).await?;
    // decrypt the length
    let length_buf = decrypt
        .decrypt(&length_buf)
        .ok_or_else(|| anyhow::anyhow!("failed to decrypt length"))?;
    if length_buf.len() != 2 {
        anyhow::bail!("length must be 16 bits");
    }
    let length_buf = &length_buf[..];
    // now read the actual body
    let mut actual_buf = vec![0u8; u16::from_be_bytes(length_buf.try_into().unwrap()) as usize];
    rdr.read_exact(&mut actual_buf).await?;
    decrypt
        .decrypt(&actual_buf)
        .ok_or_else(|| anyhow::anyhow!("cannot decrypt"))
}

async fn write_encrypted<W: AsyncWrite + Unpin>(
    encrypt: NgAEAD,
    to_send: &[u8],
    writer: &mut W,
) -> anyhow::Result<()> {
    let to_send = encrypt.encrypt(to_send);
    let raw_length = (to_send.len() as u16).to_be_bytes();
    writer.write_all(&encrypt.encrypt(&raw_length)).await?;
    writer.write_all(&to_send).await?;
    Ok(())
}
