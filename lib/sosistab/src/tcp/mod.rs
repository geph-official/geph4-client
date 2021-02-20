use std::time::Duration;

use async_dup::Arc;

use c2_chacha::{stream_cipher::NewStreamCipher, stream_cipher::SyncStreamCipher, ChaCha8};

use parking_lot::Mutex;

use smol::prelude::*;
use smol::{io::BufReader, net::TcpStream};

mod client;
pub use client::*;

const CONN_LIFETIME: Duration = Duration::from_secs(300);

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
        let buf_read = async_dup::Arc::new(async_dup::Mutex::new(BufReader::new(inner.clone())));
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
        self.inner.clone().write_all(buf).await?;
        Ok(())
    }

    async fn read_exact(&self, buf: &mut [u8]) -> std::io::Result<()> {
        self.buf_read.lock().read_exact(buf).await?;
        self.recv_chacha.lock().apply_keystream(buf);
        Ok(())
    }
}
