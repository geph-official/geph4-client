use bytes::Bytes;
use dashmap::DashMap;
use rustc_hash::FxHashMap;
use smol::channel::{Receiver, Sender};
use smol::prelude::*;
use std::{
    collections::VecDeque,
    convert::TryInto,
    net::{Shutdown, SocketAddr},
    time::SystemTime,
};

use crate::{
    crypt::{triple_ecdh, Cookie, NgAEAD},
    protocol::HandshakeFrame,
    runtime, Backhaul,
};

use super::{ObfsTCP, CONN_LIFETIME, TCP_DN_KEY, TCP_UP_KEY};

/// A TCP-based backhaul, client-side.
pub struct TcpClientBackhaul {
    dest_to_key: FxHashMap<SocketAddr, x25519_dalek::PublicKey>,
    conn_pool: DashMap<SocketAddr, VecDeque<(ObfsTCP, SystemTime)>>,
    incoming: Receiver<(Bytes, SocketAddr)>,
    send_incoming: Sender<(Bytes, SocketAddr)>,
}

impl TcpClientBackhaul {
    /// Creates a new TCP client backhaul.
    pub fn new() -> Self {
        // dummy here
        let (send_incoming, incoming) = smol::channel::unbounded();
        Self {
            dest_to_key: Default::default(),
            conn_pool: Default::default(),
            incoming,
            send_incoming,
        }
    }

    /// Adds a binding.
    pub fn add_remote_key(mut self, addr: SocketAddr, key: x25519_dalek::PublicKey) -> Self {
        self.dest_to_key.insert(addr, key);
        self
    }

    /// Gets a connection out of the pool of an address.
    fn get_conn_pooled(&self, addr: SocketAddr) -> Option<ObfsTCP> {
        let mut pool = self.conn_pool.entry(addr).or_default();
        while let Some((conn, time)) = pool.pop_front() {
            if let Ok(time) = time.elapsed() {
                if time < CONN_LIFETIME {
                    return Some(conn);
                }
                let _ = conn.inner.shutdown(Shutdown::Both);
            }
        }
        None
    }

    /// Puts a connection back into the pool of an address.
    fn put_conn(&self, addr: SocketAddr, stream: ObfsTCP) {
        let mut pool = self.conn_pool.entry(addr).or_default();
        pool.push_back((stream, SystemTime::now()));
    }

    /// Opens a connection or gets a connection from the pool.
    async fn get_conn(&self, addr: SocketAddr) -> anyhow::Result<ObfsTCP> {
        if let Some(pooled) = self.get_conn_pooled(addr) {
            Ok(pooled)
        } else {
            let my_long_sk = x25519_dalek::StaticSecret::new(&mut rand::thread_rng());
            let my_eph_sk = x25519_dalek::StaticSecret::new(&mut rand::thread_rng());

            let pubkey = *self
                .dest_to_key
                .get(&addr)
                .ok_or_else(|| anyhow::anyhow!("remote address doesn't have a public key"))?;
            let cookie = Cookie::new(pubkey);
            // first connect
            let mut remote = smol::net::TcpStream::connect(addr).await?;
            // then we send a hello
            let init_key = cookie.generate_c2s().next().unwrap();
            let init_up_key = blake3::keyed_hash(&TCP_UP_KEY, &init_key);
            let init_enc = NgAEAD::new(init_up_key.as_bytes());
            let to_send = HandshakeFrame::ClientHello {
                long_pk: (&my_long_sk).into(),
                eph_pk: (&my_eph_sk).into(),
                version: 3,
            };
            let mut to_send = to_send.to_bytes();
            let random_padding = vec![0u8; rand::random::<usize>() % 1024];
            to_send.extend_from_slice(&random_padding);
            write_encrypted(init_enc, &to_send, &mut remote).await?;
            // now we wait for a response
            let init_dn_key = blake3::keyed_hash(&TCP_DN_KEY, &init_key);
            let init_dec = NgAEAD::new(init_dn_key.as_bytes());
            let raw_response = read_encrypted(init_dec, &mut remote).await?;
            let actual_response = HandshakeFrame::from_bytes(&raw_response)?;
            if let HandshakeFrame::ServerHello {
                long_pk,
                eph_pk,
                resume_token: _,
            } = actual_response
            {
                let shared_sec = triple_ecdh(&my_long_sk, &my_eph_sk, &long_pk, &eph_pk);
                let connection = ObfsTCP::new(shared_sec, false, remote);

                let down_conn = connection.clone();
                let send_incoming = self.send_incoming.clone();
                // spawn a thread that reads from the connection
                runtime::spawn(async move {
                    let mut buffer = [0u8; 65536];
                    let main = async {
                        loop {
                            down_conn.read_exact(&mut buffer[..2]).await?;
                            let length =
                                u16::from_be_bytes((&buffer[..2]).try_into().unwrap()) as usize;
                            down_conn.read_exact(&mut buffer[..length]).await?;
                            send_incoming
                                .send((Bytes::copy_from_slice(&buffer[..length]), addr))
                                .await?;
                        }
                    };
                    let _: anyhow::Result<()> = main.await;
                })
                .detach();

                Ok(connection)
            } else {
                anyhow::bail!("server sent unrecognizable message")
            }
        }
    }
}

async fn read_encrypted<R: AsyncRead + Unpin>(
    decrypt: NgAEAD,
    rdr: &mut R,
) -> anyhow::Result<Bytes> {
    // read the length first
    let mut length_buf = vec![0u8; NgAEAD::overhead()];
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

#[async_trait::async_trait]
impl Backhaul for TcpClientBackhaul {
    async fn send_to(&self, to_send: Bytes, dest: SocketAddr) -> std::io::Result<()> {
        let _: anyhow::Result<()> = async {
            let conn = self.get_conn(dest).await?;
            conn.write(&to_send)
                .or(async {
                    tracing::warn!("skipping write due to full buffers");
                    Ok(())
                })
                .await?;
            self.put_conn(dest, conn);
            Ok(())
        }
        .await;

        Ok(())
    }

    async fn recv_from(&self) -> std::io::Result<(Bytes, SocketAddr)> {
        Ok(self.incoming.recv().await.unwrap())
    }
}
