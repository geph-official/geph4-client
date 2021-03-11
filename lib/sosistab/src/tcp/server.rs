use anyhow::Context;
use bytes::Bytes;
use dashmap::DashMap;
use smol::prelude::*;
use smol::{
    channel::{Receiver, Sender},
    net::{TcpListener, TcpStream},
};
use std::{
    convert::TryInto,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    crypt::{triple_ecdh, Cookie, NgAEAD},
    protocol::HandshakeFrame,
    recfilter::RECENT_FILTER,
    runtime, Backhaul,
};

use super::{write_encrypted, ObfsTCP, CONN_LIFETIME, TCP_DN_KEY, TCP_UP_KEY};

/// A TCP-based backhaul, server-side.
pub struct TcpServerBackhaul {
    down_table: Arc<DownTable>,
    recv_upcoming: Receiver<(Bytes, SocketAddr)>,
    _task: smol::Task<()>,
}

impl TcpServerBackhaul {
    /// Creates a new TCP server-side backhaul.
    pub fn new(listener: TcpListener, seckey: x25519_dalek::StaticSecret) -> Self {
        let down_table = Arc::new(DownTable::default());
        let table_cloned = down_table.clone();
        let (send_upcoming, recv_upcoming) = smol::channel::bounded(1000);
        let _task = runtime::spawn(async move {
            if let Err(err) = backhaul_loop(listener, seckey, table_cloned, send_upcoming).await {
                tracing::debug!("backhaul_loop exited: {:?}", err)
            }
        });
        Self {
            down_table,
            recv_upcoming,
            _task,
        }
    }
}

#[async_trait::async_trait]
impl Backhaul for TcpServerBackhaul {
    async fn recv_from(&self) -> std::io::Result<(Bytes, SocketAddr)> {
        Ok(self.recv_upcoming.recv().await.unwrap())
    }

    async fn send_to(&self, to_send: Bytes, dest: SocketAddr) -> std::io::Result<()> {
        self.down_table.send_to(to_send, dest);
        Ok(())
    }
}

async fn backhaul_loop(
    listener: TcpListener,
    seckey: x25519_dalek::StaticSecret,
    down_table: Arc<DownTable>,
    send_upcoming: Sender<(Bytes, SocketAddr)>,
) -> anyhow::Result<()> {
    // use a local executor to make sure stuff gets cleaned up very promptly
    let lexec = smol::Executor::new();
    lexec
        .run(async {
            loop {
                let (client, _) = listener.accept().await?;
                client.set_nodelay(true)?;
                lexec
                    .spawn(async {
                        if let Err(err) =
                            backhaul_one(client, seckey.clone(), &down_table, &send_upcoming)
                                .or(async {
                                    smol::Timer::after(CONN_LIFETIME * 2).await;
                                    Ok(())
                                })
                                .await
                        {
                            tracing::debug!("backhaul_one exited: {:?}", err)
                        }
                    })
                    .detach();
            }
        })
        .await
}

/// handle a TCP stream
async fn backhaul_one(
    mut client: TcpStream,
    seckey: x25519_dalek::StaticSecret,
    down_table: &DownTable,
    send_upcoming: &Sender<(Bytes, SocketAddr)>,
) -> anyhow::Result<()> {
    let cookie = Cookie::new((&seckey).into());
    // read the initial length
    let mut encrypted_hello_length = vec![0u8; NgAEAD::overhead() + 2];
    client.read_exact(&mut encrypted_hello_length).await?;
    for (possible_c2s, possible_s2c) in cookie.generate_c2s().zip(cookie.generate_s2c()) {
        let c2s_key = blake3::keyed_hash(&TCP_UP_KEY, &possible_c2s);
        let c2s_dec = NgAEAD::new(c2s_key.as_bytes());
        let s2c_key = blake3::keyed_hash(&TCP_DN_KEY, &possible_s2c);
        let s2c_enc = NgAEAD::new(s2c_key.as_bytes());
        // if we can succesfully decrypt the hello length, that's awesome! it means that we got the right up/down key
        if let Some(hello_length) = c2s_dec.decrypt(&encrypted_hello_length) {
            let hello_length = u16::from_be_bytes(
                (&hello_length[..])
                    .try_into()
                    .context("hello length is the wrong size")?,
            ) as usize;
            let mut encrypted_hello = vec![0u8; hello_length];
            client.read_exact(&mut encrypted_hello).await?;
            let raw_hello = c2s_dec
                .decrypt(&encrypted_hello)
                .ok_or_else(|| anyhow::anyhow!("cannot decrypt hello"))?;
            if !RECENT_FILTER.lock().check(&raw_hello) {
                anyhow::bail!("hello failed replay check")
            }
            let real_hello = HandshakeFrame::from_bytes(&raw_hello)?;
            // now the client has passed checks. we send back a server response using the downstream key.
            // there is an "attack" where the adversary can confuse the server and the client by replaying a different response to the client.
            // the client will be able to decrypt this, and will establish a session with bad info.
            // this is "fine" because the result is that the session breaks (nobody can decrypt anything), not anything leaking.
            if let HandshakeFrame::ClientHello {
                long_pk,
                eph_pk,
                version: 3,
            } = real_hello
            {
                let my_eph_sk = x25519_dalek::StaticSecret::new(&mut rand::thread_rng());
                let response = HandshakeFrame::ServerHello {
                    long_pk: (&seckey).into(),
                    eph_pk: (&my_eph_sk).into(),
                    resume_token: Bytes::new(),
                };
                write_encrypted(s2c_enc, &response.to_bytes(), &mut client).await?;
                let ss = triple_ecdh(&seckey, &my_eph_sk, &long_pk, &eph_pk);
                let obfs_tcp = ObfsTCP::new(ss, true, client);
                let mut fake_addr = [0u8; 16];
                obfs_tcp
                    .read_exact(&mut fake_addr)
                    .await
                    .context("cannot read fakeaddr")?;
                let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(fake_addr)), 0);
                tracing::warn!("starting TCP with fake addr {}", addr);
                return backhaul_one_inner(obfs_tcp, addr, down_table, send_upcoming).await;
            }
        }
    }
    anyhow::bail!("could not interpret the initial handshake")
}

/// handle an already initialized TCP stream
async fn backhaul_one_inner(
    obfs_tcp: ObfsTCP,
    addr: SocketAddr,
    down_table: &DownTable,
    send_upcoming: &Sender<(Bytes, SocketAddr)>,
) -> anyhow::Result<()> {
    let (send_down, recv_down) = smol::channel::bounded(100);
    let up_loop = async {
        let mut buff = [0u8; 4096];
        loop {
            down_table.set(addr, send_down.clone());
            obfs_tcp.read_exact(&mut buff[..2]).await?;
            let length = u16::from_be_bytes(
                (&buff[..2])
                    .try_into()
                    .context("length not right size? wtf?")?,
            ) as usize;
            if length > 4096 {
                break Err(anyhow::anyhow!("got a packet that's too long ({})", length));
            }
            obfs_tcp.read_exact(&mut buff[..length]).await?;
            send_upcoming
                .send((Bytes::copy_from_slice(&buff[..length]), addr))
                .await?;
        }
    };
    let dn_loop = async {
        let mut buff = [0u8; 4098];
        loop {
            let down = recv_down.recv().await?;
            if down.len() > 4096 {
                break Err(anyhow::anyhow!("rejecting a down that's too long"));
            }
            let length = down.len() as u16;
            buff[..2].copy_from_slice(&length.to_be_bytes());
            buff[2..2 + (length as usize)].copy_from_slice(&down);
            let buff = &buff[..2 + (length as usize)];
            obfs_tcp.write(buff).await?;
        }
    };
    up_loop.race(dn_loop).await
}

#[derive(Default)]
struct DownTable {
    /// maps fake IPv6 addresses (u128, 0) back through a channel to a connection actor. only keeps track of the connection that had the *latest* activity.
    mapping: DashMap<SocketAddr, (Sender<Bytes>, Instant)>,
}

impl DownTable {
    /// Creates/overwrites a new entry in the table.
    fn set(&self, addr: SocketAddr, sender: Sender<Bytes>) {
        if rand::random::<usize>() % self.mapping.len().max(10) == 0 {
            self.gc()
        }
        let now = Instant::now();
        let mut entry = self.mapping.entry(addr).or_insert((sender.clone(), now));
        if entry.1 != now {
            entry.1 = now;
            entry.0 = sender
        }
    }

    /// Sends something to a socketaddr. Silently drops on error.
    fn send_to(&self, msg: Bytes, dest: SocketAddr) {
        if let Some(val) = self.mapping.get(&dest) {
            let _ = val.value().0.try_send(msg);
        }
    }

    /// Garbage collection. Goes through the table, deleting way too old entries.
    fn gc(&self) {
        let mut to_del = Vec::new();
        for entry in self.mapping.iter() {
            if entry.value().1.elapsed() > Duration::from_secs(3600) {
                to_del.push(*entry.key())
            }
        }
        for key in to_del {
            self.mapping.remove(&key);
        }
    }
}
