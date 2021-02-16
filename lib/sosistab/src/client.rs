use crate::*;
use bytes::Bytes;
use crypt::{LegacyAEAD, NgAEAD};
use governor::{Quota, RateLimiter};
use rand::prelude::*;
use smol::channel::{Receiver, Sender};
use smol::prelude::*;
use std::{net::SocketAddr, num::NonZeroU32};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// Connects to a remote server.
#[tracing::instrument(level = "trace")]
pub async fn connect(
    server_addr: SocketAddr,
    pubkey: x25519_dalek::PublicKey,
) -> std::io::Result<Session> {
    connect_custom(server_addr, pubkey, || {
        let val = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        Ok(val)
    })
    .await
}

/// Connects to a remote server, given a closure that generates socket addresses.
#[tracing::instrument(skip(laddr_gen), level = "trace")]
pub async fn connect_custom(
    server_addr: SocketAddr,
    pubkey: x25519_dalek::PublicKey,
    laddr_gen: impl Fn() -> std::io::Result<SocketAddr> + Send + Sync + 'static,
) -> std::io::Result<Session> {
    let udp_socket = runtime::new_udp_socket_bind(laddr_gen()?).await?;
    let my_long_sk = x25519_dalek::StaticSecret::new(&mut rand::thread_rng());
    let my_eph_sk = x25519_dalek::StaticSecret::new(&mut rand::thread_rng());
    // do the handshake
    let cookie = crypt::Cookie::new(pubkey);
    let init_hello = protocol::HandshakeFrame::ClientHello {
        long_pk: (&my_long_sk).into(),
        eph_pk: (&my_eph_sk).into(),
        version: VERSION,
    };
    let mut buf = [0u8; 2048];
    for timeout_factor in (0u32..).map(|x| 2u64.pow(x)) {
        // send hello
        let init_hello = crypt::LegacyAEAD::new(&cookie.generate_c2s().next().unwrap())
            .pad_encrypt_v1(&std::slice::from_ref(&init_hello), 1000);
        udp_socket.send_to(&init_hello, server_addr).await?;
        tracing::trace!("sent client hello");
        // wait for response
        let res = udp_socket
            .recv_from(&mut buf)
            .or(async {
                smol::Timer::after(Duration::from_secs(timeout_factor)).await;
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out",
                ))
            })
            .await;
        match res {
            Ok((n, _)) => {
                let buf = &buf[..n];
                for possible_key in cookie.generate_s2c() {
                    let decrypter = crypt::LegacyAEAD::new(&possible_key);
                    let response = decrypter.pad_decrypt_v1(buf);
                    for response in response.unwrap_or_default() {
                        if let protocol::HandshakeFrame::ServerHello {
                            long_pk,
                            eph_pk,
                            resume_token,
                        } = response
                        {
                            tracing::trace!("obtained response from server");
                            if long_pk.as_bytes() != pubkey.as_bytes() {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::ConnectionRefused,
                                    "bad pubkey",
                                ));
                            }
                            let shared_sec =
                                crypt::triple_ecdh(&my_long_sk, &my_eph_sk, &long_pk, &eph_pk);
                            return init_session(
                                cookie,
                                resume_token,
                                shared_sec,
                                server_addr,
                                Arc::new(laddr_gen),
                            )
                            .await;
                        }
                    }
                }
            }
            Err(err) => {
                if err.kind() == std::io::ErrorKind::TimedOut {
                    tracing::trace!(
                        "timed out to {} with {}s timeout; trying again",
                        server_addr,
                        timeout_factor
                    );
                    continue;
                }
                return Err(err);
            }
        }
    }
    unimplemented!()
}

const SHARDS: u8 = 4;
const RESET_MILLIS: u128 = 10000;

const VERSION: u64 = 3;

#[tracing::instrument(skip(laddr_gen), level = "trace")]
async fn init_session(
    cookie: crypt::Cookie,
    resume_token: Bytes,
    shared_sec: blake3::Hash,
    remote_addr: SocketAddr,
    laddr_gen: Arc<impl Fn() -> std::io::Result<SocketAddr> + Send + Sync + 'static>,
) -> std::io::Result<Session> {
    let remind_ratelimit = Arc::new(RateLimiter::direct(Quota::per_second(
        NonZeroU32::new(3).unwrap(),
    )));
    let (send_frame_out, recv_frame_out) = smol::channel::bounded(1000);
    let (send_frame_in, recv_frame_in) = smol::channel::bounded(1000);
    let backhaul_tasks: Vec<_> = (0..SHARDS)
        .map(|i| {
            runtime::spawn(client_backhaul_once(
                remind_ratelimit.clone(),
                cookie.clone(),
                resume_token.clone(),
                send_frame_in.clone(),
                recv_frame_out.clone(),
                i,
                remote_addr,
                laddr_gen.clone(),
            ))
        })
        .collect();
    let up_key = blake3::keyed_hash(crypt::UP_KEY, shared_sec.as_bytes());
    let dn_key = blake3::keyed_hash(crypt::DN_KEY, shared_sec.as_bytes());
    let mut session = Session::new(SessionConfig {
        send_packet: send_frame_out,
        recv_packet: recv_frame_in,
        send_crypt_legacy: LegacyAEAD::new(up_key.as_bytes()),
        recv_crypt_legacy: LegacyAEAD::new(dn_key.as_bytes()),
        send_crypt_ng: NgAEAD::new(up_key.as_bytes()),
        recv_crypt_ng: NgAEAD::new(dn_key.as_bytes()),
        recv_timeout: Duration::from_secs(300),
        statistics: 40000,
        version: VERSION,
    });
    session.on_drop(move || {
        drop(backhaul_tasks);
    });
    Ok(session)
}

#[allow(clippy::all)]
#[tracing::instrument(skip(laddr_gen), level = "trace")]
async fn client_backhaul_once(
    remind_ratelimit: Arc<
        RateLimiter<
            governor::state::NotKeyed,
            governor::state::InMemoryState,
            governor::clock::DefaultClock,
        >,
    >,
    cookie: crypt::Cookie,
    resume_token: Bytes,
    send_packet_in: Sender<Bytes>,
    recv_packet_out: Receiver<Bytes>,
    shard_id: u8,
    remote_addr: SocketAddr,
    laddr_gen: Arc<impl Fn() -> std::io::Result<SocketAddr> + Send + Sync + 'static>,
) -> Option<()> {
    let mut last_reset = Instant::now();
    let mut updated = false;
    let mut socket: Arc<dyn Backhaul> =
        Arc::new(runtime::new_udp_socket_bind(laddr_gen().ok()?).await.ok()?);
    // let mut _old_cleanup: Option<smol::Task<Option<()>>> = None;

    #[derive(Debug)]
    enum Evt {
        Incoming(Vec<Bytes>),
        Outgoing(Bytes),
    };

    let mut my_reset_millis = rand::thread_rng().gen_range(RESET_MILLIS / 2, RESET_MILLIS);

    loop {
        let down = {
            let socket = &socket;
            async move {
                let packets = socket.recv_from_many().await.ok()?;
                Some(Evt::Incoming(packets.into_iter().map(|v| v.0).collect()))
            }
        };
        let up = async {
            let raw_upload = recv_packet_out.recv().await.ok()?;
            Some(Evt::Outgoing(raw_upload))
        };

        match smol::future::race(down, up).await {
            Some(Evt::Incoming(bts)) => {
                for bts in bts {
                    let _ = send_packet_in.send(bts).await;
                }
            }
            Some(Evt::Outgoing(bts)) => {
                let bts: Bytes = bts;
                let now = Instant::now();
                if remind_ratelimit.check().is_ok() || !updated {
                    updated = true;
                    let g_encrypt = crypt::LegacyAEAD::new(&cookie.generate_c2s().next().unwrap());
                    if now.saturating_duration_since(last_reset).as_millis() > my_reset_millis {
                        my_reset_millis =
                            rand::thread_rng().gen_range(RESET_MILLIS / 2, RESET_MILLIS);
                        last_reset = now;
                        // also replace the UDP socket!
                        let old_socket = socket.clone();
                        let send_packet_in = send_packet_in.clone();
                        // spawn a task to clean up the UDP socket
                        let tata: smol::Task<Option<()>> = runtime::spawn(
                            async move {
                                loop {
                                    let bufs = old_socket.recv_from_many().await.ok()?;
                                    for (buf, _) in bufs {
                                        drop(send_packet_in.send(buf).await)
                                    }
                                }
                            }
                            .or(async {
                                smol::Timer::after(Duration::from_secs(60)).await;
                                None
                            }),
                        );
                        tata.detach();
                        socket = loop {
                            match runtime::new_udp_socket_bind(laddr_gen().ok()?).await {
                                Ok(sock) => break Arc::new(sock),
                                Err(err) => {
                                    tracing::warn!("error rebinding: {}", err);
                                    smol::Timer::after(Duration::from_secs(1)).await;
                                }
                            }
                        };
                    }
                    drop(
                        socket
                            .send_to(
                                g_encrypt.pad_encrypt_v1(
                                    &[protocol::HandshakeFrame::ClientResume {
                                        resume_token: resume_token.clone(),
                                        shard_id,
                                    }],
                                    1000,
                                ),
                                remote_addr,
                            )
                            .await,
                    );
                }
                drop(socket.send_to(bts, remote_addr).await);
            }
            None => return None,
        }
    }
}
