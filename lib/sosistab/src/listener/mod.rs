use crate::{
    backhaul::{Backhaul, StatsBackhaul},
    crypt::{triple_ecdh, Cookie, LegacyAead},
    protocol::HandshakeFrame,
    runtime, safe_deserialize, Role,
};
use crate::{
    recfilter::RECENT_FILTER,
    session::{Session, SessionConfig},
};
use bytes::Bytes;

use crate::protocol::HandshakeFrame::*;
use crate::tcp::TcpServerBackhaul;
use parking_lot::RwLock;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use smol::net::AsyncToSocketAddrs;
use smol::{
    channel::{Receiver, Sender},
    net::TcpListener,
};
use std::net::SocketAddr;
use std::sync::Arc;
use table::ShardedAddrs;

use table::SessionTable;

mod table;

pub struct Listener {
    accepted: Receiver<Session>,
    local_addr: SocketAddr,
    _task: smol::Task<Option<()>>,
}

impl Listener {
    /// Accepts a session. This function must be repeatedly called for the entire Listener to make any progress.
    #[tracing::instrument(skip(self), level = "trace")]
    pub async fn accept_session(&self) -> Option<Session> {
        self.accepted.recv().await.ok()
    }
    /// Creates a new listener given the parameters.
    pub async fn listen_udp(
        addr: SocketAddr,
        long_sk: x25519_dalek::StaticSecret,
        on_recv: impl Fn(usize, SocketAddr) + 'static + Send + Sync,
        on_send: impl Fn(usize, SocketAddr) + 'static + Send + Sync,
    ) -> Self {
        let socket = runtime::new_udp_socket_bind(addr).unwrap();
        let local_addr = socket.get_ref().local_addr().unwrap();
        let cookie = Cookie::new((&long_sk).into());
        let (send, recv) = smol::channel::unbounded();
        let task = runtime::spawn(
            ListenerActor {
                socket: Arc::new(StatsBackhaul::new(socket, on_recv, on_send)),
                cookie,
                long_sk,
            }
            .run(send),
        );
        Listener {
            accepted: recv,
            local_addr,
            _task: task,
        }
    }

    /// Creates a new listener given the parameters.
    pub async fn listen_tcp(
        addr: impl AsyncToSocketAddrs,
        long_sk: x25519_dalek::StaticSecret,
        on_recv: impl Fn(usize, SocketAddr) + 'static + Send + Sync,
        on_send: impl Fn(usize, SocketAddr) + 'static + Send + Sync,
    ) -> Self {
        // let addr = async_net::resolve(addr).await;
        let listener = TcpListener::bind(addr).await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let cookie = Cookie::new((&long_sk).into());
        let socket = TcpServerBackhaul::new(listener, long_sk.clone());
        let (send, recv) = smol::channel::unbounded();
        let task = runtime::spawn(
            ListenerActor {
                socket: Arc::new(StatsBackhaul::new(socket, on_recv, on_send)),
                cookie,
                long_sk,
            }
            .run(send),
        );
        Listener {
            accepted: recv,
            local_addr,
            _task: task,
        }
    }

    /// Gets the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

struct ListenerActor {
    socket: Arc<dyn Backhaul>,
    cookie: Cookie,
    long_sk: x25519_dalek::StaticSecret,
}
impl ListenerActor {
    #[allow(clippy::mutable_key_type)]
    #[tracing::instrument(skip(self), level = "trace")]
    async fn run(self, accepted: Sender<Session>) -> Option<()> {
        // session table
        let mut session_table = SessionTable::default();
        // channel for dropping sessions
        let (send_dead, recv_dead) = smol::channel::unbounded();

        let token_key = {
            let mut buf = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut buf);
            buf
        };

        let read_socket = self.socket.clone();
        let write_socket = Arc::new(smol::lock::Mutex::new(self.socket.clone()));

        // two possible events
        enum Evt {
            NewRecv((Bytes, SocketAddr)),
            DeadSess(Bytes),
        }

        for trace_id in 0u128.. {
            let event = smol::future::race(
                async { Some(Evt::NewRecv(read_socket.recv_from().await.unwrap())) },
                async { Some(Evt::DeadSess(recv_dead.recv().await.ok()?)) },
            );
            match event.await? {
                Evt::DeadSess(resume_token) => {
                    session_table.delete(resume_token);
                }
                Evt::NewRecv((buffer, addr)) => {
                    // first we attempt to map this to an existing session
                    if let Some(handle) = session_table.lookup(addr) {
                        if handle.inject_incoming(&buffer).is_ok() {
                            continue;
                        }
                    }
                    // we know it's not part of an existing session then. we decrypt it under the current key
                    let s2c_key = self.cookie.generate_s2c().next().unwrap();
                    for possible_key in self.cookie.generate_c2s() {
                        let crypter = LegacyAead::new(&possible_key);
                        if let Some(handshake) = crypter.pad_decrypt_v1::<HandshakeFrame>(&buffer) {
                            if !RECENT_FILTER.lock().check(&buffer) {
                                tracing::debug!(
                                    "discarding replay attempt with len {}",
                                    buffer.len()
                                );
                                break;
                            }
                            tracing::trace!(
                                "[{}] decoded some sort of handshake: {:?}",
                                trace_id,
                                handshake
                            );
                            match handshake[0].clone() {
                                ClientHello {
                                    long_pk,
                                    eph_pk,
                                    version,
                                } => {
                                    if version != 3 {
                                        tracing::warn!(
                                            "got packet with incorrect version {}",
                                            version
                                        );
                                        break;
                                    }
                                    // generate session key
                                    let my_eph_sk =
                                        x25519_dalek::StaticSecret::new(&mut rand::thread_rng());
                                    let token = TokenInfo {
                                        sess_key: triple_ecdh(
                                            &self.long_sk,
                                            &my_eph_sk,
                                            &long_pk,
                                            &eph_pk,
                                        )
                                        .as_bytes()
                                        .to_vec()
                                        .into(),
                                        init_time_ms: std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap()
                                            .as_millis()
                                            as u64,
                                        version,
                                    }
                                    .encrypt(&token_key);
                                    let reply = HandshakeFrame::ServerHello {
                                        long_pk: (&self.long_sk).into(),
                                        eph_pk: (&my_eph_sk).into(),
                                        resume_token: token,
                                    };
                                    let reply =
                                        LegacyAead::new(&s2c_key).pad_encrypt_v1(&[reply], 1000);
                                    tracing::debug!(
                                        "[{}] GONNA reply to ClientHello from {}",
                                        trace_id,
                                        addr
                                    );
                                    let _ = write_socket.lock().await.send_to(reply, addr).await;
                                    tracing::debug!(
                                        "[{}] replied to ClientHello from {}",
                                        trace_id,
                                        addr
                                    );
                                }
                                ClientResume {
                                    resume_token,
                                    shard_id,
                                } => {
                                    tracing::trace!("Got ClientResume-{} from {}!", shard_id, addr);
                                    let tokinfo = TokenInfo::decrypt(&token_key, &resume_token);
                                    if let Some(tokinfo) = tokinfo {
                                        // first check whether we know about the resume token
                                        if !session_table.rebind(
                                            addr,
                                            shard_id,
                                            resume_token.clone(),
                                        ) {
                                            tracing::debug!(
                                                "[{}] ClientResume from {} is new!",
                                                trace_id,
                                                addr
                                            );

                                            let write_socket = write_socket.clone();
                                            let locked_addrs = ShardedAddrs::new(shard_id, addr);
                                            let locked_addrs = Arc::new(RwLock::new(locked_addrs));
                                            let (mut session, session_back) =
                                                Session::new(SessionConfig {
                                                    gather: Default::default(),
                                                    version: tokinfo.version,
                                                    session_key: tokinfo.sess_key.to_vec(),
                                                    role: Role::Server,
                                                });
                                            let session_back = Arc::new(session_back);
                                            let output_poller = {
                                                let locked_addrs = locked_addrs.clone();
                                                let session_back = session_back.clone();
                                                runtime::spawn(async move {
                                                    loop {
                                                        match session_back.next_outgoing().await {
                                                            Ok(data) => {
                                                                // let start = Instant::now();
                                                                let remote_addr =
                                                                    locked_addrs.write().get_addr();
                                                                drop(
                                                                    write_socket
                                                                        .lock()
                                                                        .await
                                                                        .send_to(data, remote_addr)
                                                                        .await,
                                                                );
                                                            }
                                                            Err(_) => {
                                                                smol::future::pending::<()>().await
                                                            }
                                                        }
                                                    }
                                                })
                                            };
                                            let send_dead_clo = send_dead.clone();
                                            let resume_token_clo = resume_token.clone();
                                            session.on_drop(move || {
                                                drop(output_poller);
                                                drop(send_dead_clo.try_send(resume_token_clo))
                                            });
                                            // spawn a task that writes to the socket.
                                            session_table.new_sess(
                                                resume_token.clone(),
                                                session_back,
                                                locked_addrs,
                                            );
                                            session_table.rebind(addr, shard_id, resume_token);
                                            tracing::debug!("[{}] accept {}", trace_id, addr);
                                            accepted.try_send(session).ok()?;
                                        } else {
                                            tracing::trace!(
                                                "[{}] ClientResume from {} rebound",
                                                trace_id,
                                                addr
                                            );
                                        }
                                    }
                                }
                                _ => continue,
                            }
                        }
                    }
                }
            }
        }
        unreachable!()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenInfo {
    sess_key: Bytes,
    init_time_ms: u64,
    version: u64,
}

impl TokenInfo {
    fn decrypt(key: &[u8], encrypted: &[u8]) -> Option<Self> {
        // first we decrypt
        let crypter = LegacyAead::new(key);
        let plain = crypter.decrypt(encrypted)?;
        safe_deserialize(&plain).ok()
    }

    fn encrypt(&self, key: &[u8]) -> Bytes {
        let crypter = LegacyAead::new(key);
        let mut rng = rand::thread_rng();
        crypter.encrypt(
            &bincode::serialize(self).expect("must serialize"),
            rng.gen(),
        )
    }
}
