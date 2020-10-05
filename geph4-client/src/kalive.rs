use std::{sync::Arc, time::Instant};

use crate::{cache::ClientCache, write_pascalish};
use anyhow::Context;
use serde::de::DeserializeOwned;
use smol::channel::{Receiver, Sender};
use smol::prelude::*;
use std::time::Duration;

/// An "actor" that keeps a client session alive.
pub struct Keepalive {
    open_socks5_conn: Sender<(String, Sender<sosistab::mux::RelConn>)>,
    _task: smol::Task<anyhow::Result<()>>,
}

impl Keepalive {
    /// Creates a new keepalive.
    pub fn new(exit_host: &str, use_bridges: bool, ccache: Arc<ClientCache>) -> Self {
        let (send, recv) = smol::channel::unbounded();
        Keepalive {
            open_socks5_conn: send,
            _task: smol::spawn(keepalive_actor(
                exit_host.to_string(),
                use_bridges,
                ccache,
                recv,
            )),
        }
    }

    /// Opens a connection
    pub async fn connect(&self, remote: &str) -> anyhow::Result<sosistab::mux::RelConn> {
        let (send, recv) = smol::channel::bounded(1);
        self.open_socks5_conn
            .send((remote.to_string(), send))
            .await?;
        Ok(recv.recv().await?)
    }
}

async fn keepalive_actor(
    exit_host: String,
    use_bridges: bool,
    ccache: Arc<ClientCache>,
    recv_socks5_conn: Receiver<(String, Sender<sosistab::mux::RelConn>)>,
) -> anyhow::Result<()> {
    loop {
        if let Err(err) = keepalive_actor_once(
            exit_host.clone(),
            use_bridges,
            ccache.clone(),
            recv_socks5_conn.clone(),
        )
        .await
        {
            log::warn!("keepalive_actor restarting: {}", err)
        }
    }
}

async fn keepalive_actor_once(
    exit_host: String,
    use_bridges: bool,
    ccache: Arc<ClientCache>,
    recv_socks5_conn: Receiver<(String, Sender<sosistab::mux::RelConn>)>,
) -> anyhow::Result<()> {
    // do we use bridges?
    log::debug!("keepalive_actor_once");
    let connected_sess_async = async {
        if use_bridges {
            let bridges = ccache
                .get_bridges(&exit_host)
                .await
                .context("can't get bridges")?;
            // spawn a task for *every* bridge
            let (send, recv) = smol::channel::unbounded();
            let _tasks: Vec<_> = bridges
                .into_iter()
                .map(|desc| {
                    let send = send.clone();
                    smol::spawn(async move {
                        log::debug!("connecting through {}...", desc.endpoint);
                        drop(
                            send.send((
                                desc.endpoint,
                                sosistab::connect(desc.endpoint, desc.sosistab_key).await,
                            ))
                            .await,
                        )
                    })
                })
                .collect();
            // wait for a successful result
            loop {
                let (saddr, res) = recv.recv().await.context("ran out of bridges")?;
                if let Ok(res) = res {
                    log::info!("{} is our fastest bridge", saddr);
                    break Ok(res);
                }
            }
        } else {
            let exits = ccache.get_exits().await.context("can't get exits")?;
            log::debug!("getting exit_info...");
            let exit_info = exits
                .into_iter()
                .find(|v| v.hostname == exit_host)
                .ok_or_else(|| anyhow::anyhow!("no exit with this hostname"))?;
            Ok(sosistab::connect(
                smol::net::resolve(format!("{}:19831", exit_info.hostname))
                    .await
                    .context("can't resolve hostname of exit")?[0],
                exit_info.sosistab_key,
            )
            .await?)
        }
    };
    let session: anyhow::Result<sosistab::Session> = connected_sess_async
        .or(async {
            smol::Timer::after(Duration::from_secs(30)).await;
            anyhow::bail!("initial connection timeout");
        })
        .await;
    let session = session?;
    let mux = sosistab::mux::Multiplex::new(session);
    let scope = smol::Executor::new();
    // now let's authenticate
    let token = ccache.get_auth_token().await?;
    authenticate_session(&mux, &token).await?;
    // TODO actually authenticate
    log::info!(
        "KEEPALIVE MAIN LOOP for exit_host={}, use_bridges={}",
        exit_host,
        use_bridges
    );
    scope
        .run(async {
            loop {
                let (conn_host, conn_reply) = recv_socks5_conn.recv().await?;
                let mux = &mux;
                scope
                    .spawn(async move {
                        let start = Instant::now();
                        let mut remote = (&mux).open_conn().await.ok()?;
                        write_pascalish(&mut remote, &conn_host).await.ok()?;
                        log::info!(
                            "opened connection for {} in {}ms",
                            conn_host,
                            start.elapsed().as_millis()
                        );
                        conn_reply.send(remote).await.ok()?;
                        Some(())
                    })
                    .detach();
            }
        })
        .await
}

/// authenticates a muxed session
async fn authenticate_session(
    session: &sosistab::mux::Multiplex,
    token: &crate::cache::Token,
) -> anyhow::Result<()> {
    let mut auth_conn = session.open_conn().await?;
    log::debug!("sending auth info...");
    write_pascalish(
        &mut auth_conn,
        &(
            &token.unblinded_digest,
            &token.unblinded_signature,
            &token.level,
        ),
    )
    .await?;
    let _: u8 = read_pascalish(&mut auth_conn).await?;
    Ok(())
}

async fn read_pascalish<T: DeserializeOwned>(
    reader: &mut (impl AsyncRead + Unpin),
) -> anyhow::Result<T> {
    // first read 2 bytes as length
    let mut len_bts = [0u8; 2];
    reader.read_exact(&mut len_bts).await?;
    let len = u16::from_be_bytes(len_bts);
    // then read len
    let mut true_buf = vec![0u8; len as usize];
    reader.read_exact(&mut true_buf).await?;
    // then deserialize
    Ok(bincode::deserialize(&true_buf)?)
}
