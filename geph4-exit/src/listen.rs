use std::{net::SocketAddr, sync::Arc, time::Duration, time::SystemTime};

use anyhow::Context;
use binder_transport::{BinderClient, BinderRequestData, BinderResponse};
use ed25519_dalek::Signer;
use rand::prelude::*;
use serde::{de::DeserializeOwned, Serialize};
use smol::prelude::*;

/// the main listening loop
pub async fn main_loop<'a>(
    exit_hostname: &'a str,
    binder_client: Arc<dyn BinderClient>,
    bridge_secret: &'a str,
    signing_sk: ed25519_dalek::Keypair,
    sosistab_sk: x25519_dalek::StaticSecret,
) -> anyhow::Result<()> {
    let scope = smol::LocalExecutor::new();
    // control protocol listener
    let control_prot_listen = smol::net::TcpListener::bind("[::0]:28080").await?;
    // future that governs the control protocol
    let control_prot_fut = async {
        loop {
            let (client, _) = control_prot_listen.accept().await?;
            scope
                .spawn(async {
                    let res = handle_control(
                        exit_hostname,
                        binder_client.clone(),
                        client,
                        bridge_secret,
                        &signing_sk,
                    )
                    .await;
                    if let Err(err) = res {
                        log::warn!("handle_control exited with error {}", err)
                    }
                })
                .detach();
        }
    };
    // future that governs the "self binder"
    let self_binder_fut = async {
        let sosis_listener = sosistab::Listener::listen("[::0]:19831", sosistab_sk).await;
        log::info!("sosis_listener initialized");
        loop {
            let sess = sosis_listener
                .accept_session()
                .await
                .ok_or_else(|| anyhow::anyhow!("can't accept from sosistab"))?;
            scope.spawn(handle_session(sess)).detach();
        }
    };
    // race
    scope
        .run(smol::future::race(control_prot_fut, self_binder_fut))
        .await
}

async fn handle_control<'a>(
    exit_hostname: &'a str,
    binder_client: Arc<dyn BinderClient>,
    mut client: smol::net::TcpStream,
    bridge_secret: &'a str,
    signing_sk: &'a ed25519_dalek::Keypair,
) -> anyhow::Result<()> {
    let bridge_secret = bridge_secret.as_bytes();
    // first, let's challenge the client to prove that they have the bridge secret
    let challenge_string: [u8; 32] = rand::thread_rng().gen();
    client
        .write_all(&challenge_string)
        .await
        .context("failed to write challenge")?;
    // then, we read back a challenge
    let mut challenge_response = [0u8; 32];
    client
        .read_exact(&mut challenge_response)
        .await
        .context("failed to read challenge response")?;
    // verify the challenge
    let correct_response = blake3::keyed_hash(&challenge_string, &bridge_secret);
    if *correct_response.as_bytes() != challenge_response {
        anyhow::bail!("failed bridge secret authentication");
    }
    // now we read their info
    let mut info: Option<(u16, x25519_dalek::PublicKey)> = None;
    let mut _task: Option<smol::Task<anyhow::Result<()>>> = None;
    let scope = smol::LocalExecutor::new();
    scope
        .run(async {
            loop {
                let (their_addr, their_group): (SocketAddr, String) = read_pascalish(&mut client)
                    .or(async {
                        smol::Timer::after(Duration::from_secs(60)).await;
                        anyhow::bail!("timeout")
                    })
                    .await?;
                log::info!("bridge in group {} to forward {}", their_group, their_addr);
                // create or recall binding
                if info.is_none() {
                    log::info!("redoing binding because info is none");
                    let sosis_secret = x25519_dalek::StaticSecret::new(&mut rand::thread_rng());
                    let sosis_listener =
                        sosistab::Listener::listen("[::0]:0", sosis_secret.clone()).await;
                    info = Some((
                        sosis_listener.local_addr().port(),
                        x25519_dalek::PublicKey::from(&sosis_secret),
                    ));
                    _task = Some(scope.spawn(async move {
                        let scope = smol::LocalExecutor::new();
                        scope
                            .run(async {
                                loop {
                                    let sess =
                                        sosis_listener.accept_session().await.ok_or_else(|| {
                                            anyhow::anyhow!("can't accept from sosistab")
                                        })?;
                                    scope.spawn(handle_session(sess)).detach();
                                }
                            })
                            .await
                    }));
                }
                // send to the other side and then binder
                let (port, sosistab_pk) = info.unwrap();
                write_pascalish(&mut client, &(port, sosistab_pk)).await?;
                let route_unixtime = SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let to_sign = bincode::serialize(&(
                    sosistab_pk,
                    their_addr,
                    their_group.clone(),
                    route_unixtime,
                ))
                .unwrap();
                let exit_signature = signing_sk.sign(&to_sign);
                let binder_client = binder_client.clone();
                let exit_hostname = exit_hostname.to_string();
                let resp = smol::unblock(move || {
                    binder_client.request(
                        BinderRequestData::AddBridgeRoute {
                            sosistab_pubkey: sosistab_pk,
                            bridge_address: their_addr,
                            bridge_group: their_group,
                            exit_hostname,
                            route_unixtime,
                            exit_signature,
                        },
                        Duration::from_secs(10),
                    )
                })
                .await
                .context("failed to go to binder")?;
                assert_eq!(resp, BinderResponse::Okay);
            }
        })
        .await
}

async fn handle_session(sess: sosistab::Session) -> anyhow::Result<()> {
    let sess = sosistab::mux::Multiplex::new(sess);
    let scope = smol::LocalExecutor::new();
    log::info!("handle_session entered");
    let handle_streams = async {
        loop {
            let stream = sess.accept_conn().await?;
            log::info!("accepted stream");
            scope.spawn(handle_proxy_stream(stream)).detach();
        }
    };
    scope.run(handle_streams).await
}

async fn handle_proxy_stream(mut client: sosistab::mux::RelConn) -> anyhow::Result<()> {
    // read proxy request
    let to_prox: String = read_pascalish(&mut client).await?;
    log::info!("proxying {}", to_prox);
    let remote = smol::net::TcpStream::connect(&to_prox)
        .or(async {
            smol::Timer::after(Duration::from_secs(10)).await;
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out remote",
            ))
        })
        .await?;
    // copy the streams
    smol::future::race(
        smol::io::copy(remote.clone(), client.clone()),
        smol::io::copy(client, remote),
    )
    .await?;
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

async fn write_pascalish<T: Serialize>(
    writer: &mut (impl AsyncWrite + Unpin),
    value: &T,
) -> anyhow::Result<()> {
    let serialized = bincode::serialize(value).unwrap();
    assert!(serialized.len() <= 65535);
    // write bytes
    writer
        .write_all(&(serialized.len() as u16).to_be_bytes())
        .await?;
    writer.write_all(&serialized).await?;
    Ok(())
}
