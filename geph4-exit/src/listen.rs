use std::{net::SocketAddr, sync::Arc, time::Duration, time::SystemTime};

use anyhow::Context;
use binder_transport::{BinderClient, BinderRequestData, BinderResponse};
use ed25519_dalek::Signer;
use rand::prelude::*;
use smol::prelude::*;
use smol_timeout::TimeoutExt;

/// the main listening loop
pub async fn main_loop<'a>(
    stat_client: statsd::Client,
    exit_hostname: &'a str,
    binder_client: Arc<dyn BinderClient>,
    bridge_secret: &'a str,
    signing_sk: ed25519_dalek::Keypair,
    sosistab_sk: x25519_dalek::StaticSecret,
) -> anyhow::Result<()> {
    let scope = smol::Executor::new();
    // control protocol listener
    let control_prot_listen = smol::net::TcpListener::bind("[::0]:28080").await?;
    // future that governs the control protocol
    let control_prot_fut = async {
        loop {
            let (client, _) = control_prot_listen.accept().await?;
            scope
                .spawn(async {
                    let res = handle_control(
                        &stat_client,
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
            scope
                .spawn(handle_session(
                    &stat_client,
                    exit_hostname,
                    binder_client.clone(),
                    sess,
                ))
                .detach();
        }
    };
    // race
    scope
        .run(smol::future::race(control_prot_fut, self_binder_fut))
        .await
}

async fn handle_control<'a>(
    stat_client: &'a statsd::Client,
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
    let scope = smol::Executor::new();
    scope
        .run(async {
            loop {
                let (their_addr, their_group): (SocketAddr, String) =
                    aioutils::read_pascalish(&mut client)
                        .or(async {
                            smol::Timer::after(Duration::from_secs(60)).await;
                            anyhow::bail!("timeout")
                        })
                        .await?;
                log::info!("bridge in group {} to forward {}", their_group, their_addr);
                // create or recall binding
                if info.is_none() {
                    let binder_client = binder_client.clone();
                    log::info!("redoing binding because info is none");
                    let sosis_secret = x25519_dalek::StaticSecret::new(&mut rand::thread_rng());
                    let sosis_listener =
                        sosistab::Listener::listen("[::0]:0", sosis_secret.clone()).await;
                    info = Some((
                        sosis_listener.local_addr().port(),
                        x25519_dalek::PublicKey::from(&sosis_secret),
                    ));
                    _task = Some(scope.spawn(async move {
                        let scope = smol::Executor::new();
                        let binder_client = binder_client.clone();
                        scope
                            .run(async {
                                let binder_client = binder_client.clone();
                                loop {
                                    let sess =
                                        sosis_listener.accept_session().await.ok_or_else(|| {
                                            anyhow::anyhow!("can't accept from sosistab")
                                        })?;
                                    scope
                                        .spawn(handle_session(
                                            &stat_client,
                                            exit_hostname,
                                            binder_client.clone(),
                                            sess,
                                        ))
                                        .detach();
                                }
                            })
                            .await
                    }));
                }
                // send to the other side and then binder
                let (port, sosistab_pk) = info.unwrap();
                aioutils::write_pascalish(&mut client, &(port, sosistab_pk)).await?;
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

async fn handle_session<'a>(
    stat_client: &'a statsd::Client,
    exit_hostname: &'a str,
    binder_client: Arc<dyn BinderClient>,
    sess: sosistab::Session,
) -> anyhow::Result<()> {
    log::info!("authentication started...");
    let sess = sosistab::mux::Multiplex::new(sess);
    let scope = smol::Executor::new();
    let handle_streams = async {
        authenticate_sess(binder_client.clone(), &sess)
            .timeout(Duration::from_secs(10))
            .await
            .ok_or_else(|| anyhow::anyhow!("authentication timeout"))??;
        log::info!("authenticated a new session");
        loop {
            let stream = sess
                .accept_conn()
                .timeout(Duration::from_secs(600))
                .await
                .ok_or_else(|| anyhow::anyhow!("accept timeout"))??;
            scope
                .spawn(handle_proxy_stream(stat_client, exit_hostname, stream))
                .detach();
        }
    };
    scope.run(handle_streams).await
}

async fn authenticate_sess(
    binder_client: Arc<dyn BinderClient>,
    sess: &sosistab::mux::Multiplex,
) -> anyhow::Result<()> {
    let mut stream = sess.accept_conn().await?;
    log::debug!("authenticating session...");
    // wait for a message containing a blinded signature
    let (auth_tok, auth_sig, level): (Vec<u8>, mizaru::UnblindedSignature, String) =
        aioutils::read_pascalish(&mut stream).await?;
    if (auth_sig.epoch as i32 - mizaru::time_to_epoch(SystemTime::now()) as i32).abs() > 2 {
        anyhow::bail!("outdated authentication token")
    }
    // validate it through the binder
    let res = smol::unblock(move || {
        binder_client.request(
            BinderRequestData::Validate {
                level,
                unblinded_digest: auth_tok,
                unblinded_signature: auth_sig,
            },
            Duration::from_secs(10),
        )
    })
    .await?;
    if res != BinderResponse::ValidateResp(true) {
        anyhow::bail!("unexpected authentication response from binder: {:?}", res)
    }
    // send response
    aioutils::write_pascalish(&mut stream, &1u8).await?;
    Ok(())
}

async fn handle_proxy_stream<'a>(
    stat_client: &'a statsd::Client,
    exit_hostname: &'a str,
    mut client: sosistab::mux::RelConn,
) -> anyhow::Result<()> {
    // read proxy request
    let to_prox: String = match client.additional_info() {
        Some(s) => s.to_string(),
        None => aioutils::read_pascalish(&mut client).await?,
    };
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
    // this is fine because just connecting to a local service is not a security problem
    if &to_prox != "127.0.0.1:3128" {
        if let Ok(peer_addr) = remote.peer_addr() {
            if peer_addr.ip().is_loopback() || peer_addr.ip().is_multicast() {
                anyhow::bail!("attempted a connection to a non-global IP address")
            }
        }
    }
    let key = format!("exit_usage.{}", exit_hostname.replace(".", "-"));
    // copy the streams
    smol::future::race(
        aioutils::copy_with_stats(remote.clone(), client.clone(), |n| {
            stat_client.sampled_count(&key, n as f64, 0.5);
        }),
        aioutils::copy_with_stats(client, remote, |n| {
            stat_client.sampled_count(&key, n as f64, 0.5);
        }),
    )
    .await?;
    Ok(())
}
