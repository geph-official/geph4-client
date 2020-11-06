use std::{
    net::SocketAddr,
    sync::{atomic::AtomicUsize, Arc},
    time::Duration,
    time::SystemTime,
};

use anyhow::Context;
use binder_transport::{BinderClient, BinderRequestData, BinderResponse};
use ed25519_dalek::Signer;
use rand::prelude::*;
use smol::prelude::*;
use smol_timeout::TimeoutExt;
use smolscale::OnError;

use crate::ALLOCATOR;
/// the root context
struct RootCtx {
    stat_client: Arc<statsd::Client>,
    exit_hostname: String,
    binder_client: Arc<dyn BinderClient>,
    bridge_secret: String,
    signing_sk: ed25519_dalek::Keypair,
    sosistab_sk: x25519_dalek::StaticSecret,
    session_count: AtomicUsize,

    nursery: smolscale::Nursery,
}

impl RootCtx {
    fn new_sess(self: &Arc<Self>, sess: sosistab::Session) -> SessCtx {
        SessCtx {
            root: self.clone(),
            sess,
            nursery: smolscale::Nursery::new(),
        }
    }
}

/// per-session context
struct SessCtx {
    root: Arc<RootCtx>,
    sess: sosistab::Session,

    nursery: smolscale::Nursery,
}

/// the main listening loop
pub async fn main_loop<'a>(
    stat_client: statsd::Client,
    exit_hostname: &'a str,
    binder_client: Arc<dyn BinderClient>,
    bridge_secret: &'a str,
    signing_sk: ed25519_dalek::Keypair,
    sosistab_sk: x25519_dalek::StaticSecret,
) -> anyhow::Result<()> {
    let ctx = Arc::new(RootCtx {
        stat_client: Arc::new(stat_client),
        exit_hostname: exit_hostname.to_string(),
        binder_client,
        bridge_secret: bridge_secret.to_string(),
        signing_sk,
        sosistab_sk,
        session_count: AtomicUsize::new(0),
        nursery: smolscale::Nursery::new(),
    });
    // control protocol listener
    let control_prot_listen = smol::net::TcpListener::bind("[::0]:28080").await?;
    // future that governs the control protocol
    let control_prot_fut = async {
        loop {
            let ctx = ctx.clone();
            let sp = ctx.nursery.handle();
            let (client, _) = control_prot_listen.accept().await?;
            let claddr = client.peer_addr()?;
            sp.spawn(
                OnError::ignore_with(move |e| {
                    log::warn!("control protocol for {} died with {}", claddr, e)
                }),
                |_| handle_control(ctx, client),
            );
        }
    };
    // future that governs the "self bridge"
    let ctx1 = ctx.clone();
    let self_bridge_fut = async {
        let sosis_listener =
            sosistab::Listener::listen("[::0]:19831", ctx1.sosistab_sk.clone()).await;
        log::info!("sosis_listener initialized");
        loop {
            let sess = sosis_listener
                .accept_session()
                .await
                .ok_or_else(|| anyhow::anyhow!("can't accept from sosistab"))?;
            let ctx1 = ctx1.clone();
            let sp = ctx1.nursery.handle();
            sp.spawn(OnError::Ignore, move |_| {
                handle_session(ctx1.new_sess(sess))
            });
        }
    };
    // future that uploads gauge statistics
    let stat_client = ctx.stat_client.clone();
    let gauge_fut = async {
        let key = format!("session_count.{}", exit_hostname.replace(".", "-"));
        let memkey = format!("bytes_allocated.{}", exit_hostname.replace(".", "-"));
        loop {
            let session_count = ctx.session_count.load(std::sync::atomic::Ordering::Relaxed);
            stat_client.gauge(&key, session_count as f64);
            let memory_usage = ALLOCATOR.allocated();
            stat_client.gauge(&memkey, memory_usage as f64);
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    };
    // race
    smol::future::race(control_prot_fut, self_bridge_fut)
        .or(gauge_fut)
        .await
}

async fn handle_control<'a>(
    ctx: Arc<RootCtx>,
    mut client: smol::net::TcpStream,
) -> anyhow::Result<()> {
    let bridge_secret = ctx.bridge_secret.as_bytes();
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
    loop {
        let (their_addr, their_group): (SocketAddr, String) = aioutils::read_pascalish(&mut client)
            .or(async {
                smol::Timer::after(Duration::from_secs(60)).await;
                anyhow::bail!("timeout")
            })
            .await?;
        log::info!("bridge in group {} to forward {}", their_group, their_addr);
        // create or recall binding
        if info.is_none() {
            let ctx = ctx.clone();
            log::info!("redoing binding because info is none");
            let sosis_secret = x25519_dalek::StaticSecret::new(&mut rand::thread_rng());
            let sosis_listener = sosistab::Listener::listen("[::0]:0", sosis_secret.clone()).await;
            info = Some((
                sosis_listener.local_addr().port(),
                x25519_dalek::PublicKey::from(&sosis_secret),
            ));
            ctx.nursery
                .handle()
                .spawn(OnError::Ignore, move |nursery| async move {
                    loop {
                        let sess = sosis_listener
                            .accept_session()
                            .await
                            .ok_or_else(|| anyhow::anyhow!("could not accept sosis session"))?;
                        let ctx = ctx.clone();
                        nursery.spawn(OnError::Ignore, move |_| handle_session(ctx.new_sess(sess)));
                    }
                });
        }
        // send to the other side and then binder
        let (port, sosistab_pk) = info.unwrap();
        aioutils::write_pascalish(&mut client, &(port, sosistab_pk)).await?;
        let route_unixtime = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let to_sign =
            bincode::serialize(&(sosistab_pk, their_addr, their_group.clone(), route_unixtime))
                .unwrap();
        let exit_signature = ctx.signing_sk.sign(&to_sign);
        let binder_client = ctx.binder_client.clone();
        let exit_hostname = ctx.exit_hostname.to_string();
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
}

async fn handle_session(ctx: SessCtx) -> anyhow::Result<()> {
    log::info!("authentication started...");
    let SessCtx {
        root,
        sess,
        nursery,
    } = ctx;
    let sess = sosistab::mux::Multiplex::new(sess);
    let nhandle = nursery.handle();
    authenticate_sess(root.binder_client.clone(), &sess)
        .timeout(Duration::from_secs(10))
        .await
        .ok_or_else(|| anyhow::anyhow!("authentication timeout"))??;
    log::info!("authenticated a new session");
    root.session_count
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    scopeguard::defer!({
        root.session_count
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    });
    loop {
        let stream = sess
            .accept_conn()
            .timeout(Duration::from_secs(600))
            .await
            .ok_or_else(|| anyhow::anyhow!("accept timeout"))??;
        let root = root.clone();
        nhandle.spawn(OnError::Ignore, move |_| {
            handle_proxy_stream(root.stat_client.clone(), root.exit_hostname.clone(), stream)
        });
    }
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

async fn handle_proxy_stream(
    stat_client: Arc<statsd::Client>,
    exit_hostname: String,
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
