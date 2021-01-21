use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
    time::SystemTime,
};

use anyhow::Context;
use binder_transport::{BinderClient, BinderRequestData, BinderResponse};
use ed25519_dalek::Signer;
use rand::prelude::*;
use smol::{channel::Sender, prelude::*};
use smol_timeout::TimeoutExt;
use smolscale::OnError;

use crate::{vpn::handle_vpn_session, ALLOCATOR};
/// the root context
struct RootCtx {
    stat_client: Arc<statsd::Client>,
    exit_hostname: String,
    binder_client: Arc<dyn BinderClient>,
    bridge_secret: String,
    signing_sk: ed25519_dalek::Keypair,
    sosistab_sk: x25519_dalek::StaticSecret,

    session_count: AtomicUsize,
    conn_count: AtomicUsize,

    free_limit: u32,
    port_whitelist: bool,

    google_proxy: Option<SocketAddr>,

    nursery: smolscale::NurseryHandle,
}

impl RootCtx {
    fn new_sess(self: &Arc<Self>, sess: sosistab::Session) -> SessCtx {
        let new_nurs = smolscale::Nursery::new();
        let new_hand = new_nurs.handle();
        self.nursery.spawn(OnError::Ignore, |_| new_nurs.wait());
        SessCtx {
            root: self.clone(),
            sess,
            nursery: new_hand,
        }
    }
}

/// per-session context
struct SessCtx {
    root: Arc<RootCtx>,
    sess: sosistab::Session,

    nursery: smolscale::NurseryHandle,
}

/// the main listening loop
#[allow(clippy::clippy::too_many_arguments)]
pub async fn main_loop<'a>(
    stat_client: statsd::Client,
    exit_hostname: &'a str,
    binder_client: Arc<dyn BinderClient>,
    bridge_secret: &'a str,
    signing_sk: ed25519_dalek::Keypair,
    sosistab_sk: x25519_dalek::StaticSecret,
    free_limit: u32,
    google_proxy: Option<SocketAddr>,
    port_whitelist: bool,
) -> anyhow::Result<()> {
    let nursery = smolscale::Nursery::new();
    let ctx = Arc::new(RootCtx {
        stat_client: Arc::new(stat_client),
        exit_hostname: exit_hostname.to_string(),
        binder_client,
        bridge_secret: bridge_secret.to_string(),
        signing_sk,
        sosistab_sk,
        session_count: AtomicUsize::new(0),
        conn_count: AtomicUsize::new(0),
        free_limit,
        port_whitelist,
        google_proxy,
        nursery: nursery.handle(),
    });

    // control protocol listener
    let control_prot_listen = smol::net::TcpListener::bind("[::0]:28080").await?;
    // future that governs the control protocol
    let control_prot_fut = async {
        loop {
            let ctx = ctx.clone();
            let sp = ctx.nursery.clone();
            let (client, _) = control_prot_listen.accept().await?;
            let claddr = client.peer_addr()?;
            sp.spawn(
                OnError::ignore_with(move |e| {
                    log::warn!("control protocol for {} died with {:?}", claddr, e)
                }),
                |_| handle_control(ctx, client),
            );
        }
    };
    let exit_hostname2 = exit_hostname.to_string();
    let bridge_pkt_key = move |bridge_group: &str| {
        format!(
            "raw_flow.{}.{}",
            exit_hostname2.replace(".", "-"),
            bridge_group.replace(".", "-")
        )
    };
    // future that governs the "self bridge"
    let ctx1 = ctx.clone();
    let stat = ctx1.stat_client.clone();
    let self_bridge_fut = async {
        let flow_key = bridge_pkt_key("SELF");
        let stat2 = stat.clone();
        let fk2 = flow_key.clone();
        let sosis_listener = sosistab::Listener::listen(
            "[::0]:19831",
            ctx1.sosistab_sk.clone(),
            move |len, _| stat.sampled_count(&flow_key, len as f64, 0.1),
            move |len, _| stat2.sampled_count(&fk2, len as f64, 0.1),
        )
        .await;
        log::debug!("sosis_listener initialized");
        loop {
            let sess = sosis_listener
                .accept_session()
                .await
                .ok_or_else(|| anyhow::anyhow!("can't accept from sosistab"))?;
            let ctx1 = ctx1.clone();
            let sp = ctx1.nursery.clone();
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
        let connkey = format!("conn_count.{}", exit_hostname.replace(".", "-"));
        loop {
            let session_count = ctx.session_count.load(std::sync::atomic::Ordering::Relaxed);
            stat_client.gauge(&key, session_count as f64);
            let memory_usage = ALLOCATOR.allocated();
            stat_client.gauge(&memkey, memory_usage as f64);
            let conn_count = ctx.conn_count.load(std::sync::atomic::Ordering::Relaxed);
            stat_client.gauge(&connkey, conn_count as f64);
            smol::Timer::after(Duration::from_secs(5)).await;
        }
    };
    // race
    smol::future::race(control_prot_fut, self_bridge_fut)
        .or(gauge_fut)
        .or(nursery.wait())
        .await
}

async fn handle_control<'a>(
    ctx: Arc<RootCtx>,
    mut client: smol::net::TcpStream,
) -> anyhow::Result<()> {
    let exit_hostname = ctx.exit_hostname.clone();
    let bridge_pkt_key = move |bridge_group: &str| {
        format!(
            "raw_flow.{}.{}",
            exit_hostname.replace(".", "-"),
            bridge_group.replace(".", "-")
        )
    };

    let bridge_secret = ctx.bridge_secret.as_bytes();
    // first, let's challenge the client to prove that they have the bridge secret
    let challenge_string: [u8; 32] = rand::thread_rng().gen();
    client
        .write_all(&challenge_string)
        .timeout(Duration::from_secs(10))
        .await
        .ok_or_else(|| anyhow::anyhow!("challenge send timeout"))
        .context("failed to write challenge")??;
    // then, we read back a challenge
    let mut challenge_response = [0u8; 32];
    client
        .read_exact(&mut challenge_response)
        .timeout(Duration::from_secs(10))
        .await
        .ok_or_else(|| anyhow::anyhow!("challenge recv timeout"))
        .context("failed to read challenge response")??;
    // verify the challenge
    let correct_response = blake3::keyed_hash(&challenge_string, &bridge_secret);
    if *correct_response.as_bytes() != challenge_response {
        anyhow::bail!("failed bridge secret authentication");
    }
    // now we read their info
    let mut info: Option<(u16, x25519_dalek::PublicKey, Sender<()>)> = None;
    loop {
        let (their_addr, their_group): (SocketAddr, String) = aioutils::read_pascalish(&mut client)
            .or(async {
                smol::Timer::after(Duration::from_secs(600)).await;
                anyhow::bail!("timeout read")
            })
            .await?;
        let flow_key = bridge_pkt_key(&their_group);
        log::debug!("bridge in group {} to forward {}", their_group, their_addr);
        // create or recall binding
        if info.is_none() {
            let ctx = ctx.clone();
            let stat = ctx.stat_client.clone();
            let stat2 = stat.clone();
            let fk2 = flow_key.clone();
            log::debug!("redoing binding because info is none");
            let sosis_secret = x25519_dalek::StaticSecret::new(&mut rand::thread_rng());
            let sosis_listener = sosistab::Listener::listen(
                "[::0]:0",
                sosis_secret.clone(),
                move |len, _| stat.sampled_count(&flow_key, len as f64, 0.01),
                move |len, _| stat2.sampled_count(&fk2, len as f64, 0.01),
            )
            .await;
            let (send, recv) = smol::channel::bounded(1);
            info = Some((
                sosis_listener.local_addr().port(),
                x25519_dalek::PublicKey::from(&sosis_secret),
                send,
            ));
            // spawn a task that dies when the binding is gone
            ctx.nursery.clone().spawn(OnError::Ignore, move |nursery| {
                async move {
                    loop {
                        let sess = sosis_listener
                            .accept_session()
                            .await
                            .ok_or_else(|| anyhow::anyhow!("could not accept sosis session"))?;
                        let ctx = ctx.clone();
                        nursery.spawn(OnError::Ignore, move |_| handle_session(ctx.new_sess(sess)));
                    }
                }
                .or(async move { Ok(recv.recv().await?) })
            });
        }
        // send to the other side and then binder
        let (port, sosistab_pk, _) = info.as_ref().unwrap();
        aioutils::write_pascalish(&mut client, &(port, sosistab_pk))
            .or(async {
                smol::Timer::after(Duration::from_secs(600)).await;
                anyhow::bail!("timeout write")
            })
            .await?;
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
        let resp = binder_client
            .request(BinderRequestData::AddBridgeRoute {
                sosistab_pubkey: *sosistab_pk,
                bridge_address: their_addr,
                bridge_group: their_group,
                exit_hostname,
                route_unixtime,
                exit_signature,
            })
            .await
            .context("failed to go to binder")?;
        assert_eq!(resp, BinderResponse::Okay);
    }
}

async fn handle_session(ctx: SessCtx) -> anyhow::Result<()> {
    let SessCtx {
        root,
        sess,
        nursery,
    } = ctx;
    let sess = Arc::new(sosistab::mux::Multiplex::new(sess));
    let nhandle = nursery.clone();
    let is_plus = authenticate_sess(root.binder_client.clone(), &sess)
        .timeout(Duration::from_secs(300))
        .await
        .ok_or_else(|| anyhow::anyhow!("authentication timeout"))??;
    log::info!("authenticated a new session (is_plus = {})", is_plus);
    if !is_plus {
        if root.free_limit == 0 {
            anyhow::bail!("not accepting free users here")
        }
        sess.get_session().set_ratelimit(root.free_limit);
    }

    let (send_sess_alive, recv_sess_alive) = smol::channel::bounded(1);
    let sess_alive_loop = async {
        let alive = AtomicBool::new(false);
        let guard = scopeguard::guard(alive, |v| {
            if v.load(Ordering::SeqCst) {
                root.session_count
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            }
        });
        loop {
            let signal = recv_sess_alive
                .recv()
                .timeout(Duration::from_secs(600))
                .await;
            if let Some(sig) = signal {
                let _ = sig?;
                if !guard.swap(true, Ordering::SeqCst) {
                    root.session_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            } else if guard.swap(false, Ordering::SeqCst) {
                root.session_count
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    };

    let proxy_loop = async {
        loop {
            let stream = sess.accept_conn().await?;
            let root = root.clone();
            let send_sess_alive = send_sess_alive.clone();
            nhandle.spawn(OnError::Ignore, move |_| async move {
                root.conn_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let _deferred = scopeguard::guard((), |_| {
                    root.conn_count
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                });
                let _ = send_sess_alive.try_send(());
                handle_proxy_stream(
                    root.stat_client.clone(),
                    root.exit_hostname.clone(),
                    root.port_whitelist,
                    stream,
                    root.google_proxy,
                )
                .await
            });
        }
    };
    let vpn_loop = handle_vpn_session(
        sess.clone(),
        root.exit_hostname.clone(),
        root.stat_client.clone(),
        root.port_whitelist,
    );
    smol::future::race(proxy_loop.or(sess_alive_loop), vpn_loop).await
}

async fn authenticate_sess(
    binder_client: Arc<dyn BinderClient>,
    sess: &sosistab::mux::Multiplex,
) -> anyhow::Result<bool> {
    let mut stream = sess.accept_conn().await?;
    log::debug!("authenticating session...");
    // wait for a message containing a blinded signature
    let (auth_tok, auth_sig, level): (Vec<u8>, mizaru::UnblindedSignature, String) =
        aioutils::read_pascalish(&mut stream).await?;
    if (auth_sig.epoch as i32 - mizaru::time_to_epoch(SystemTime::now()) as i32).abs() > 2 {
        anyhow::bail!("outdated authentication token")
    }
    let is_plus = level != "free";
    // validate it through the binder
    let res = binder_client
        .request(BinderRequestData::Validate {
            level: level.clone(),
            unblinded_digest: auth_tok,
            unblinded_signature: auth_sig,
        })
        .await?;
    if res != BinderResponse::ValidateResp(true) {
        anyhow::bail!("unexpected authentication response from binder: {:?}", res)
    }
    // send response
    aioutils::write_pascalish(&mut stream, &1u8).await?;
    Ok(is_plus)
}

async fn handle_proxy_stream(
    stat_client: Arc<statsd::Client>,
    exit_hostname: String,
    port_whitelist: bool,
    mut client: sosistab::mux::RelConn,
    google_proxy: Option<SocketAddr>,
) -> anyhow::Result<()> {
    // read proxy request
    let to_prox: String = match client.additional_info() {
        Some(s) => s.to_string(),
        None => aioutils::read_pascalish(&mut client).await?,
    };
    let addr = smol::net::resolve(&to_prox)
        .await?
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("dns failed"))?;
    let asn = crate::asn::get_asn(addr.ip());
    log::debug!("proxying {} ({}, AS{})", to_prox, addr, asn);

    if crate::lists::BLACK_PORTS.contains(&addr.port()) {
        anyhow::bail!("port blacklisted")
    }
    if port_whitelist && !crate::lists::WHITE_PORTS.contains(&addr.port()) {
        anyhow::bail!("port not whitelisted")
    }

    // what should we connect to depends on whether or not it's google
    let to_conn = if let Some(proxy) = google_proxy {
        if addr.port() == 443 && asn == crate::asn::GOOGLE_ASN {
            proxy
        } else {
            addr
        }
    } else {
        addr
    };
    let remote = smol::net::TcpStream::connect(&to_conn)
        .or(async {
            smol::Timer::after(Duration::from_secs(60)).await;
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out remote",
            ))
        })
        .await?;
    // this is fine because just connecting to a local service is not a security problem
    if &to_prox != "127.0.0.1:3128" && (addr.ip().is_loopback() || addr.ip().is_multicast()) {
        anyhow::bail!("attempted a connection to a non-global IP address")
    }

    remote.set_nodelay(true)?;
    let key = format!("exit_usage.{}", exit_hostname.replace(".", "-"));
    // copy the streams
    smol::future::race(
        aioutils::copy_with_stats(remote.clone(), client.clone(), |n| {
            stat_client.sampled_count(&key, n as f64, 0.01);
        }),
        aioutils::copy_with_stats(client, remote, |n| {
            stat_client.sampled_count(&key, n as f64, 0.01);
        }),
    )
    .await?;
    Ok(())
}
