use std::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime},
};

use super::SessCtx;
use crate::vpn::handle_vpn_session;
use binder_transport::{BinderClient, BinderRequestData, BinderResponse};
use smol::prelude::*;
use smol_timeout::TimeoutExt;
use smolscale::OnError;
use std::sync::Arc;

pub async fn handle_session(ctx: SessCtx) -> anyhow::Result<()> {
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
    // log::debug!("proxying {} ({}, AS{})", to_prox, addr, asn);

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
            if fastrand::f32() < 0.05 {
                stat_client.count(&key, n as f64 * 20.0)
            }
        }),
        aioutils::copy_with_stats(client, remote, |n| {
            if fastrand::f32() < 0.05 {
                stat_client.count(&key, n as f64 * 20.0)
            }
        }),
    )
    .await?;
    Ok(())
}
