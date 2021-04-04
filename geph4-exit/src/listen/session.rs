use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime},
};

use super::SessCtx;
use crate::{connect::proxy_loop, vpn::handle_vpn_session};
use binder_transport::{BinderClient, BinderRequestData, BinderResponse};

use futures_util::TryFutureExt;
use smol::prelude::*;
use smol_timeout::TimeoutExt;

use std::sync::Arc;

pub async fn handle_session(ctx: SessCtx) -> anyhow::Result<()> {
    let SessCtx { root, sess } = ctx;

    // raw session count
    root.raw_session_count
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let _guard = scopeguard::guard((), |_| {
        root.raw_session_count
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    });

    let sess = Arc::new(sosistab::Multiplex::new(sess));
    let is_plus = authenticate_sess(root.binder_client.clone(), &sess)
        .timeout(Duration::from_secs(300))
        .await
        .ok_or_else(|| anyhow::anyhow!("authentication timeout"))??;
    log::info!(
        "authenticated a new session (is_plus = {}, raw_session_count = {})",
        is_plus,
        root.raw_session_count.load(Ordering::Relaxed)
    );
    if !is_plus {
        if root.free_limit == 0 {
            anyhow::bail!("not accepting free users here")
        }
        sess.get_session().set_ratelimit(root.free_limit);
    }

    let (send_sess_alive, recv_sess_alive) = smol::channel::bounded(1);
    let sess_alive_loop = {
        let recv_sess_alive = recv_sess_alive.clone();
        let root = root.clone();
        async move {
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
        }
    };

    let proxy_loop = {
        let root = root.clone();
        let sess = sess.clone();
        async move {
            loop {
                let client = sess.accept_conn().await?;
                let send_sess_alive = send_sess_alive.clone();
                let root = root.clone();
                smolscale::spawn(
                    async move {
                        let _ = send_sess_alive.try_send(());
                        let addr = client.additional_info().unwrap_or_default().to_owned();
                        proxy_loop(root, client, addr, true).await
                    }
                    .map_err(|e| log::trace!("proxy conn closed: {}", e)),
                )
                .detach();
            }
        }
    };
    let vpn_loop = handle_vpn_session(
        sess.clone(),
        root.exit_hostname.clone(),
        root.stat_client.clone(),
        root.port_whitelist,
    );

    (proxy_loop.or(sess_alive_loop)).race(vpn_loop).await
}

async fn authenticate_sess(
    binder_client: Arc<dyn BinderClient>,
    sess: &sosistab::Multiplex,
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
