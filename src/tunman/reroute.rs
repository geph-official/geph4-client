use anyhow::Context;
use async_net::SocketAddr;
use sosistab::Multiplex;

use super::{getsess::get_session, tunnelctx::TunnelCtx};

pub async fn rerouter_once(
    ctx: TunnelCtx,
    bridge_addr: SocketAddr,
    tunnel_mux: &Multiplex,
    other_id: [u8; 32],
) -> anyhow::Result<()> {
    let new_sess = get_session(ctx.clone(), Some(bridge_addr)).await;
    match new_sess {
        Ok(new_sess) => {
            // if new_sess.remote_addr() == bridge_addr {
            //     log::trace!("skipping hijack because the best connection was identical");
            // } else {
            new_sess
                .hijack(tunnel_mux, other_id)
                .await
                .context("hijack failed")?;
            // }
            Ok(())
        }
        Err(err) => {
            anyhow::bail!("rerouter failed to make new sess: {:?}", err);
        }
    }
}
