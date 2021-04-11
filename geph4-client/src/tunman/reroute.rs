use std::time::{Duration, SystemTime};

use crate::{activity::timeout_multiplier, cache::ClientCache};
use anyhow::Context;
use binder_transport::ExitDescriptor;
use smol::prelude::*;
use sosistab::Multiplex;

use super::getsess::get_session;

const REROUTE_TIMEOUT: Duration = Duration::from_secs(20);

pub async fn rerouter_loop(
    tunnel_mux: &Multiplex,
    exit_info: &ExitDescriptor,
    ccache: &ClientCache,
    use_bridges: bool,
    use_tcp: bool,
) -> anyhow::Result<()> {
    let mut old_addr = None;
    // We first request the ID of the other multiplex.
    let other_id = {
        let mut conn = tunnel_mux.open_conn(Some("!id".into())).await?;
        let mut buf = [0u8; 32];
        conn.read_exact(&mut buf).await.context("!id failed")?;
        buf
    };
    loop {
        let start = SystemTime::now();
        smol::Timer::after(REROUTE_TIMEOUT.mul_f64(timeout_multiplier())).await;
        log::trace!("rerouter called after interval of {:?}", start.elapsed());
        let new_sess = get_session(exit_info, ccache, use_bridges, use_tcp).await;
        match new_sess {
            Ok(new_sess) => {
                if Some(new_sess.remote_addr()) == old_addr {
                    log::trace!("skipping hijack because the best connection was identical")
                } else {
                    old_addr = Some(new_sess.remote_addr());
                    new_sess
                        .hijack(tunnel_mux, other_id)
                        .await
                        .context("hijack failed")?;
                }
            }
            Err(err) => {
                log::warn!("rerouter failed to make new sess: {:?}", err);
            }
        }
    }
}
