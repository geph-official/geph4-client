use std::time::{Duration, SystemTime};

use crate::{
    activity::{self},
    cache::ClientCache,
};
use activity::wait_activity;
use anyhow::Context;
use async_net::SocketAddr;
use binder_transport::ExitDescriptor;
use smol::prelude::*;
use sosistab::Multiplex;

use super::getsess::get_session;

pub async fn rerouter_loop(
    tunnel_mux: &Multiplex,
    exit_info: &ExitDescriptor,
    bridge_addr: SocketAddr,
    ccache: &ClientCache,
    use_bridges: bool,
    use_tcp: bool,
) -> anyhow::Result<()> {
    let mut old_addr = bridge_addr;
    // We first request the ID of the other multiplex.
    let other_id = {
        let mut conn = tunnel_mux.open_conn(Some("!id".into())).await?;
        let mut buf = [0u8; 32];
        conn.read_exact(&mut buf).await.context("!id failed")?;
        buf
    };
    loop {
        let start = SystemTime::now();
        wait_activity().await;
        log::trace!("rerouter called after interval of {:?}", start.elapsed());
        let new_sess = get_session(exit_info, ccache, use_bridges, use_tcp, Some(old_addr)).await;
        match new_sess {
            Ok(new_sess) => {
                if new_sess.remote_addr() == old_addr {
                    log::trace!("skipping hijack because the best connection was identical")
                } else {
                    old_addr = new_sess.remote_addr();
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
        smol::Timer::after(Duration::from_secs(30)).await;
    }
}
