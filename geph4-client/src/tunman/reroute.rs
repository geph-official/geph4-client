use std::time::{Duration, SystemTime};

use binder_transport::ExitDescriptor;
use sosistab::Multiplex;

use crate::{activity::timeout_multiplier, cache::ClientCache};

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
    loop {
        let start = SystemTime::now();
        smol::Timer::after(REROUTE_TIMEOUT.mul_f64(timeout_multiplier())).await;
        log::info!("rerouter called after interval of {:?}", start.elapsed());
        let new_sess = get_session(exit_info, ccache, use_bridges, use_tcp).await;
        match new_sess {
            Ok(new_sess) => {
                if Some(new_sess.remote_addr()) == old_addr {
                    log::debug!("skipping hijack because the best connection was identical")
                } else {
                    old_addr = Some(new_sess.remote_addr());
                    new_sess.hijack(tunnel_mux).await?;
                }
            }
            Err(err) => {
                log::warn!("rerouter failed to make new sess: {:?}", err);
            }
        }
    }
}
