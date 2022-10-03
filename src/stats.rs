

use geph4_protocol::tunnel::{activity::wait_activity, ClientTunnel};
use std::{sync::Arc, time::Duration};

/// Prints stats in a loop.
pub async fn print_stats_loop(tun: Arc<ClientTunnel>) {
    loop {
        wait_activity(Duration::from_secs(200)).await;
        let stats = tun.get_stats().await;
        log::info!("** recv_loss = {:.2}% **", stats.last_loss * 100.0);
        smol::Timer::after(Duration::from_secs(30)).await;
    }
}
