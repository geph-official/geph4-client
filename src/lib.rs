use std::ops::Deref;

mod config;
mod fronts;

mod socks2http;

use crate::config::{Opt, CONFIG};
mod binderproxy;
mod china;
mod connect;

// #[cfg(target_os = "ios")]
pub mod ios;

mod debugpak;
mod main_bridgetest;
mod sync;

pub fn dispatch() -> anyhow::Result<()> {
    std::env::remove_var("http_proxy");
    std::env::remove_var("https_proxy");
    config_logging();
    let version = env!("CARGO_PKG_VERSION");
    log::info!("geph4-client v{} starting...", version);

    smolscale::permanently_single_threaded();

    smolscale::block_on(async move {
        match CONFIG.deref() {
            Opt::Connect(_opt) => {
                connect::start_main_connect();
                smol::future::pending().await
            }
            Opt::Sync(opt) => sync::main_sync(opt.clone()).await,
            Opt::BinderProxy(opt) => binderproxy::main_binderproxy(opt.clone()).await,
            Opt::BridgeTest(opt) => main_bridgetest::main_bridgetest(opt.clone()).await,
        }
    })
}

fn config_logging() {
    if let Err(e) = env_logger::Builder::from_env(
        env_logger::Env::default()
            .default_filter_or("geph4client=debug,geph4_protocol=debug,warn,geph_nat=debug"),
    )
    .format_timestamp_millis()
    .format_target(false)
    .try_init()
    {
        log::debug!("{}", e);
    }
}
