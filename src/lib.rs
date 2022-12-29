use std::io::Write;
use std::ops::Deref;

mod config;
mod fronts;

mod socks2http;

use cap::Cap;
use once_cell::sync::Lazy;

use crate::{
    config::{Opt, CONFIG},
    debugpack::{DEBUGPACK, TIMESERIES_LOOP},
};
mod binderproxy;
mod china;
mod connect;

// #[cfg(target_os = "ios")]
pub mod ios;

mod debugpack;
mod main_bridgetest;
mod sync;

#[global_allocator]
pub static ALLOCATOR: Cap<std::alloc::System> = Cap::new(std::alloc::System, usize::max_value());

pub fn dispatch() -> anyhow::Result<()> {
    std::env::remove_var("http_proxy");
    std::env::remove_var("https_proxy");
    Lazy::force(&TIMESERIES_LOOP);
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
            Opt::Debugpack(opt) => debugpack::export_debugpak(&opt.export_to),
        }
    })
}

fn config_logging() {
    if let Err(e) = env_logger::Builder::from_env(
        env_logger::Env::default()
            .default_filter_or("geph4client=debug,geph4_protocol=debug,warn,geph_nat=debug"),
    )
    .format_timestamp_millis()
    .format(move |buf, record| {
        let line = format!(
            "[{} {}]: {}",
            record.level(),
            record.module_path().unwrap_or("none"),
            record.args()
        );
        writeln!(buf, "{}", line).unwrap();
        let _ = DEBUGPACK.add_logline(&line);
        Ok(())
    })
    .format_target(false)
    .try_init()
    {
        log::debug!("{}", e);
    }
}
