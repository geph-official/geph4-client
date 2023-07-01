use std::{io::Write, sync::atomic::AtomicUsize};
use std::{ops::Deref, sync::atomic::Ordering};

mod config;
mod fronts;

mod melprot_cache;
mod socks2http;

use cap::Cap;
use colored::Colorize;
use melprot_cache::FlatFileStateCache;
use once_cell::sync::Lazy;
use pad::{Alignment, PadStr};

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
    std::env::set_var("GEPH_VERSION", version);
    config_melprot_cache()?;
    smolscale::block_on(async move {
        match CONFIG.deref() {
            Opt::Connect(_) => {
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

static LONGEST_LINE_EVER: AtomicUsize = AtomicUsize::new(0);

fn config_logging() {
    if let Err(e) = env_logger::Builder::from_env(
        env_logger::Env::default()
            .default_filter_or("geph4client=debug,geph4_protocol=debug,melprot=debug,warn"),
    )
    .format_timestamp_millis()
    .format(move |buf, record| {
        let preamble = format!(
            "[{} {}]:",
            record.module_path().unwrap_or("none").dimmed(),
            match record.level() {
                log::Level::Error => "ERRO".red(),
                log::Level::Warn => "WARN".bright_yellow(),
                log::Level::Info => "INFO".bright_green(),
                log::Level::Debug => "DEBG".bright_blue(),
                log::Level::Trace => "TRAC".bright_black(),
            },
        );
        let len = strip_ansi_escapes::strip(&preamble).unwrap().len();
        let longest = LONGEST_LINE_EVER.fetch_max(len, Ordering::SeqCst);
        let preamble = ""
            .pad_to_width_with_alignment(longest.saturating_sub(len), Alignment::Right)
            + &preamble;
        let line = format!("{} {}", preamble, record.args());
        writeln!(buf, "{}", line).unwrap();
        DEBUGPACK.add_logline(&String::from_utf8_lossy(
            &strip_ansi_escapes::strip(line).unwrap(),
        ));
        Ok(())
    })
    .format_target(false)
    .try_init()
    {
        log::debug!("{}", e);
    }
}

fn config_melprot_cache() -> anyhow::Result<()> {
    let path = match CONFIG.deref() {
        Opt::Connect(opt) => Some(&opt.auth.credential_cache),
        Opt::BridgeTest(opt) => Some(&opt.auth.credential_cache),
        Opt::Sync(opt) => Some(&opt.auth.credential_cache),
        Opt::BinderProxy(_) => None,
        Opt::Debugpack(_) => None,
    };
    if let Some(mut path) = path.cloned() {
        path.push("melprot");
        let cache = FlatFileStateCache::open(&path)?;
        melprot::set_global_cache(cache);
        log::debug!("set up global melprot cache at {:?}", path);
    }
    Ok(())
}
