use std::{io::Write, sync::atomic::AtomicUsize, time::Duration};
use std::{sync::atomic::Ordering};

mod config;
mod fronts;

mod melprot_cache;
mod socks2http;

use cap::Cap;
use clone_macro::clone;
use colored::Colorize;


use pad::{Alignment, PadStr};
use smolscale::immortal::{Immortal, RespawnStrategy};
use structopt::StructOpt;

use crate::config::Opt;
mod binderproxy;
mod china;
mod connect;
mod conninfo_store;
mod metrics;

mod debugpack;
mod main_bridgetest;
mod sync;

#[global_allocator]
pub static ALLOCATOR: Cap<std::alloc::System> = Cap::new(std::alloc::System, usize::max_value());

pub fn dispatch() -> anyhow::Result<()> {
    std::env::remove_var("http_proxy");
    std::env::remove_var("https_proxy");

    config_logging();
    let version = env!("CARGO_PKG_VERSION");
    log::info!("geph4-client v{} starting...", version);
    std::env::set_var("GEPH_VERSION", version);

    let opt = Opt::from_args();
    smolscale::block_on(async move {
        match opt {
            Opt::Connect(opt) => {
                let _loop = Immortal::respawn(
                    RespawnStrategy::JitterDelay(Duration::from_secs(1), Duration::from_secs(5)),
                    clone!([opt], move || connect::connect_loop(opt.clone())),
                );
                smol::future::pending().await
            }
            Opt::Sync(opt) => sync::main_sync(opt.clone()).await,
            Opt::BinderProxy(opt) => binderproxy::main_binderproxy(opt.clone()).await,
            Opt::BridgeTest(opt) => main_bridgetest::main_bridgetest(opt.clone()).await,
            Opt::Debugpack(_opt) => todo!(),
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

        Ok(())
    })
    .format_target(false)
    .try_init()
    {
        log::debug!("{}", e);
    }
}

fn log_restart_error<E>(label: &str) -> impl FnOnce(E) + '_
where
    E: std::fmt::Debug,
{
    move |s| log::warn!("{label} restart, error: {:?}", s)
}
