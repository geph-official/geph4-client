use std::sync::atomic::Ordering;
use std::{io::Write, sync::atomic::AtomicUsize};

mod config;
mod fronts;

mod socks2http;

use colored::Colorize;

use pad::{Alignment, PadStr};

use smol::channel::Sender;
use structopt::StructOpt;

use crate::{config::Opt, connect::ConnectDaemon, debugpack::DebugPack};
mod binderproxy;
mod china;
mod connect;
mod conninfo_store;
mod debugpack;
mod main_bridgetest;

mod sync;

// #[global_allocator]
// pub static ALLOCATOR: Cap<std::alloc::System> = Cap::new(std::alloc::System, usize::max_value());

pub fn dispatch() -> anyhow::Result<()> {
    std::env::remove_var("http_proxy");
    std::env::remove_var("https_proxy");

    let (send_logs, recv_logs) = smol::channel::bounded(1000);
    config_logging(send_logs);
    let version = env!("CARGO_PKG_VERSION");
    log::info!("geph4-client v{} starting...", version);
    std::env::set_var("GEPH_VERSION", version);

    let opt = Opt::from_args();
    smolscale::block_on(async move {
        match opt {
            Opt::Connect(opt) => {
                let daemon = ConnectDaemon::start(opt).await?;
                loop {
                    let log = recv_logs.recv().await?;
                    daemon.debug().add_logline(&log);
                }
            }
            Opt::Sync(opt) => sync::main_sync(opt.clone()).await,
            Opt::BinderProxy(opt) => binderproxy::main_binderproxy(opt.clone()).await,
            Opt::BridgeTest(opt) => main_bridgetest::main_bridgetest(opt.clone()).await,
            Opt::DebugPack(opt) => {
                let pack = DebugPack::new(&opt.common.debugpack_path)?;
                pack.backup(&opt.export_to)?;
                Ok(())
            }
        }
    })
}

static LONGEST_LINE_EVER: AtomicUsize = AtomicUsize::new(0);

fn config_logging(logs: Sender<String>) {
    if let Err(e) =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(
            "geph4client=debug,geph4_protocol=debug,melprot=debug,warn,geph5=debug",
        ))
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
            let _ = logs.try_send(
                String::from_utf8_lossy(&strip_ansi_escapes::strip(line).unwrap()).to_string(),
            );
            Ok(())
        })
        .format_target(false)
        .try_init()
    {
        log::debug!("{}", e);
    }
}
