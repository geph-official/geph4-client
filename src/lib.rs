use std::ffi::{c_char, c_uchar, CStr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::{io::Write, sync::atomic::AtomicUsize};

mod config;
mod fronts;

mod socks2http;

use colored::Colorize;

use libc::c_int;
use once_cell::sync::Lazy;
use pad::{Alignment, PadStr};

use sharded_slab::Slab;
use smol::channel::Sender;
use structopt::StructOpt;
use sync::sync_json;

use crate::binderproxy::binderproxy_once;
use crate::config::CommonOpt;
use crate::sync::SyncOpt;
use crate::{config::Opt, connect::ConnectDaemon, debugpack::DebugPack};
mod binderproxy;
mod china;
mod connect;
mod conninfo_store;
mod debugpack;
mod main_bridgetest;
mod metrics;
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

static SLAB: Lazy<Slab<ConnectDaemon>> = Lazy::new(|| Slab::new());

pub unsafe extern "C" fn start(opt_json: *const c_char) -> c_int {
    if let Ok(opt_str) = unsafe { CStr::from_ptr(opt_json) }.to_str() {
        if let Ok(opt) = serde_json::from_str(opt_str) {
            let daemon = smolscale::block_on(async { ConnectDaemon::start(opt).await.unwrap() });
            SLAB.insert(daemon).unwrap() as c_int
        } else {
            -2
        }
    } else {
        -1
    }
}

pub extern "C" fn stop(daemon_key: c_int) -> c_int {
    SLAB.remove(daemon_key as usize);
    0
}

pub extern "C" fn sync(opt_json: *const c_char, inout: *mut c_char, buflen: c_int) -> c_int {
    let opt_str = unsafe { CStr::from_ptr(opt_json) }.to_str().unwrap();
    let opt: SyncOpt = serde_json::from_str(opt_str).unwrap();
    let resp = smolscale::block_on(async { sync_json(opt).await.unwrap() });
    fill_inout(inout, buflen, resp.as_bytes())
}

pub extern "C" fn binder_rpc(req: *const c_char, inout: *mut c_char, buflen: c_int) -> c_int {
    let req_str = unsafe { CStr::from_ptr(req) }.to_str().unwrap();
    let binder_client = Arc::new(CommonOpt::from_iter(vec![""]).get_binder_client());
    if let Ok(resp) = smolscale::block_on(binderproxy_once(binder_client, req_str.to_owned())) {
        log::debug!("binder resp = {resp}");
        fill_inout(inout, buflen, resp.as_bytes());
        0
    } else {
        -1
    }
}

pub unsafe extern "C" fn send_vpn(daemon_key: c_int, pkt: *const c_uchar, len: c_int) -> c_int {
    let daemon = if let Some(daemon) = SLAB.get(daemon_key as _) {
        daemon
    } else {
        return -1;
    };
    let slice = std::slice::from_raw_parts(pkt as *mut u8, len as usize);
    if smol::future::block_on(daemon.send_vpn(slice)).is_err() {
        return -2;
    }
    return 0;
}

pub extern "C" fn recv_vpn(daemon_key: c_int, inout: *mut c_char, buflen: c_int) -> c_int {
    let daemon = if let Some(daemon) = SLAB.get(daemon_key as _) {
        daemon
    } else {
        return -1;
    };
    if let Ok(ret) = smol::future::block_on(daemon.recv_vpn()) {
        return fill_inout(inout, buflen, &ret);
    } else {
        return -2;
    }
}

pub unsafe extern "C" fn debugpack(daemon_key: c_int, dest: *const c_char) -> c_int {
    let dest = CStr::from_ptr(dest).to_str().unwrap();
    let daemon = if let Some(daemon) = SLAB.get(daemon_key as usize) {
        daemon
    } else {
        return -1;
    };
    if let Ok(_) = daemon.debug().backup(dest) {
        return 0;
    } else {
        return -2;
    }
}

pub extern "C" fn version(inout: *mut c_char, buflen: c_int) -> c_int {
    let version = env!("CARGO_PKG_VERSION");
    fill_inout(inout, buflen, version.as_bytes())
}

fn fill_inout(buffer: *mut c_char, buflen: c_int, output: &[u8]) -> c_int {
    let mut slice = unsafe { std::slice::from_raw_parts_mut(buffer as *mut u8, buflen as usize) };
    if output.len() < slice.len() {
        if slice.write_all(output).is_err() {
            log::debug!("call_geph failed: writing to buffer failed!");
            -1
        } else {
            output.len() as c_int
        }
    } else {
        log::debug!("call_geph failed: buffer not big enough!");
        -1
    }
}
