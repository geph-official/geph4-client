use std::ffi::{c_char, c_uchar, CStr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::{io::Write, sync::atomic::AtomicUsize};

mod config;
mod fronts;

mod socks2http;

use colored::Colorize;

use config::ConnectOpt;
use libc::c_int;
use once_cell::sync::Lazy;
use pad::{Alignment, PadStr};

use sharded_slab::Slab;
use smol::channel::{Receiver, Sender};
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

#[no_mangle]
pub unsafe extern "C" fn start(opt: *const c_char, daemon_rpc_secret: *const c_char) -> c_int {
    // maybe i32 will be a problem
    let fallible = || {
        // config daemon rpc secret
        let daemon_rpc_secret = unsafe { CStr::from_ptr(daemon_rpc_secret) }
            .to_str()?
            .to_owned();
        std::env::set_var("GEPH_RPC_KEY", daemon_rpc_secret);

        // start daemon
        let opt_str = CStr::from_ptr(opt).to_str()?;
        eprintln!("opt_str = {opt_str}");
        let args: Vec<String> = serde_json::from_str(opt_str)?;
        let opt = ConnectOpt::from_iter_safe(args.into_iter())?;
        let daemon = smolscale::block_on(async { ConnectDaemon::start(opt).await })?;
        let ret = SLAB.insert(daemon).unwrap() as c_int;
        anyhow::Ok(ret)
    };
    match fallible() {
        Ok(ret) => ret,
        Err(err) => {
            eprintln!("ERR starting daemon from iOS: {err}");
            log::debug!("ERR starting daemon from iOS: {err}");
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn stop(daemon_key: c_int) -> c_int {
    SLAB.remove(daemon_key as usize);
    0
}

#[no_mangle]
pub unsafe extern "C" fn geph_sync(
    opt: *const c_char,
    buffer: *mut c_char,
    buflen: c_int,
) -> c_int {
    let fallible = || {
        let opt_str = CStr::from_ptr(opt).to_str()?;
        let args: Vec<String> = serde_json::from_str(opt_str)?;
        let opt = SyncOpt::from_iter_safe(args)?;
        let resp = smolscale::block_on(async { sync_json(opt).await })?;
        anyhow::Ok(fill_buffer(buffer, buflen, resp.as_bytes()))
    };
    match fallible() {
        Ok(ret) => ret,
        Err(err) => {
            log::debug!("ERR starting daemon from iOS: {err}");
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn binder_rpc(
    req: *const c_char,
    buffer: *mut c_char,
    buflen: c_int,
) -> c_int {
    let req_str = if let Ok(req_str) = CStr::from_ptr(req).to_str() {
        req_str
    } else {
        return -1;
    };
    let binder_client = Arc::new(
        CommonOpt::from_iter_safe(vec![""])
            .unwrap()
            .get_binder_client(),
    );
    if let Ok(resp) = smolscale::block_on(binderproxy_once(binder_client, req_str.to_owned())) {
        // println!("binder resp = {resp}");
        log::debug!("binder resp = {resp}");
        fill_buffer(buffer, buflen, resp.as_bytes())
    } else {
        -2
    }
}

#[no_mangle]
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

#[no_mangle]
pub unsafe extern "C" fn recv_vpn(daemon_key: c_int, buffer: *mut c_char, buflen: c_int) -> c_int {
    let daemon = if let Some(daemon) = SLAB.get(daemon_key as _) {
        daemon
    } else {
        return -1;
    };
    if let Ok(ret) = smol::future::block_on(daemon.recv_vpn()) {
        return fill_buffer(buffer, buflen, &ret);
    } else {
        return -2;
    }
}

#[no_mangle]
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

#[no_mangle]
pub unsafe extern "C" fn version(buffer: *mut c_char, buflen: c_int) -> c_int {
    let version = env!("CARGO_PKG_VERSION");
    fill_buffer(buffer, buflen, version.as_bytes())
}

unsafe fn fill_buffer(buffer: *mut c_char, buflen: c_int, output: &[u8]) -> c_int {
    let mut slice = std::slice::from_raw_parts_mut(buffer as *mut u8, buflen as usize);
    // println!("buffer.len() = {}", slice.len());
    // println!("output.len() = {}", output.len());
    if output.len() < slice.len() {
        if slice.write_all(output).is_err() {
            log::debug!("call_geph failed: writing to buffer failed!");
            -4
        } else {
            output.len() as c_int
        }
    } else {
        log::debug!("call_geph failed: buffer not big enough!");
        -3
    }
}

static LOG_LINES: Lazy<Receiver<String>> = Lazy::new(|| {
    let (send, recv) = smol::channel::unbounded();
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("geph4client=debug,geph4_protocol=debug,warn"),
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
        let _ = send.send_blocking(line);

        Ok(())
    })
    .init();
    recv
});

#[no_mangle]
// returns one line of logs
pub extern "C" fn get_log_line(buffer: *mut c_char, buflen: c_int) -> c_int {
    let line = LOG_LINES.recv_blocking().unwrap();
    unsafe {
        let mut slice: &mut [u8] =
            std::slice::from_raw_parts_mut(buffer as *mut u8, buflen as usize);
        if line.len() < slice.len() {
            if slice.write_all(line.as_bytes()).is_err() {
                -1
            } else {
                line.len() as c_int
            }
        } else {
            -1
        }
    }
}

// #[no_mangle]
// pub extern "C" fn init_logging(daemon_key: c_int) -> c_int {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    #[test]
    fn test_binder_rpc_invalid_input() {
        // Prepare a valid input request
        let input = CString::new(
            "{\"jsonrpc\":\"2.0\",\"method\":\"get_announcements\",\"params\":[],\"id\":1}",
        )
        .expect("CString::new failed");
        let input_ptr = input.as_ptr();

        // Allocate a buffer for the response
        let mut buffer = vec![0; 1024 * 128]; // Adjust size as needed
        let buffer_ptr = buffer.as_mut_ptr();

        // Call the function
        let result = unsafe { binder_rpc(input_ptr, buffer_ptr, buffer.len() as c_int) };
        // Assert expected results (e.g., result code, content of the buffer)
        assert!(result > 0); // Replace with the expected success code

        // let output = unsafe { CStr::from_ptr(buffer_ptr).to_string_lossy().into_owned() };
        // println!("Output: {}", output);
    }

    #[test]
    fn test_geph_sync() {
        // Prepare a valid input option in JSON format
        let input_option = CString::new(
            "[\"sync\", \"auth-password\", \"--username\", \"shmol\", \"--password\", \"shmol\"]",
        )
        .expect("CString::new failed");
        let input_ptr = input_option.as_ptr();

        // Allocate a buffer for the response
        let mut buffer = vec![0; 128 * 1024]; // Adjust size as needed
        let buffer_ptr = buffer.as_mut_ptr();

        // Call the function
        let result = unsafe { geph_sync(input_ptr, buffer_ptr, buffer.len() as c_int) };

        // Print the result code
        println!("sync retcode: {}", result);
        assert!(result >= 0);

        let _output = unsafe { CStr::from_ptr(buffer_ptr).to_string_lossy().into_owned() };
    }

    #[test]
    fn test_start() {
        // Prepare a valid input option in JSON format
        let input_option = CString::new(
            "[\"connect\", \"--exit-server\", \"jp\", \"--use-bridges\", \"auth-password\", \"--username\", \"shmol\", \"--password\", \"shmol\"]",
        )
        .expect("CString::new failed");
        let input_ptr = input_option.as_ptr();
        let daemon_rpc_secret = CString::new("").unwrap();
        // Call the function
        let result = unsafe { start(input_ptr, daemon_rpc_secret.as_ptr()) };

        // Print the result code
        println!("start retcode: {}", result);
        assert!(result >= 0);
    }
}
