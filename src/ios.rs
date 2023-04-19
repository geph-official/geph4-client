use std::{
    ffi::CStr,
    format,
    io::Write,
    os::raw::{c_char, c_int, c_uchar},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use once_cell::sync::Lazy;

use smol::channel::Receiver;
use structopt::StructOpt;

use crate::{
    binderproxy::binderproxy_once,
    config::{override_config, CommonOpt},
    connect::{
        start_main_connect,
        vpn::{vpn_download, vpn_upload},
    },
    debugpack::{self, DebugPackOpt, DEBUGPACK, TIMESERIES_LOOP},
    sync::{sync_json, SyncOpt},
    Opt,
};

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
        DEBUGPACK.add_logline(&line);
        // match DEBUGPACK.add_logline(&line) {
        //     Ok(n) => {
        //         let _ = send.send_blocking(format!("ADD_LOGLINE wrote {} rows!", n));
        //         let _ = DEBUGPACK.loglines_count().and_then(|loglines_size| {
        //             let _ = send.send_blocking(format!(
        //                 "LOGLINES currently has {} entries!",
        //                 loglines_size
        //             ));
        //             Ok(0)
        //         });
        //     }
        //     Err(e) => {
        //         let _ = send.send_blocking(format!("ERROR SEEN: {:?}", e));
        //     }
        // };
        let _ = send.send_blocking(line);
        Ok(())
    })
    .init();

    recv
});

fn config_logging_ios() {
    log::debug!("TRYING TO CONFIG iOS LOGGING HERE");
    Lazy::force(&LOG_LINES);
}

fn dispatch_ios(func: String, args: Vec<String>) -> anyhow::Result<String> {
    smolscale::permanently_single_threaded();
    let version = env!("CARGO_PKG_VERSION");
    log::info!("IOS geph4-client v{} starting...", version);
    std::env::set_var("GEPH_VERSION", version);

    smol::future::block_on(async move {
        let func = func.as_str();
        // let args: Vec<&str> = args.into_iter().map(|s| s.as_str()).collect();

        match func {
            "start_daemon" => {
                log::info!("start_daemon selected with args: {:?}", args);
                let opt = Opt::from_iter_safe(
                    vec![String::from("geph4-client"), String::from("connect")]
                        .into_iter()
                        .chain(args.into_iter()),
                )
                .map_err(|e| {
                    log::error!("OH NO WEIRD FAIL: {:?}", e);
                    std::thread::sleep(Duration::from_secs(10));
                    e
                })?;
                log::info!("parsed Opt: {:?}", opt);
                override_config(opt);
                log::info!("override config done");
                config_logging_ios();
                Lazy::force(&TIMESERIES_LOOP); // must be called *after* CONFIG is set

                start_main_connect();
                log::info!("called the start_main_connect");
                Ok("".into())
            }
            "sync" => {
                let opt = Opt::from_iter_safe(
                    vec![String::from("geph4-client"), String::from("sync")]
                        .into_iter()
                        .chain(args.clone().into_iter()),
                )?;
                override_config(opt);

                let sync_opt = SyncOpt::from_iter(
                    std::iter::once(String::from("sync")).chain(args.into_iter()),
                );
                let ret = sync_json(sync_opt).await?;
                anyhow::Ok(ret)
            }
            "binder_rpc" => {
                let opt = Opt::from_iter_safe(
                    vec![String::from("geph4-client"), String::from("binder-proxy")].into_iter(),
                )?;
                override_config(opt);
                let binder_client = Arc::new(CommonOpt::from_iter(vec![""]).get_binder_client());
                let line = args[0].clone();
                let resp = binderproxy_once(binder_client, line).await?;
                log::debug!("binder resp = {resp}");
                anyhow::Ok(resp)
            }
            "debugpack" => {
                let opt = Opt::from_iter_safe(
                    vec![String::from("geph4-client"), String::from("debugpack")]
                        .into_iter()
                        .chain(args.clone().into_iter()),
                )?;
                override_config(opt);

                let dp_opt = DebugPackOpt::from_iter(
                    std::iter::once(String::from("debugpak")).chain(args.into_iter()),
                );
                debugpack::export_debugpak(&dp_opt.export_to)?;
                anyhow::Ok(dp_opt.export_to)
            }
            "version" => anyhow::Ok(String::from(version)),
            _ => anyhow::bail!("function {func} does not exist"),
        }
    })
}

#[no_mangle]
/// calls the iOS ffi function "func", with JSON-encoded array of arguments in "opt", returning a string into buffer
/// # Safety
/// The pointers must be valid.
pub unsafe extern "C" fn call_geph(
    func: *const c_char,
    daemon_rpc_secret: *const c_char,
    opt: *const c_char,
    buffer: *mut c_char,
    buflen: c_int,
) -> c_int {
    std::env::set_var("SMOLSCALE_USE_AGEX", "1");
    let inner = || {
        let func = unsafe { CStr::from_ptr(func) }.to_str()?.to_owned();
        let daemon_rpc_secret = unsafe { CStr::from_ptr(daemon_rpc_secret) }
            .to_str()?
            .to_owned();
        std::env::set_var("GEPH_RPC_KEY", daemon_rpc_secret);
        let opt = unsafe { CStr::from_ptr(opt) };
        log::debug!("func = {:?}, opt = {:?}", func, opt);
        let args: Vec<String> = serde_json::from_str(opt.to_str()?)?;
        let result = std::panic::catch_unwind(|| dispatch_ios(func, args)).map_err(|e| {
            anyhow::anyhow!("a panic happened: {}", panic_message::panic_message(&e))
        })?;
        anyhow::Ok(result?)
    };

    let output = match inner() {
        Ok(output) => unsafe {
            let mut slice = std::slice::from_raw_parts_mut(buffer as *mut u8, buflen as usize);
            if output.len() < slice.len() {
                if slice.write_all(output.as_bytes()).is_err() {
                    log::debug!("call_geph failed: writing to buffer failed!");
                    -1
                } else {
                    output.len() as c_int
                }
            } else {
                log::debug!("call_geph failed: buffer not big enough!");
                -1
            }
        },
        Err(err) => unsafe {
            let mut slice = std::slice::from_raw_parts_mut(buffer as *mut u8, buflen as usize);
            if err.to_string().len() < slice.len() {
                if slice.write_all(err.to_string().as_bytes()).is_err() {
                    log::debug!("call_geph failed: writing to buffer failed!");
                    -1
                } else {
                    -(err.to_string().len() as c_int)
                }
            } else {
                log::debug!("call_geph failed: buffer not big enough!");
                -1
            }
        },
    };
    output
}

#[no_mangle]
pub extern "C" fn upload_packet(pkt: *const c_uchar, len: c_int) {
    // Lazy::force(&VPN_SHUFFLE_TASK);
    unsafe {
        let slice = std::slice::from_raw_parts(pkt as *mut u8, len as usize);
        let owned = slice.to_vec();
        let bytes: Bytes = owned.into();
        vpn_upload(bytes);
    }
}

#[no_mangle]
pub extern "C" fn download_packet(buffer: *mut c_uchar, buflen: c_int) -> c_int {
    // Lazy::force(&VPN_SHUFFLE_TASK);
    let pkt = smol::future::block_on(vpn_download());
    let pkt_ref = pkt.as_ref();
    unsafe {
        let mut slice: &mut [u8] =
            std::slice::from_raw_parts_mut(buffer as *mut u8, buflen as usize);
        if pkt.len() < slice.len() {
            if slice.write_all(pkt_ref).is_err() {
                log::debug!("from geph: error writing to buffer!");
                -1
            } else {
                pkt.len() as c_int
            }
        } else {
            log::debug!("from geph: buffer too small!");
            -1
        }
    }
}

#[no_mangle]
// returns one line of logs
pub extern "C" fn get_logs(buffer: *mut c_char, buflen: c_int) -> c_int {
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
