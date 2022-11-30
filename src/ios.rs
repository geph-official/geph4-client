use std::{
    ffi::CStr,
    format,
    io::{BufRead, BufReader, Write},
    os::raw::{c_char, c_int, c_uchar},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use once_cell::sync::Lazy;
use os_pipe::PipeReader;
use parking_lot::Mutex;

use structopt::StructOpt;

use crate::{
    binderproxy::binderproxy_once,
    config::{override_config, CommonOpt},
    connect::{
        start_main_connect,
        vpn::{vpn_download, vpn_upload},
        TUNNEL,
    },
    sync::{sync_json, SyncOpt},
    Opt,
};

static LOG_LINES: Lazy<Mutex<BufReader<PipeReader>>> = Lazy::new(|| {
    let (read, write) = os_pipe::pipe().unwrap();
    let write = Mutex::new(write);
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("geph4client=debug,geph4_protocol=debug,warn"),
    )
    .format_timestamp_millis()
    // .target(env_logger::Target::Pipe(Box::new(std::io::sink())))
    .format(move |buf, record| {
        let line = format!(
            "[{} {}]: {}",
            record.level(),
            record.module_path().unwrap_or("none"),
            record.args()
        );
        let mut write = write.lock();
        writeln!(buf, "{}", line).unwrap();
        writeln!(write, "{}", line)
    })
    .init();

    Mutex::new(BufReader::new(read))
});

fn config_logging_ios() {
    log::debug!("TRYING TO CONFIG iOS LOGGING HERE");
    Lazy::force(&LOG_LINES);
}

fn dispatch_ios(func: String, args: Vec<String>) -> anyhow::Result<String> {
    smolscale::permanently_single_threaded();
    config_logging_ios();
    let version = env!("CARGO_PKG_VERSION");
    log::info!("IOS geph4-client v{} starting...", version);

    smolscale::block_on(async move {
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
                smol::Timer::after(Duration::from_secs(1)).await;
                override_config(opt);
                log::info!("override config done");
                smol::Timer::after(Duration::from_secs(1)).await;
                start_main_connect();
                log::info!("called the start_main_connect");
                loop {
                    smol::Timer::after(Duration::from_secs(1)).await;
                    if TUNNEL.status().connected() {
                        break anyhow::Ok(String::from(""));
                    }
                }
            }
            "sync" => {
                let sync_opt = SyncOpt::from_iter(
                    std::iter::once(String::from("sync")).chain(args.into_iter()),
                );
                let ret = sync_json(sync_opt).await?;
                anyhow::Ok(ret)
            }
            "binder_rpc" => {
                let binder_client = Arc::new(CommonOpt::from_iter(vec![""]).get_binder_client());
                let line = args[0].clone();
                let resp = binderproxy_once(binder_client, line).await?;
                log::debug!("binder resp = {resp}");
                anyhow::Ok(resp)
            }
            _ => anyhow::bail!("function {func} does not exist"),
        }
    })
}

#[no_mangle]
/// calls the iOS ffi function "func", with JSON-encoded array of arguments in "opt", returning a string into buffer
pub extern "C" fn call_geph(
    func: *const c_char,
    opt: *const c_char,
    buffer: *mut c_char,
    buflen: c_int,
) -> c_int {
    let inner = || {
        let func = unsafe { CStr::from_ptr(func) }.to_str()?.to_owned();
        let opt = unsafe { CStr::from_ptr(opt) };
        log::debug!("func = {:?}, opt = {:?}", func, opt);
        let args: Vec<String> = serde_json::from_str(opt.to_str()?)?;
        anyhow::Ok(dispatch_ios(func, args)?)
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
    unsafe {
        let slice = std::slice::from_raw_parts(pkt as *mut u8, len as usize);
        let owned = slice.to_vec();
        let bytes: Bytes = owned.into();
        vpn_upload(bytes);
    }
}

#[no_mangle]
pub extern "C" fn download_packet(buffer: *mut c_uchar, buflen: c_int) -> c_int {
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
    let mut line = String::new();
    if LOG_LINES.lock().read_line(&mut line).is_err() {
        return -1;
    }

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
