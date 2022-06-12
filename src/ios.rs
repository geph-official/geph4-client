use std::{
    ffi::{CStr, CString},
    format,
    io::{BufRead, BufReader, Write},
    net::IpAddr,
    os::raw::{c_char, c_int, c_uchar},
    time::Duration,
};

use bytes::Bytes;
use geph4_protocol::EndpointSource;
use once_cell::sync::Lazy;
use os_pipe::PipeReader;
use parking_lot::Mutex;
use structopt::StructOpt;

use crate::{
    main_binderproxy, main_bridgetest, main_connect, main_sync,
    vpn::{DOWN_CHANNEL, UP_CHANNEL},
    Opt,
};

static LOG_LINES: Lazy<Mutex<BufReader<PipeReader>>> = Lazy::new(|| {
    let (read, write) = os_pipe::pipe().unwrap();

    let lala = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("geph4client=debug,warn"),
    )
    .format_timestamp_millis()
    .target(env_logger::Target::Pipe(Box::new(write)))
    .try_init();

    if let Err(e) = lala {
        eprintln!("{}", e);
    };

    Mutex::new(BufReader::new(read))
});

fn config_logging_ios() {
    eprintln!("TRYING TO CONFIG LOGGING HERE");
    Lazy::force(&LOG_LINES);
}

fn dispatch_ios(opt: Opt) -> anyhow::Result<String> {
    config_logging_ios();
    let version = env!("CARGO_PKG_VERSION");
    log::info!("geph4-client v{} starting...", version);

    #[cfg(target_os = "android")]
    smolscale::permanently_single_threaded();

    smolscale::block_on(async move {
        match opt {
            Opt::Connect(opt) => loop {
                if let Err(err) = main_connect::main_connect(opt.clone()).await {
                    log::error!("Something SERIOUSLY wrong has happened! {:#?}", err);
                    smol::Timer::after(Duration::from_secs(1)).await;
                };
                return Ok(String::from(""));
            },
            Opt::Sync(opt) => main_sync::sync_json(opt).await,
            Opt::BinderProxy(opt) => {
                main_binderproxy::main_binderproxy(opt).await?;
                return Ok(String::from(""));
            }
            Opt::BridgeTest(opt) => {
                main_bridgetest::main_bridgetest(opt).await?;
                return Ok(String::from(""));
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn call_geph(opt: *const c_char) -> *mut c_char {
    let inner = || {
        let c_str = unsafe { CStr::from_ptr(opt) };
        // if c_str.to_str()?.contains("connect") {
        //     anyhow::bail!("lol always fail connects")
        // }
        let args: Vec<&str> = serde_json::from_str(c_str.to_str()?)?;
        std::env::set_var("GEPH_RECURSIVE", "1"); // no forking in iOS
        let opt: Opt = Opt::from_iter_safe(args)?;
        dispatch_ios(opt)
    };

    let output = match inner() {
        Ok(output) => output,
        Err(err) => format!("ERROR!!!! {:?}", err),
    };

    CString::new(output).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn upload_packet(pkt: *const c_uchar, len: c_int) {
    unsafe {
        let slice = std::slice::from_raw_parts(pkt as *mut u8, len as usize);
        let bytes: Bytes = slice.into();
        UP_CHANNEL.0.send(bytes).unwrap();
    }
}

#[no_mangle]
pub extern "C" fn download_packet(buffer: *mut c_uchar, buflen: c_int) -> c_int {
    let pkt = DOWN_CHANNEL.1.recv().unwrap();
    let pkt_ref = pkt.as_ref();
    unsafe {
        let mut slice: &mut [u8] =
            std::slice::from_raw_parts_mut(buffer as *mut u8, buflen as usize);
        if pkt.len() < slice.len() {
            if slice.write_all(pkt_ref).is_err() {
                -1
            } else {
                pkt.len() as c_int
            }
        } else {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn check_bridges(buffer: *mut c_char, buflen: c_int) -> c_int {
    let mut whitelist: Vec<IpAddr> = Vec::new();
    if let Some(tun) = main_connect::TUNNEL.read().clone() {
        let endpoint = tun.get_endpoint();
        match endpoint {
            EndpointSource::Independent { endpoint: _ } => {
                eprintln!("yo independent~");
                return -1; // independent exits not supported for iOS
            }
            EndpointSource::Binder(binder_tunnel_params) => {
                let cached_binder = binder_tunnel_params.ccache;
                let exits = smol::block_on(cached_binder.get_exits()).unwrap();
                for exit in exits {
                    if let Ok(server_addr) = smol::block_on(
                        geph4_protocol::getsess::ipv4_addr_from_hostname(exit.hostname.clone()),
                    ) {
                        whitelist.push(server_addr.ip());
                        // bridges
                        if let Ok(bridges) =
                            smol::block_on(cached_binder.get_bridges(&exit.hostname, true))
                        {
                            for bridge in bridges {
                                let ip = bridge.endpoint.ip();
                                whitelist.push(ip);
                            }
                        }
                    }
                }
                let whitelist = serde_json::json!(whitelist).to_string();
                eprintln!(
                    "whitelist is {}; with length {}",
                    whitelist,
                    whitelist.len()
                );

                unsafe {
                    let mut slice =
                        std::slice::from_raw_parts_mut(buffer as *mut u8, buflen as usize);
                    if whitelist.len() < slice.len() {
                        if slice.write_all(whitelist.as_bytes()).is_err() {
                            log::debug!("check bridges failed: writing to buffer failed");
                            return -1;
                        } else {
                            return whitelist.len() as c_int;
                        }
                    } else {
                        log::debug!("check bridges failed: buffer not big enough");
                        return -1;
                    }
                }
            }
        }
    } else {
        log::debug!("check bridges failed: no tunnel");
        -1
    }
}

#[no_mangle]
// returns one line of logs
pub extern "C" fn get_logs(buffer: *mut c_char, buflen: c_int) -> c_int {
    let mut line = String::new();
    if let Err(_) = LOG_LINES.lock().read_line(&mut line) {
        return -1;
    }

    unsafe {
        let mut slice: &mut [u8] =
            std::slice::from_raw_parts_mut(buffer as *mut u8, buflen as usize);
        if line.len() < slice.len() {
            if slice.write_all(line.as_bytes()).is_err() {
                return -1;
            } else {
                return line.len() as c_int;
            }
        } else {
            return -1;
        }
    }
}
