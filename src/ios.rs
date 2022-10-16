use std::{
    ffi::{CStr, CString},
    format,
    io::{BufRead, BufReader, Write},
    os::raw::{c_char, c_int, c_uchar},
    sync::Arc,
};

use bytes::Bytes;
use once_cell::sync::Lazy;
use os_pipe::PipeReader;
use parking_lot::Mutex;
use smol::process::Command;
use structopt::StructOpt;

use crate::{
    binderproxy::{self, binderproxy_once},
    config::{override_config, CommonOpt, ConnectOpt},
    connect::{
        start_main_connect,
        vpn::{vpn_download, vpn_upload},
        TUNNEL,
    },
    main_bridgetest,
    sync::{self, sync_json, SyncOpt},
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
    config_logging_ios();
    let version = env!("CARGO_PKG_VERSION");
    log::info!("IOS geph4-client v{} starting...", version);

    smolscale::block_on(async move {
        let func = func.as_str();
        // let args: Vec<&str> = args.into_iter().map(|s| s.as_str()).collect();

        match func {
            "start_daemon" => {
                let opt = Opt::from_iter(
                    vec![String::from("geph4-client"), String::from("connect")]
                        .into_iter()
                        .chain(args.into_iter()),
                );
                override_config(opt);
                start_main_connect();
                anyhow::Ok(String::from(""))
            }
            "is_connected" => {
                let ret = serde_json::to_string(&true)?;
                anyhow::Ok(ret)
            }
            "is_running" => {
                let ret = serde_json::to_string(&TUNNEL.is_connected())?;
                anyhow::Ok(ret)
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
                println!("binder resp = {resp}");
                anyhow::Ok(resp)
            }
            _ => anyhow::bail!("function {func} does not exist"),
        }
    })
}

#[no_mangle]
pub extern "C" fn call_geph(func: *const c_char, opt: *const c_char) -> *mut c_char {
    let inner = || {
        let func = unsafe { CStr::from_ptr(func) }.to_str()?.to_owned();
        // println!("func = {func}");
        let c_str = unsafe { CStr::from_ptr(opt) };
        // println!("got args str");
        let args: Vec<&str> = serde_json::from_str(c_str.to_str()?)?;
        // println!("args = {:?}", args);
        anyhow::Ok(dispatch_ios(
            func,
            args.into_iter().map(|s| s.to_owned()).collect(),
        )?)
    };

    let output = match inner() {
        Ok(output) => output,
        Err(err) => format!("ERROR!!!! {:?}", err),
    };
    println!("output = {output}");
    CString::new(output).unwrap().into_raw()
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::call_geph;

    // fn test() {
    //     let v = vec![String::from("labooyah")];
    //     let vprime: Vec<&str> = v.iter().map(|s| s.as_str()).collect();
    //     println!("{:?}", vprime);
    // }

    // #[test]
    // fn test_cstr() {
    //     let inner = || {
    //         let args = ["--username", "public", "--password", "public", "--force"];
    //         let args_str = CString::new(serde_json::to_string(&args)?)?.into_raw();

    //         let c_str = unsafe { CStr::from_ptr(args_str) };
    //         let s = c_str.to_str()?;
    //         println!("s = {s}");
    //         let args: Vec<&str> = serde_json::from_str(s)?;
    //         anyhow::Ok(args)
    //     };
    //     match inner() {
    //         Ok(x) => println!("{:?}", x),
    //         Err(e) => println!("{e}"),
    //     }
    // }

    // #[test]
    // fn test_rstr() {
    //     let inner = || {
    //         let s = String::from("heyhey");
    //         let ptr_to_s = &s;
    //         ptr_to_s
    //     };

    //     println!("{}", inner());
    // }

    fn test(func: &str, args: Vec<&str>) {
        let inner = || {
            let func_c = CString::new(func).unwrap().into_raw();
            let args_c = CString::new(serde_json::to_string(&args).unwrap())
                .unwrap()
                .into_raw();
            let ret = call_geph(func_c, args_c);
            unsafe {
                let output = CString::from_raw(ret).to_str()?.to_owned();
                anyhow::Ok(output)
            }
        };
        let output = inner();
        println!("Output of {func} = {:?}", output);
        assert!(output.is_ok());
    }

    #[test]
    fn test_c_functions() {
        test(
            "start_daemon",
            vec!["--username", "public", "--password", "public"],
        );

        test("is_connected", vec![]);

        test("is_running", vec![]);

        test("sync", vec!["--username", "public", "--password", "public"]);

        // test(
        //     "binder_rpc",
        //     vec!["{ jsonrpc: \"2.0\", method: \"method\", params: [], id: 1 }"],
        // );
    }
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

// #[no_mangle]
// pub extern "C" fn check_bridges(_buffer: *mut c_char, _buflen: c_int) -> c_int {
// let mut whitelist: Vec<IpAddr> = Vec::new();
// if let Some(tun) = main_connect::TUNNEL.read().clone() {
//     let endpoint = tun.get_endpoint();
//     match endpoint {
//         EndpointSource::Independent { endpoint: _ } => {
//             -1 // independent exits not supported for iOS
//         }
//         EndpointSource::Binder(binder_tunnel_params) => {
//             let cached_binder = binder_tunnel_params.ccache;
//             let exits = smol::block_on(cached_binder.get_summary().exits).unwrap();
//             for exit in exits {
//                 if let Ok(server_addr) = smol::block_on(
//                     geph4_protocol::getsess::ipv4_addr_from_hostname(exit.hostname.clone()),
//                 ) {
//                     whitelist.push(server_addr.ip());
//                     // bridges
//                     if let Ok(bridges) =
//                         smol::block_on(cached_binder.get_bridges(&exit.hostname, true))
//                     {
//                         for bridge in bridges {
//                             let ip = bridge.endpoint.ip();
//                             whitelist.push(ip);
//                         }
//                     }
//                 }
//             }
//             let whitelist = serde_json::json!(whitelist).to_string();
//             log::debug!(
//                 "whitelist is {}; with length {}",
//                 whitelist,
//                 whitelist.len()
//             );

//             unsafe {
//                 let mut slice =
//                     std::slice::from_raw_parts_mut(buffer as *mut u8, buflen as usize);
//                 if whitelist.len() < slice.len() {
//                     if slice.write_all(whitelist.as_bytes()).is_err() {
//                         log::debug!("check bridges failed: writing to buffer failed");
//                         -1
//                     } else {
//                         whitelist.len() as c_int
//                     }
//                 } else {
//                     log::debug!("check bridges failed: buffer not big enough");
//                     -1
//                 }
//             }
//         }
//     }
// } else {
//     log::debug!("check bridges failed: no tunnel");
//     -1
// }
// }
