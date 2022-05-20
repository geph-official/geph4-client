#![type_length_limit = "2000000"]
use bytes::Bytes;
use fronts::parse_fronts;
use geph4_binder_transport::BinderClient;
use once_cell::sync::Lazy;
use serde::{self, Deserialize, Serialize};
use serde_json;
use smol_timeout::TimeoutExt;
use std::{
    collections::BTreeMap,
    ffi::{c_void, CStr, CString},
    io::{self, BufRead, BufReader, Read, Write},
    os::raw::{c_char, c_int, c_uchar},
    path::PathBuf,
    sync::Arc,
    thread,
    time::Duration,
};
use structopt::StructOpt;
use vpn::{DOWN_CHANNEL, UP_CHANNEL};
mod cache;
mod fd_semaphore;
mod fronts;
mod lazy_binder_client;
pub mod serialize;
mod socks2http;
mod tunman;
use gag::{self, BufferRedirect};
use prelude::*;

use crate::{fronts::fetch_fronts, lazy_binder_client::LazyBinderClient};
mod dns;
mod prelude;
mod stats;
mod vpn;

mod activity;

mod plots;

mod china;
mod main_binderproxy;
mod main_bridgetest;
mod main_connect;
mod main_sync;

// #[global_allocator]
// static ALLOC: alloc_geiger::System = alloc_geiger::SYSTEM;

#[derive(Debug, StructOpt, Deserialize, Serialize)]
pub enum Opt {
    Connect(main_connect::ConnectOpt),
    BridgeTest(main_bridgetest::BridgeTestOpt),
    Sync(main_sync::SyncOpt),
    BinderProxy(main_binderproxy::BinderProxyOpt),
}

fn config_logging() {
    eprintln!("TRYING TO CONFIG LOGGING HERE");
    if let Err(e) = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("geph4client=debug,warn"),
    )
    .format_timestamp_millis()
    .try_init()
    {
        eprintln!("{}", e);
    }
}

static LOG_LINES: Lazy<flume::Receiver<String>> = Lazy::new(|| {
    let (send, recv) = flume::unbounded();
    // let mut logs: BufferRedirect = BufferRedirect::stderr().unwrap();
    std::thread::spawn(move || {
        // let mut logs = BufReader::new(logs);
        loop {
            // let mut line = String::new();
            // logs.read_line(&mut line).unwrap();
            send.send("pahpah".to_string()).unwrap();
            std::thread::sleep(Duration::from_secs(1));
        }
    });
    recv
});

#[no_mangle]
pub extern "C" fn call_geph(opt: *const c_char) -> *mut c_char {
    let inner = || {
        let c_str = unsafe { CStr::from_ptr(opt) };
        // if c_str.to_str()?.contains("connect") {
        //     anyhow::bail!("lol always fail connects")
        // }
        let args: Vec<&str> = serde_json::from_str(c_str.to_str()?)?;

        let mut buf = BufferRedirect::stdout()?;
        let mut output = String::new();
        std::env::set_var("GEPH_RECURSIVE", "1"); // no forking in iOS
        start_with_args(args)?;
        buf.read_to_string(&mut output)?;
        Ok::<_, anyhow::Error>(output)
    };

    let output = match inner() {
        Ok(output) => output,
        Err(err) => format!("ERROR!!!! {:?}", err),
    };

    CString::new(output).unwrap().into_raw()
}

pub fn start_with_args(args: Vec<&str>) -> anyhow::Result<()> {
    let opt: Opt = Opt::from_iter_safe(args)?;
    dispatch(opt)
}

pub fn dispatch(opt: Opt) -> anyhow::Result<()> {
    config_logging();
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
                }
            },
            Opt::Sync(opt) => main_sync::main_sync(opt).await,
            Opt::BinderProxy(opt) => main_binderproxy::main_binderproxy(opt).await,
            Opt::BridgeTest(opt) => main_bridgetest::main_bridgetest(opt).await,
        }
    })
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
    let mut ips: Vec<String> = Vec::new();

    if let Some(rem_addr) = tunman::getsess::REMOTE_ADDR.get() {
        let ip = match rem_addr {
            async_net::SocketAddr::V4(ip) => ip.to_string(),
            async_net::SocketAddr::V6(ip) => ip.to_string(),
        };
        ips.push(ip);
    }

    if let Some(bridges) = tunman::getsess::BRIDGES.get() {
        for bd in bridges {
            let ip = match bd.endpoint.ip() {
                async_net::IpAddr::V4(ip) => ip.to_string(),
                async_net::IpAddr::V6(ip) => ip.to_string(),
            };
            ips.push(ip);
        }
    }

    let ips = serde_json::json!(ips).to_string();
    eprintln!("ips is {}; with length {}", ips, ips.len());

    unsafe {
        let mut slice = std::slice::from_raw_parts_mut(buffer as *mut u8, buflen as usize);
        if ips.len() < slice.len() {
            if slice.write_all(ips.as_bytes()).is_err() {
                -1
            } else {
                ips.len() as c_int
            }
        } else {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn get_logs(buffer: *mut c_char, buflen: c_int) -> c_int {
    let output = LOG_LINES.recv().unwrap();
    unsafe {
        let mut slice: &mut [u8] =
            std::slice::from_raw_parts_mut(buffer as *mut u8, buflen as usize);
        if output.len() < slice.len() {
            if slice.write_all(output.as_bytes()).is_err() {
                -1
            } else {
                output.len() as c_int
            }
        } else {
            -1
        }
    }
}

#[derive(Debug, StructOpt, Clone, Deserialize, Serialize)]
pub struct CommonOpt {
    #[structopt(
        long,
        default_value = "https://www.netlify.com/v4/,https+nosni://www.cdn77.com/,https+nosni://ajax.aspnetcdn.com/,https://d1hoqe10mv32pv.cloudfront.net"
    )]
    /// HTTP(S) address of the binder, FRONTED
    binder_http_fronts: String,

    #[structopt(
        long,
        default_value = "loving-bell-981479.netlify.app,1049933718.rsc.cdn77.org,gephbinder-4.azureedge.net,dtnins2n354c4.cloudfront.net"
    )]
    /// HTTP(S) actual host of the binder
    binder_http_hosts: String,

    #[structopt(
        long,
        default_value = "https://gitlab.com/bunsim/geph4-additional-fronts/-/raw/main/booboo.json,https://f001.backblazeb2.com/file/geph4-dl/Geph4Releases/booboo.json"
    )]
    /// URL to download extra binder front/host pairs
    binder_extra_url: String,

    #[structopt(
        long,
        default_value = "124526f4e692b589511369687498cce57492bf4da20f8d26019c1cc0c80b6e4b",
        parse(from_str = str_to_x25519_pk)
    )]
    /// x25519 master key of the binder
    binder_master: x25519_dalek::PublicKey,

    #[structopt(
        long,
        default_value = "4e01116de3721cc702f4c260977f4a1809194e9d3df803e17bb90db2a425e5ee",
        parse(from_str = str_to_mizaru_pk)
    )]
    /// mizaru master key of the binder, for FREE
    binder_mizaru_free: mizaru::PublicKey,

    #[structopt(
        long,
        default_value = "44ab86f527fbfb5a038cc51a49e0467be6eb532c4b9c6cb5cdb430926c95bdab",
        parse(from_str = str_to_mizaru_pk)
    )]
    /// mizaru master key of the binder, for PLUS
    binder_mizaru_plus: mizaru::PublicKey,
}

impl CommonOpt {
    pub async fn to_binder_client(&self) -> Arc<dyn BinderClient> {
        let fronts: BTreeMap<String, String> = self
            .binder_http_fronts
            .split(',')
            .zip(self.binder_http_hosts.split(','))
            .map(|(front, host)| (front.to_string(), host.to_string()))
            .collect();
        let main_fronts = parse_fronts(self.binder_master, fronts);
        let binder_extra_url = self.binder_extra_url.clone();
        let binder_master = self.binder_master;
        let auxiliary_fronts = LazyBinderClient::new(smolscale::spawn(async move {
            for url in binder_extra_url.split(',') {
                log::debug!("getting extra fronts...");
                match fetch_fronts(url.into())
                    .timeout(Duration::from_secs(30))
                    .await
                {
                    None => log::debug!("(timed out)"),
                    Some(Ok(val)) => {
                        log::debug!("inserting extra {} fronts", val.len());
                        return Arc::new(parse_fronts(binder_master, val));
                    }
                    Some(Err(e)) => {
                        log::warn!("error fetching fronts from {}: {:?}", url, e)
                    }
                }
            }
            smol::future::pending().await
        }));
        let mut toret = geph4_binder_transport::MultiBinderClient::empty();
        toret = toret.add_client(main_fronts);
        toret = toret.add_client(auxiliary_fronts);
        Arc::new(toret)
    }
}

#[derive(Debug, StructOpt, Clone, Deserialize, Serialize)]
pub struct AuthOpt {
    #[structopt(
        long,
        default_value = "auto",
        parse(from_str = str_to_path)
    )]
    /// where to store Geph's credential cache. The default value of "auto", meaning a platform-specific path that Geph gets to pick.
    credential_cache: PathBuf,

    #[structopt(long, default_value = "")]
    /// username
    username: String,

    #[structopt(long, default_value = "")]
    /// password
    password: String,
}
