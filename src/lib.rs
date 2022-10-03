use bytes::Bytes;

use fronts::parse_fronts;
// use geph4_binder_transport::BinderClient;
use geph4_protocol::binder::client::CachedBinderClient;
use geph4_protocol::binder::protocol::BinderClient;

use serde::{self, Deserialize, Serialize};

use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use structopt::StructOpt;
mod fd_semaphore;
mod fronts;
mod lazy_binder_client;
pub mod serialize;
mod socks2http;
use prelude::*;
mod china;
mod dns;
pub mod ios;
mod main_binderproxy;
mod main_bridgetest;
mod main_connect;
mod main_sync;
mod plots;
mod port_forwarder;
mod prelude;
mod socks5;
mod stats;
mod vpn;

#[derive(Debug, StructOpt, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum Opt {
    Connect(main_connect::ConnectOpt),
    BridgeTest(main_bridgetest::BridgeTestOpt),
    Sync(main_sync::SyncOpt),
    BinderProxy(main_binderproxy::BinderProxyOpt),
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

#[derive(Debug, StructOpt, Clone, Deserialize, Serialize)]
pub struct AuthOpt {
    #[structopt(
        long,
        default_value = "auto",
        parse(from_str = str_to_path)
    )]
    /// where to store Geph's credential cache. The default value is "auto", meaning a platform-specific path that Geph gets to pick.
    credential_cache: PathBuf,

    #[structopt(long, default_value = "")]
    /// username
    username: String,

    #[structopt(long, default_value = "")]
    /// password
    password: String,
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

pub async fn get_binder_client(
    common_opt: &CommonOpt,
    auth_opt: &AuthOpt,
) -> anyhow::Result<CachedBinderClient> {
    let mut dbpath = auth_opt.credential_cache.clone();
    dbpath.push(&auth_opt.username);
    std::fs::create_dir_all(&dbpath)?;
    let cbc = CachedBinderClient::new(
        {
            let dbpath = dbpath.clone();
            move |key| {
                let mut dbpath = dbpath.clone();
                dbpath.push(format!("{}.json", key));
                let r = std::fs::read(dbpath).ok()?;
                let (tstamp, bts): (u64, Bytes) = bincode::deserialize(&r).ok()?;
                if tstamp > SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() {
                    Some(bts)
                } else {
                    None
                }
            }
        },
        {
            let dbpath = dbpath.clone();
            move |k, v, expires| {
                let noviy_taymstamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + expires.as_secs();
                let to_write =
                    bincode::serialize(&(noviy_taymstamp, Bytes::copy_from_slice(v))).unwrap();
                let mut dbpath = dbpath.clone();
                dbpath.push(format!("{}.json", k));
                let _ = std::fs::write(dbpath, to_write);
            }
        },
        BinderClient(parse_fronts(
            *common_opt.binder_master.as_bytes(),
            common_opt
                .binder_http_fronts
                .split(',')
                .zip(common_opt.binder_http_hosts.split(','))
                .map(|(k, v)| (k.to_string(), v.to_string())),
        )),
        &auth_opt.username,
        &auth_opt.password,
    );
    Ok(cbc)
}

fn config_logging() {
    log::debug!("TRYING TO CONFIG LOGGING HERE");
    if let Err(e) = env_logger::Builder::from_env(
        env_logger::Env::default()
            .default_filter_or("geph4client=debug,geph4_protocol=debug,warn,geph_nat=debug"),
    )
    .format_timestamp_millis()
    .try_init()
    {
        log::debug!("{}", e);
    }
}
