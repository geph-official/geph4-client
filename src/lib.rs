#![type_length_limit = "2000000"]
use acidjson::AcidJson;
use bytes::Bytes;
use fronts::parse_fronts;
use geph4_binder_transport::BinderClient;
use geph4_protocol::{BinderParams, CachedBinderClient};
use serde::{self, Deserialize, Serialize};
use smol_timeout::TimeoutExt;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
use structopt::StructOpt;
mod fd_semaphore;
mod fronts;
mod lazy_binder_client;
pub mod serialize;
mod socks2http;
use crate::{fronts::fetch_fronts, lazy_binder_client::LazyBinderClient};
use prelude::*;
mod china;
mod dns;
pub mod ios;
pub mod logs;
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

pub use vpn::ack_decimate;

// #[global_allocator]
// static ALLOC: alloc_geiger::System = alloc_geiger::SYSTEM;

#[derive(Debug, StructOpt, Deserialize, Serialize)]
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
    /// where to store Geph's credential cache. The default value is "auto", meaning a platform-specific path that Geph gets to pick.
    credential_cache: PathBuf,

    #[structopt(long, default_value = "")]
    /// username
    username: String,

    #[structopt(long, default_value = "")]
    /// password
    password: String,
}

// pub fn start_with_args(args: Vec<&str>) -> anyhow::Result<()> {
//     let opt: Opt = Opt::from_iter_safe(args)?;
//     dispatch(opt)
// }

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

pub async fn to_cached_binder_client(
    common_opt: &CommonOpt,
    auth_opt: &AuthOpt,
) -> anyhow::Result<CachedBinderClient> {
    let mut dbpath = auth_opt.credential_cache.clone();
    std::fs::create_dir_all(&dbpath)?;
    dbpath.push("ngcredentials.json");
    if std::fs::read(&dbpath).is_err() {
        std::fs::write(&dbpath, b"{}")?;
    }
    let cache: AcidJson<BTreeMap<String, Bytes>> = AcidJson::open(&dbpath)?;
    let cbc = CachedBinderClient::new(BinderParams {
        underlying: common_opt.to_binder_client().await,
        cache: Arc::new(cache),
        binder_mizaru_free_pk: common_opt.binder_mizaru_free.clone(),
        binder_mizaru_plus_pk: common_opt.binder_mizaru_plus.clone(),
        username: auth_opt.username.clone(),
        password: auth_opt.password.clone(),
    });
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
