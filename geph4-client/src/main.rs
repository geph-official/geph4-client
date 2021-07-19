#![type_length_limit = "2000000"]

use std::{collections::BTreeMap, io::Write, path::PathBuf, sync::Arc, time::Duration};

use binder_transport::BinderClient;
use flexi_logger::{DeferredNow, Record};
use fronts::parse_fronts;
use smol_timeout::TimeoutExt;
use structopt::StructOpt;
mod cache;
mod fronts;
mod tunman;

use prelude::*;

use crate::fronts::fetch_fronts;
mod dns;
mod nettest;
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
#[derive(Debug, StructOpt)]
enum Opt {
    Connect(main_connect::ConnectOpt),
    BridgeTest(main_bridgetest::BridgeTestOpt),
    Sync(main_sync::SyncOpt),
    BinderProxy(main_binderproxy::BinderProxyOpt),
}

fn main() -> anyhow::Result<()> {
    // fixes timer resolution on Windows
    #[cfg(windows)]
    unsafe {
        winapi::um::timeapi::timeBeginPeriod(1);
    }

    // the logging function
    fn logger(
        write: &mut dyn Write,
        now: &mut DeferredNow,
        record: &Record<'_>,
    ) -> Result<(), std::io::Error> {
        use flexi_logger::style;
        let level = record.level();
        let level_str = match level {
            flexi_logger::Level::Debug => "DEBG".to_string(),
            x => x.to_string(),
        };
        write!(
            write,
            "[{}] {} [{}:{}] {}",
            style(level, now.now().naive_utc().format("%Y-%m-%d %H:%M:%S")),
            style(level, level_str),
            record.file().unwrap_or("<unnamed>"),
            record.line().unwrap_or(0),
            &record.args()
        )?;
        Ok(())
    }

    flexi_logger::Logger::with_env_or_str("geph4_client = debug, warn")
        // .format(flexi_logger::colored_detailed_format)
        .set_palette("192;208;158;248;240".to_string())
        .format(logger)
        .start()
        .unwrap();
    let opt: Opt = Opt::from_args();
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

#[derive(Debug, StructOpt, Clone)]
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
        let mut fronts: BTreeMap<String, String> = self
            .binder_http_fronts
            .split(',')
            .zip(self.binder_http_hosts.split(','))
            .map(|(front, host)| (front.to_string(), host.to_string()))
            .collect();
        for url in self.binder_extra_url.split(',') {
            log::debug!("getting extra fronts...");
            match fetch_fronts(url.into())
                .timeout(Duration::from_secs(1))
                .await
            {
                None => log::debug!("(timed out)"),
                Some(Ok(val)) => {
                    log::debug!("inserting extra {} fronts", val.len());
                    for (k, v) in val {
                        fronts.insert(k, v);
                    }
                }
                Some(Err(e)) => {
                    log::warn!("error fetching fronts from {}: {:?}", url, e)
                }
            }
        }
        parse_fronts(self.binder_master, fronts)
    }
}

#[derive(Debug, StructOpt, Clone)]
pub struct AuthOpt {
    #[structopt(
        long,
        default_value = "auto",
        parse(from_str = str_to_path)
    )]
    /// where to store Geph's credential cache. The default value of "auto", meaning a platform-specific path that Geph gets to pick.
    credential_cache: PathBuf,

    #[structopt(long)]
    /// username
    username: String,

    #[structopt(long)]
    /// password
    password: String,
}
