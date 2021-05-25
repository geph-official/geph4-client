#![type_length_limit = "2000000"]

use std::{io::Write, path::PathBuf, sync::Arc, time::Duration};

use binder_transport::BinderClient;
use flexi_logger::{DeferredNow, Record};
use rustls::ClientConfig;
use stats::GLOBAL_LOGGER;
use structopt::StructOpt;
mod cache;
mod tunman;

use once_cell::sync::Lazy;
use prelude::*;
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
        static IP_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
            regex::Regex::new(r#"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"#).unwrap()
        });
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
            style(level, level_str.clone()),
            record.file().unwrap_or("<unnamed>"),
            record.line().unwrap_or(0),
            &record.args()
        )?;
        let detailed_line = format!(
            "[{}] {} [{}:{}] {}",
            now.now().naive_utc().format("%Y-%m-%d %H:%M:%S"),
            level_str,
            record.file().unwrap_or("<unnamed>"),
            record.line().unwrap_or(0),
            &record.args()
        );
        if let Some(logger) = GLOBAL_LOGGER.lock().as_ref() {
            let _ = logger.try_send(
                IP_REGEX
                    .replace_all(&detailed_line, "[redacted]")
                    .to_string(),
            );
        }
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
        default_value = "https://www.netlify.com/v4/,https+nosni://www.cdn77.com/,https+nosni://ajax.aspnetcdn.com/,https+nosni://d3dsacqprgcsqh.cloudfront.net/,https://d1hoqe10mv32pv.cloudfront.net"
    )]
    /// HTTP(S) address of the binder, FRONTED
    binder_http_fronts: String,

    #[structopt(
        long,
        default_value = "loving-bell-981479.netlify.app,1049933718.rsc.cdn77.org,gephbinder-4.azureedge.net,dtnins2n354c4.cloudfront.net,dtnins2n354c4.cloudfront.net"
    )]
    /// HTTP(S) actual host of the binder
    binder_http_hosts: String,

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
    pub fn to_binder_client(&self) -> Arc<dyn BinderClient> {
        let fronts: Vec<_> = self
            .binder_http_fronts
            .split(',')
            .zip(self.binder_http_hosts.split(','))
            .map(|(front, host)| (front.to_string(), host.to_string()))
            .collect();
        let mut toret = binder_transport::MultiBinderClient::empty();
        for (mut front, host) in fronts {
            let mut tls_config = None;
            if front.contains("+nosni") {
                front = front.replace("+nosni", "");
                let mut cfg = ClientConfig::default();
                cfg.enable_sni = false;
                cfg.root_store
                    .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
                tls_config = Some(cfg);
            }
            toret = toret.add_client(binder_transport::HttpClient::new(
                self.binder_master,
                front,
                &[("Host".to_string(), host.clone())],
                tls_config,
            ));
        }
        Arc::new(toret)
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
