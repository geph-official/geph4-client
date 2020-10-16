#![type_length_limit = "2000000"]

use std::{path::PathBuf, sync::Arc, time::Duration};

use binder_transport::BinderClient;
use env_logger::Env;
use structopt::StructOpt;
mod cache;
mod kalive;
mod persist;
use prelude::*;
mod prelude;
mod stats;

mod main_connect;
mod main_sync;
mod main_binderproxy;

static GEXEC: smol::Executor = smol::Executor::new();

#[global_allocator]
pub static ALLOCATOR: cap::Cap<std::alloc::System> = cap::Cap::new(std::alloc::System, 1024 * 1024 * 1000);

#[derive(Debug, StructOpt)]
enum Opt {
    Connect(main_connect::ConnectOpt),
    Sync(main_sync::SyncOpt),
    BinderProxy(main_binderproxy::BinderProxyOpt)
}

fn main() -> anyhow::Result<()> {
    sosistab::runtime::set_smol_executor(&GEXEC);
    let opt: Opt = Opt::from_args();
    env_logger::from_env(Env::default().default_filter_or("geph4_client=debug")).init();
    let version = env!("CARGO_PKG_VERSION");
    log::info!("geph4-client v{} starting...", version);
    smol::future::block_on(GEXEC.run(async move {
        match opt {
            Opt::Connect(opt) => main_connect::main_connect(opt).await,
            Opt::Sync(opt) => main_sync::main_sync(opt).await,
            Opt::BinderProxy(opt) => main_binderproxy::main_binderproxy(opt).await
        }
    }))
}

#[derive(Debug, StructOpt)]
pub struct CommonOpt {
    #[structopt(long, default_value = "https://www.netlify.com/v4/")]
    /// HTTP(S) address of the binder, FRONTED
    binder_http_front: String,

    #[structopt(long, default_value = "loving-bell-981479.netlify.app")]
    /// HTTP(S) actual host of the binder
    binder_http_host: String,

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
        Arc::new(binder_transport::HttpClient::new(
            self.binder_master,
            self.binder_http_front.to_string(),
            &[("Host".to_string(), self.binder_http_host.clone())],
        ))
    }
}

#[derive(Debug, StructOpt)]
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