use env_logger::Env;
use main_connect::ConnectOpt;
use once_cell::sync::Lazy;
use structopt::StructOpt;
mod cache;
mod kalive;
mod main_connect;
mod persist;
mod prelude;

static GEXEC: Lazy<smolscale::ExecutorPool> = Lazy::new(smolscale::ExecutorPool::new);

#[derive(Debug, StructOpt)]
enum Opt {
    Connect(ConnectOpt),
}

fn main() -> anyhow::Result<()> {
    let opt: Opt = Opt::from_args();
    env_logger::from_env(Env::default().default_filter_or("info")).init();
    let version = env!("CARGO_PKG_VERSION");
    log::info!("geph4-client v{} starting...", version);
    sosistab::runtime::set_smol_executor(&GEXEC);
    match opt {
        Opt::Connect(opt) => GEXEC.block_on(main_connect::main_connect(opt)),
    }
}
