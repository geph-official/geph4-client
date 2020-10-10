#![type_length_limit = "1538014"]

use env_logger::Env;
use main_connect::ConnectOpt;
use structopt::StructOpt;
mod cache;
mod kalive;
mod main_connect;
mod persist;
mod prelude;
mod stats;

static GEXEC: smol::Executor = smol::Executor::new();

#[derive(Debug, StructOpt)]
enum Opt {
    Connect(ConnectOpt),
}

fn main() -> anyhow::Result<()> {
    sosistab::runtime::set_smol_executor(&GEXEC);
    let opt: Opt = Opt::from_args();
    env_logger::from_env(Env::default().default_filter_or("info")).init();
    let version = env!("CARGO_PKG_VERSION");
    log::info!("geph4-client v{} starting...", version);
    match opt {
        Opt::Connect(opt) => smol::block_on(GEXEC.run(main_connect::main_connect(opt))),
    }
}
