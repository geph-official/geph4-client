use env_logger::Env;
use structopt::StructOpt;
#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(long, default_value = "http://binder-v4.geph.io:8964")]
    /// HTTP(S) address of the binder
    binder_http: String,

    #[structopt(
        long,
        default_value = "124526f4e692b589511369687498cce57492bf4da20f8d26019c1cc0c80b6e4b"
    )]
    /// x25519 master key of the binder
    binder_master_pk: String,
}

fn main() -> anyhow::Result<()> {
    // structured concurrency
    smol::block_on(async move {
        let opt: Opt = Opt::from_args();
        env_logger::from_env(Env::default().default_filter_or("info")).init();
        unimplemented!()
    })
}
