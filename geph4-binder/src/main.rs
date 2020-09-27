mod bindercore;
mod responder;
use std::{net::SocketAddr, path::PathBuf};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Opt {
    /// PostgreSQL database URL
    #[structopt(long)]
    database: String,
    /// Path to database connection CA file
    #[structopt(long)]
    database_ca_cert: PathBuf,
    /// Captcha service
    #[structopt(default_value = "https://single-verve-156821.ew.r.appspot.com", long)]
    captcha_endpoint: String,
    /// HTTP listening port
    #[structopt(default_value = "127.0.0.1:18080", long)]
    listen_http: SocketAddr,
}

fn main() {
    let opt = Opt::from_args();
    let binder_core = bindercore::BinderCore::create(
        &opt.database,
        &opt.captcha_endpoint,
        &std::fs::read(opt.database_ca_cert).unwrap(),
    );
    dbg!(binder_core.get_mizaru_sk().unwrap().to_public_key());
}
