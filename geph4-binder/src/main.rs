mod bindercore;
mod responder;
use env_logger::Env;
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
    env_logger::from_env(Env::default().default_filter_or("geph4_binder=debug")).init();
    let opt = Opt::from_args();
    let binder_core = bindercore::BinderCore::create(
        &opt.database,
        &opt.captcha_endpoint,
        &std::fs::read(opt.database_ca_cert).unwrap(),
    );
    let master_secret = binder_core.get_master_sk().unwrap();
    let free_mizaru_sk = binder_core.get_mizaru_sk("free").unwrap();
    let plus_mizaru_sk = binder_core.get_mizaru_sk("plus").unwrap();
    println!("geph4-binder starting with:");
    println!(
        "  Master x25519 public key = {}",
        hex::encode(x25519_dalek::PublicKey::from(&master_secret).to_bytes())
    );
    println!(
        "  Mizaru public key (FREE) = {}",
        hex::encode(free_mizaru_sk.to_public_key().0)
    );
    println!(
        "  Mizaru public key (PLUS) = {}",
        hex::encode(plus_mizaru_sk.to_public_key().0)
    );
    // create server
    let http_serv = binder_transport::HttpServer::new(opt.listen_http, master_secret);
    println!("HTTP listening on {}", opt.listen_http);
    responder::handle_requests(http_serv, &binder_core)
}
