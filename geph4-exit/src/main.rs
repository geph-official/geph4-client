use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use binder_transport::{BinderClient, BinderRequestData, BinderResponse};
use env_logger::Env;
use jemallocator::Jemalloc;
use std::os::unix::fs::PermissionsExt;
use structopt::StructOpt;

mod asn; 
mod connect;
mod listen;
mod lists;
mod ratelimit;
mod vpn;

#[derive(Debug, StructOpt, Clone)]
struct Opt {
    #[structopt(long, default_value = "https://binder-v4.geph.io")]
    /// HTTP address of the binder
    binder_http: String,

    #[structopt(long, default_value = "172.105.28.221:8125")]
    /// UDP address of the statsd daemon
    statsd_addr: SocketAddr,

    #[structopt( 
        long,
        default_value = "124526f4e692b589511369687498cce57492bf4da20f8d26019c1cc0c80b6e4b"
    )]
    /// x25519 master key of the binder
    binder_master_pk: String,

    #[structopt(long, default_value = "/var/local/geph4-exit.key")]
    /// signing key location
    signing_sk: PathBuf,

    /// bridge secret. All bridges and exits know this secret, and it's used to prevent random people from spamming the bridge table.
    #[structopt(long)]
    bridge_secret: String,

    /// Hostname of this exit.
    #[structopt(long)]
    exit_hostname: String,

    /// Speed limit for free users, in KB/s. If zero, completely blocks free users.
    #[structopt(long, default_value = "200")]
    free_limit: u32,

    /// Whether or not to use port whitelist.
    #[structopt(long)]
    port_whitelist: bool,

    /// Google proxy server to redirect all port 443 Google requests to.
    #[structopt(long)]
    google_proxy: Option<SocketAddr>,

    /// External interface to run the VPN NAT on.
    #[structopt(long)]
    nat_interface: String,
}

#[global_allocator]
pub static ALLOCATOR: Jemalloc = Jemalloc;

fn main() -> anyhow::Result<()> {
    // smolscale::permanently_single_threaded();
    let opt: Opt = Opt::from_args();
    let stat_client = statsd::Client::new(opt.statsd_addr, "geph4")?;
    env_logger::Builder::from_env(Env::default().default_filter_or("geph4_exit=debug,warn")).init();
    smol::future::block_on(smolscale::spawn(async move {
        config_iptables(&opt).await?;
        log::info!("geph4-exit starting...");
        // read or generate key
        let signing_sk = {
            match std::fs::read(&opt.signing_sk) {
                Ok(vec) => bincode::deserialize(&vec)?,
                Err(err) => {
                    log::warn!(
                        "can't read signing_sk, so creating one and saving it! {}",
                        err
                    );
                    let new_keypair = ed25519_dalek::Keypair::generate(&mut rand::rngs::OsRng {});
                    if let Err(err) =
                        std::fs::write(&opt.signing_sk, bincode::serialize(&new_keypair)?)
                    {
                        log::error!("cannot save signing_sk persistently!!! {}", err);
                    } else {
                        let mut perms = std::fs::metadata(&opt.signing_sk)?.permissions();
                        perms.set_readonly(true);
                        perms.set_mode(0o600);
                        std::fs::set_permissions(&opt.signing_sk, perms)?;
                    }
                    new_keypair
                }
            }
        };
        let sosistab_sk = x25519_dalek::StaticSecret::from(*signing_sk.secret.as_bytes());
        log::info!("signing_pk = {}", hex::encode(signing_sk.public.as_bytes()));
        log::info!(
            "sosistab_sk = {}",
            hex::encode(x25519_dalek::PublicKey::from(&sosistab_sk).as_bytes())
        );
        // create binder client
        let binder_client = Arc::new(binder_transport::HttpClient::new(
            bincode::deserialize(&hex::decode(opt.binder_master_pk)?)?,
            &opt.binder_http,
            &[],
            None,
        ));
        let exits = {
            let resp = binder_client.request(BinderRequestData::GetExits).await?;
            match resp {
                BinderResponse::GetExitsResp(exits) => exits,
                _ => panic!(),
            } 
        };
        // warn if not in exits
        if !exits.iter().any(|e| e.signing_key == signing_sk.public) {
            log::warn!("this exit is not found at the binder; you should manually add it first")
        }
        // listen
        listen::main_loop(
            stat_client,
            &opt.exit_hostname,
            binder_client,
            &opt.bridge_secret,
            signing_sk,
            sosistab_sk,
            opt.free_limit,
            opt.google_proxy,
            opt.port_whitelist,
        )
        .await?;
        Ok(())
    }))
}

/// Configures iptables.
async fn config_iptables(opt: &Opt) -> anyhow::Result<()> {
    let to_run = format!(
        r#"
    #!/bin/sh
export INTERFACE={}

iptables --flush
iptables -t nat -F

iptables -t nat -A PREROUTING -i tun-geph -p tcp --syn -j REDIRECT --match multiport --dports 80,443,8080 --to-ports 10000

iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE --random
iptables -A FORWARD -i $INTERFACE -o tun-geph -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i tun-geph -o $INTERFACE -j ACCEPT
iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
"#,
        opt.nat_interface
    );
    let cmd = smol::process::Command::new("sh")
        .arg("-c")
        .arg(&to_run)
        .spawn()?;
    cmd.output().await?;
    Ok(())
}
