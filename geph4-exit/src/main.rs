use std::{path::PathBuf, sync::Arc, time::Duration};

use binder_transport::{BinderClient, BinderRequestData, BinderResponse};
use env_logger::Env;
use once_cell::sync::Lazy;
use std::os::unix::fs::PermissionsExt;
use structopt::StructOpt;

mod listen;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(long, default_value = "https://binder-v4.geph.io")]
    /// HTTP address of the binder
    binder_http: String,

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
}

static GEXEC: Lazy<smolscale::ExecutorPool> = Lazy::new(smolscale::ExecutorPool::new);

fn main() -> anyhow::Result<()> {
    let opt: Opt = Opt::from_args();
    sosistab::runtime::set_smol_executor(&GEXEC);
    env_logger::from_env(Env::default().default_filter_or("geph4_exit=info")).init();
    GEXEC.block_on(async move {
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
                        perms.set_mode(600);
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
        ));
        let exits = {
            let binder_client = binder_client.clone();
            let resp = smol::unblock(move || {
                binder_client.request(BinderRequestData::GetExits, Duration::from_secs(10))
            })
            .await?;
            match resp {
                BinderResponse::GetExitsResp(exits) => exits,
                _ => panic!(),
            }
        };
        // warn if not in exits
        if exits
            .iter()
            .find(|e| e.signing_key == signing_sk.public)
            .is_none()
        {
            log::warn!("this exit is not found at the binder; you should manually add it")
        }
        // listen
        listen::main_loop(
            &opt.exit_hostname,
            binder_client,
            &opt.bridge_secret,
            signing_sk,
            sosistab_sk,
        )
        .await?;
        Ok(())
    })
}
