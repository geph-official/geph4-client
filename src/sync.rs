use geph4_protocol::binder::protocol::Level;

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use stdcode::StdcodeSerializeExt;
use structopt::StructOpt;

use crate::config::{get_cached_binder_client, AuthOpt, CommonOpt};

#[derive(Debug, StructOpt, Deserialize, Serialize, Clone)]
pub struct SyncOpt {
    #[structopt(flatten)]
    pub common: CommonOpt,

    #[structopt(flatten)]
    pub auth: AuthOpt,

    /// Forces synchronization of fresh data.
    #[structopt(long)]
    pub force: bool,
}

pub async fn main_sync(opt: SyncOpt) -> anyhow::Result<()> {
    println!("{}", sync_json(opt).await?);
    Ok(())
}
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn sync_json(opt: SyncOpt) -> anyhow::Result<String> {
    if opt.force {
        let mut dbpath = opt.auth.credential_cache.clone();

        let user_cache_key = hex::encode(blake3::hash(&opt.auth.auth_kind.stdcode()).as_bytes());
        dbpath.push(&user_cache_key);
        // clear the entire directory, baby!
        for _ in 0..10 {
            let _ = std::fs::remove_dir_all(&dbpath);
        }
    }

    let binder_client = get_cached_binder_client(&opt.common, &opt.auth)?;
    let master = binder_client.get_summary().await?;
    let user = binder_client.get_auth_token().await?.0;
    let exits = master
        .exits
        .into_iter()
        .map(|exit| DumbedDownExitDescriptor {
            hostname: exit.hostname.into(),
            signing_key: hex::encode(exit.signing_key),
            country_code: exit.country_code.into(),
            city_code: exit.city_code.into(),
            allowed_levels: exit
                .allowed_levels
                .into_iter()
                .map(|l| match l {
                    Level::Free => "free".to_string(),
                    Level::Plus => "plus".to_string(),
                })
                .collect_vec(),
            load: exit.load,
        })
        .collect_vec();
    Ok(format!(
        "{{\"exits\": {}, \"user\": {}, \"version\": {:?}}}",
        serde_json::to_string(&exits)?,
        serde_json::to_string(&user)?,
        VERSION
    ))
}

#[derive(Serialize)]
struct DumbedDownExitDescriptor {
    hostname: String,
    signing_key: String,
    country_code: String,
    city_code: String,
    allowed_levels: Vec<String>,
    load: f64,
}
