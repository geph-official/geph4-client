use geph4_protocol::binder::protocol::Level;

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use structopt::StructOpt;

use crate::config::{get_conninfo_store, AuthOpt, CommonOpt};

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
    let binder_client = get_conninfo_store(&opt.common, &opt.auth, "").await?;
    binder_client.refresh().await?; // we always refresh for the sync verb

    let master = binder_client.summary();
    let user = binder_client.user_info();
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
