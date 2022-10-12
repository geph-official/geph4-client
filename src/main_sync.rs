use geph4_protocol::binder::{client::DynBinderClient, protocol::Level};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

use crate::config::{AuthOpt, CommonOpt, CACHED_BINDER_CLIENT};

#[derive(Debug, StructOpt, Deserialize, Serialize, Clone)]
pub struct SyncOpt {
    #[structopt(flatten)]
    pub common: CommonOpt,

    #[structopt(flatten)]
    pub auth: AuthOpt,

    /// Forces synchronization of fresh data.
    #[structopt(long)]
    force: bool,
}

pub async fn main_sync(opt: SyncOpt) -> anyhow::Result<()> {
    println!("{}", sync_json(opt).await?);
    Ok(())
}

pub async fn sync_json(opt: SyncOpt) -> anyhow::Result<String> {
    let master = CACHED_BINDER_CLIENT.get_summary().await?;
    let user = CACHED_BINDER_CLIENT.get_auth_token().await?.0;
    let exits = master
        .exits
        .into_iter()
        .map(|exit| DumbedDownExitDescriptor {
            hostname: exit.hostname.into(),
            signing_key: hex::encode(&exit.signing_key),
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
        })
        .collect_vec();
    Ok(format!(
        "{{\"exits\": {}, \"user\": {}}}",
        serde_json::to_string(&exits)?,
        serde_json::to_string(&user)?
    ))
}

#[derive(Serialize)]
struct DumbedDownExitDescriptor {
    hostname: String,
    signing_key: String,
    country_code: String,
    city_code: String,
    allowed_levels: Vec<String>,
}
