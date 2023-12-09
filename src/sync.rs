use geph4_protocol::binder::protocol::Level;

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use smol_timeout::TimeoutExt;
use std::time::Duration;

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
    log::info!("SYNC getting conninfo store");

    let timeout_duration = Duration::from_secs(15);
    let result = (async {
        let binder_client = get_conninfo_store(&opt.common, &opt.auth, "").await?;
        binder_client.refresh().await?; // we always refresh for the sync verb

        let master = binder_client.summary().await?;
        let user = binder_client.user_info().await?;
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

        Ok(serde_json::json!({
            "exits": exits,
            "user": user,
            "version": VERSION
        })
        .to_string())
    })
    .timeout(timeout_duration)
    .await;

    match result {
        Some(res) => res,
        None => anyhow::bail!(
            "sync timed out after {:?} seconds",
            timeout_duration.as_secs()
        ),
    }
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
