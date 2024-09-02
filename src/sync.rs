use anyhow::Context;
use geph4_protocol::binder::protocol::{Level, UserInfoV2};

use geph5_broker_protocol::BrokerClient;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use smol_timeout::TimeoutExt;
use std::time::Duration;
use stdcode::StdcodeSerializeExt;

use structopt::StructOpt;

use crate::config::{AuthOpt, CommonOpt, GEPH5_CONFIG_TEMPLATE};

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

    let broker_transport = BrokerClient::from(
        GEPH5_CONFIG_TEMPLATE
            .broker
            .as_ref()
            .unwrap()
            .rpc_transport(),
    );

    let timeout_duration = Duration::from_secs(15);
    let result = (async {
        let exits = broker_transport
            .get_exits()
            .await?
            .map_err(|e| anyhow::anyhow!(e))?;
        let free_exits = broker_transport
            .get_free_exits()
            .await?
            .map_err(|e| anyhow::anyhow!(e))?;
        // TODO verify
        let exits = exits.inner;
        let free_exits = free_exits.inner;
        let exits = exits
            .all_exits
            .into_iter()
            .map(|exit| DumbedDownExitDescriptor {
                hostname: exit.1.b2e_listen.ip().to_string(),
                signing_key: hex::encode(exit.0.as_bytes()),
                country_code: exit.1.country.alpha2().into(),
                city_code: exit.1.city.clone(),
                allowed_levels: if free_exits.all_exits.iter().map(|fe| fe.0).any(|fe| fe == exit.0) {
                    vec!["free".to_string(), "plus".to_string()]
                } else {
                    vec!["plus".to_string()]
                },
                load: exit.1.load as _,
            })
            .collect_vec();

        let credentials = match &opt.auth.auth_kind {
            Some(crate::config::AuthKind::AuthPassword { username, password }) => {
                geph5_broker_protocol::Credential::LegacyUsernamePassword { username: username.clone(), password: password.clone() }
            }
            _ => todo!(),
        };
        let user_cache_key = hex::encode(blake3::hash(&opt.auth.stdcode()).as_bytes());
        std::fs::create_dir_all(&opt.auth.credential_cache)?;
        let token_path = opt.auth.credential_cache.join(format!("{user_cache_key}-sync_auth_token"));
        let auth_token = if let Ok(val) = smol::fs::read_to_string(&token_path).await {
            val
        } else {
            let auth_token = broker_transport.get_auth_token(credentials).await??;
            smol::fs::write(&token_path, &auth_token).await?;
            auth_token
        };
        let user_info = broker_transport
            .get_user_info(auth_token)
            .await??
            .context("no such user")?;

        Ok(serde_json::json!({
            "exits": exits,
            "user": UserInfoV2 { userid: user_info.user_id as _, subscription: user_info.plus_expires_unix.map(|unix| {
                geph4_protocol::binder::protocol::SubscriptionInfo { level: Level::Plus, expires_unix: unix as _ }
            }) },
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
