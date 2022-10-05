use std::collections::HashMap;

use crate::{AuthOpt, CommonOpt};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

#[derive(Debug, StructOpt, Deserialize, Serialize)]
pub struct SyncOpt {
    #[structopt(flatten)]
    common: CommonOpt,

    #[structopt(flatten)]
    auth: AuthOpt,

    /// Forces synchronization of fresh data.
    #[structopt(long)]
    force: bool,
}

pub async fn main_sync(opt: SyncOpt) -> anyhow::Result<()> {
    println!("{}", sync_json(opt).await?);
    Ok(())
}

pub async fn sync_json(opt: SyncOpt) -> anyhow::Result<String> {
    let cbc = crate::to_cached_binder_client(&opt.common, &opt.auth).await?;
    log::info!("sync mode started (force = {})", opt.force);

    let res = cbc.sync(opt.force).await;
    match res {
        Ok(info) => {
            #[cfg(target_os = "ios")]
            if info.user_info.subscription.is_none() {
                return Ok(
                    "{\"error\": \"Not a Plus user / iOS beta testing only available to existing Plus users; the production version will be open to all users / 您非付费用户 / iOS beta 测试只面向付费用户；正式版会对免费用户开放\"}"
                        .to_owned(),
                );
            }
            let json = serde_json::to_string(&(info.user_info, info.exits, info.exits_free))?;
            Ok(json)
        }
        Err(err) => {
            let mut haha = HashMap::new();
            haha.insert("error".to_string(), err.to_string());
            let json = serde_json::to_string(&haha)?;
            Ok(json)
        }
    }
}
