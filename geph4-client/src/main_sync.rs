use std::collections::HashMap;

use crate::cache::ClientCache;
use crate::{AuthOpt, CommonOpt};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
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
    let mut client_cache = ClientCache::from_opts(&opt.common, &opt.auth)?;
    client_cache.force_sync = opt.force;
    if let Err(err) = attempt(&client_cache).await {
        let mut haha = HashMap::new();
        haha.insert("error".to_string(), err.to_string());
        let json = serde_json::to_string_pretty(&haha)?;
        println!("{}", json);
    }
    Ok(())
}

async fn attempt(ccache: &ClientCache) -> anyhow::Result<()> {
    let atok = ccache.get_auth_token().await?;
    let json = serde_json::to_string_pretty(&atok.user_info)?;
    println!("{}", json);
    Ok(())
}
