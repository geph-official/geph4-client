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
    let mut client_cache = ClientCache::from_opts(&opt.common, &opt.auth).await?;
    client_cache.force_sync = opt.force;
    log::info!("sync mode started (force = {})", opt.force);
    if let Err(err) = attempt(&client_cache).await {
        let mut haha = HashMap::new();
        haha.insert("error".to_string(), err.to_string());
        let json = serde_json::to_string(&haha)?;
        println!("{}", json);
    }
    Ok(())
}

#[allow(clippy::eval_order_dependence)]
async fn attempt(ccache: &ClientCache) -> anyhow::Result<()> {
    let exec = smol::Executor::new();
    let atok = exec.spawn(ccache.get_auth_token());
    let exits = exec.spawn(ccache.get_exits());
    let exits_free = exec.spawn(ccache.get_free_exits());
    exec.run(async move {
        let json =
            serde_json::to_string(&(atok.await?.user_info, exits.await?, exits_free.await?))?;
        println!("{}", json);
        Ok(())
    })
    .await
}
