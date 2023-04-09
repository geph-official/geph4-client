use geph4_protocol::binder::protocol::Level;

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

use crate::config::{user_id_hex, get_cached_binder_client, AuthOpt, CommonOpt};

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
    let orig_dbpath = opt.auth.credential_cache.clone();

    // this will leave original status unmodified, and ONLY overwriting if success to get next state.
    // so (in the case) if we unable to fetch network info from binder, this will make the program able to fallback to last one
    let next_dbpath = {
        let mut p = orig_dbpath.clone();
        assert!(
            // that do something like this: /tmp/cache -> /tmp/cache.next-state-123
            p.set_extension(
                format!("next-state-{}", fastrand::u32(..))
            )
        );
        p
    };

    //println!("called: next-state-dir: {:?}", &next_dbpath);
    //println!("orig-state: {:?}", &orig_dbpath);

    // make sure next state is empty
    for _ in 0..100 {
        let _ = std::fs::remove_dir_all(&next_dbpath);
    }


    let binder_client = get_cached_binder_client(&opt.common, &{
        // create a temp context for binder_client only
        let mut opt_auth = opt.auth.clone();
        opt_auth.credential_cache = next_dbpath.clone();
        opt_auth
    })?;
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

    // in this case, we got latest network info from binder:
    // so use ".next.state" to overwrite the real cache path.
    let id = user_id_hex(&opt.auth);
    std::fs::rename({
        let mut p = orig_dbpath.clone();
        p.push(&id);
        for _ in 0..100 { let _ = std::fs::remove_dir_all(&p); }

        let mut p = next_dbpath.clone();
        p.push(&id);
        p
    }, {
        let mut p = orig_dbpath.clone();
        p.push(id);
        p
    })?;

    // clean temp directory to avoid dropping junk to local disk
    for _ in 0..100 {
        let _ = std::fs::remove_dir_all(&next_dbpath);
    }

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
