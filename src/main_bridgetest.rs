use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use smol_timeout::TimeoutExt;
use structopt::StructOpt;

use crate::{AuthOpt, CommonOpt};

#[derive(Debug, StructOpt, Clone, Deserialize, Serialize)]
pub struct BridgeTestOpt {
    #[structopt(flatten)]
    common: CommonOpt,

    #[structopt(flatten)]
    auth: AuthOpt,

    #[structopt(long)]
    /// Whether to use TCP
    use_tcp: bool,
}

/// Entry point to the bridgetest subcommand, which sweeps through all available bridges and displays their reachability and performance in table.
pub async fn main_bridgetest(opt: BridgeTestOpt) -> anyhow::Result<()> {
    let cached_client = crate::to_cached_binder_client(&opt.common, &opt.auth).await?;

    let exits = cached_client.get_exits().await?;
    for exit in exits {
        eprintln!(
            "EXIT: {} ({}-{})",
            exit.hostname, exit.country_code, exit.city_code
        );
        cached_client.purge_bridges(&exit.hostname)?;
        let bridges = cached_client.get_bridges(&exit.hostname, false).await?;
        let proto = if opt.use_tcp {
            sosistab::Protocol::DirectTcp
        } else {
            sosistab::Protocol::DirectUdp
        };
        let iter = bridges
            .into_iter()
            .map(|bridge| {
                let proto = proto.clone();
                smolscale::spawn(async move {
                    let start = Instant::now();
                    let sess = sosistab::ClientConfig::new(
                        proto,
                        bridge.endpoint,
                        bridge.sosistab_key,
                        Default::default(),
                    )
                    .connect()
                    .timeout(Duration::from_secs(5))
                    .await;
                    match sess {
                        Some(Ok(_)) => eprintln!(">>> {} ({:?})", bridge.endpoint, start.elapsed()),
                        Some(Err(e)) => eprintln!(">>> {} (!! ERR: {} !!)", bridge.endpoint, e),
                        None => eprintln!(">>> {} (!! TIMEOUT !!)", bridge.endpoint),
                    }
                })
            })
            .collect::<Vec<_>>();
        for task in iter {
            task.await;
        }
    }
    Ok(())
}
