

use serde::{Deserialize, Serialize};

use structopt::StructOpt;

use crate::config::{AuthOpt, CommonOpt};

#[derive(Debug, StructOpt, Clone, Deserialize, Serialize)]
pub struct BridgeTestOpt {
    #[structopt(flatten)]
    pub common: CommonOpt,

    #[structopt(flatten)]
    pub auth: AuthOpt,

    #[structopt(long)]
    /// Whether to use TCP
    use_tcp: bool,
}

/// Entry point to the bridgetest subcommand, which sweeps through all available bridges and displays their reachability and performance in table.
pub async fn main_bridgetest(_opt: BridgeTestOpt) -> anyhow::Result<()> {
    todo!()
    // let exits = CACHED_BINDER_CLIENT.get_summary().await?.exits;
    // for exit in exits {
    //     log::debug!(
    //         "EXIT: {} ({}-{})",
    //         exit.hostname,
    //         exit.country_code,
    //         exit.city_code
    //     );
    //     let bridges = CACHED_BINDER_CLIENT.get_bridges(&exit.hostname).await?;
    //     let proto = if opt.use_tcp {
    //         sosistab::Protocol::DirectTcp
    //     } else {
    //         sosistab::Protocol::DirectUdp
    //     };
    //     let iter = bridges
    //         .into_iter()
    //         .map(|bridge| {
    //             let proto = proto.clone();
    //             smolscale::spawn(async move {
    //                 let start = Instant::now();
    //                 let sess = sosistab::ClientConfig::new(
    //                     proto,
    //                     bridge.endpoint,
    //                     bridge.sosistab_key,
    //                     Default::default(),
    //                 )
    //                 .connect()
    //                 .timeout(Duration::from_secs(5))
    //                 .await;
    //                 match sess {
    //                     Some(Ok(_)) => {
    //                         log::debug!(">>> {} ({:?})", bridge.endpoint, start.elapsed())
    //                     }
    //                     Some(Err(e)) => log::debug!(">>> {} (!! ERR: {} !!)", bridge.endpoint, e),
    //                     None => log::debug!(">>> {} (!! TIMEOUT !!)", bridge.endpoint),
    //                 }
    //             })
    //         })
    //         .collect::<Vec<_>>();
    //     for task in iter {
    //         task.await;
    //     }
    // }
    // Ok(())
}
