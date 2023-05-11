use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use anyhow::Context;
use async_trait::async_trait;
use backoff::{backoff::Backoff, ExponentialBackoffBuilder};
use geph4_protocol::binder::client::E2eeHttpTransport;

use itertools::Itertools;
use nanorpc::{DynRpcTransport, RpcTransport};
use once_cell::sync::Lazy;
use smol_timeout::TimeoutExt;

/// Parses a list of front/host pairs and produces a DynRpcTransport.
pub fn parse_fronts(
    binder_lpk: [u8; 32],
    fronts: impl IntoIterator<Item = (String, String)>,
) -> DynRpcTransport {
    // make a list of the different alternatives, then select between them at random while increasing the timeout every time
    let alternatives = fronts
        .into_iter()
        .map(|(endpoint, real_host)| {
            DynRpcTransport::new(E2eeHttpTransport::new(
                binder_lpk,
                endpoint,
                vec![("host".to_string(), real_host)],
            ))
        })
        .collect_vec();
    let unified = MultiRpcTransport(alternatives);
    DynRpcTransport::new(unified)
}

struct MultiRpcTransport(Vec<DynRpcTransport>);

#[async_trait]
impl RpcTransport for MultiRpcTransport {
    type Error = anyhow::Error;

    async fn call_raw(
        &self,
        req: nanorpc::JrpcRequest,
    ) -> Result<nanorpc::JrpcResponse, Self::Error> {
        let mut backoff = ExponentialBackoffBuilder::new()
            .with_max_elapsed_time(Duration::from_secs(30).into())
            .build();
        loop {
            static IDX: Lazy<AtomicUsize> = Lazy::new(|| AtomicUsize::new(fastrand::usize(..)));
            let idx = IDX.load(Ordering::Relaxed) % self.0.len();
            let random_element = &self.0[idx];
            log::debug!("selecting binder front {idx} for method {:?}", req.method);
            let req = req.clone();
            let vv = async {
                anyhow::Ok(
                    random_element
                        .call_raw(req)
                        .timeout(Duration::from_secs(3))
                        .await
                        .context("timeout on one of the transports")??,
                )
            };
            match vv.await {
                Ok(v) => return Ok(v),
                Err(err) => {
                    log::warn!("binder front {idx} failed: {:?}", err);
                    IDX.fetch_add(1, Ordering::Relaxed);
                    if let Some(next) = backoff.next_backoff() {
                        log::debug!("backing off for {:?}", next);
                        smol::Timer::after(next).await;
                    } else {
                        return Err(err);
                    }
                }
            }
        }
    }
}
