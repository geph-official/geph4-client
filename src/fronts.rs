use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use anyhow::Context;
use async_trait::async_trait;
use geph4_protocol::binder::client::E2eeHttpTransport;
use http_types::{Method, Request, Url};
use itertools::Itertools;
use nanorpc::{DynRpcTransport, RpcTransport};
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
        static IDX: AtomicUsize = AtomicUsize::new(2);
        let idx = IDX.load(Ordering::Relaxed) % self.0.len();
        let random_element = &self.0[idx];
        log::debug!("selecting binder front {idx}");
        let vv = async {
            anyhow::Ok(
                random_element
                    .call_raw(req)
                    .timeout(Duration::from_secs(10))
                    .await
                    .context("timeout on one of the transports")??,
            )
        };
        match vv.await {
            Ok(v) => Ok(v),
            Err(err) => {
                log::warn!("binder front {idx} failed: {:?}", err);
                IDX.store(fastrand::usize(..), Ordering::Relaxed);
                Err(err)
            }
        }
    }
}

/// Obtains a front/host mapping from a URL.
#[cached::proc_macro::cached(result = true)]
pub async fn fetch_fronts(url: String) -> http_types::Result<BTreeMap<String, String>> {
    let url = Url::parse(&url)?;
    let req = Request::new(Method::Get, url.clone());
    let connect_to =
        geph4_aioutils::resolve(&format!("{}:443", url.host_str().context("bad")?)).await?;

    let response: BTreeMap<String, String> = {
        let connection =
            smol::net::TcpStream::connect(connect_to.get(0).context("no addrs for checkip")?)
                .await?;
        let tls_connection = async_tls::TlsConnector::default()
            .connect(url.host_str().context("bad")?, connection)
            .await?;
        async_h1::connect(tls_connection, req)
            .await?
            .body_json()
            .await?
    };
    Ok(response)
}
