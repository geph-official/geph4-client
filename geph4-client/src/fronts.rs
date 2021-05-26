use std::{collections::BTreeMap, sync::Arc};

use anyhow::Context;
use binder_transport::BinderClient;
use http_types::{Method, Request, Url};
use rustls::ClientConfig;

/// Parses a list of front/host pairs and produces a BinderClient.
pub fn parse_fronts(
    master_key: x25519_dalek::PublicKey,
    fronts: impl IntoIterator<Item = (String, String)>,
) -> Arc<dyn BinderClient> {
    let mut toret = binder_transport::MultiBinderClient::empty();
    for (mut front, host) in fronts {
        let mut tls_config = None;
        if front.contains("+nosni") {
            front = front.replace("+nosni", "");
            let mut cfg = ClientConfig::default();
            cfg.enable_sni = false;
            cfg.root_store
                .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
            tls_config = Some(cfg);
        }
        toret = toret.add_client(binder_transport::HttpClient::new(
            master_key,
            front,
            &[("Host".to_string(), host.clone())],
            tls_config,
        ));
    }
    Arc::new(toret)
}

/// Obtains a front/host mapping from a URL.
#[cached::proc_macro::cached(result = true)]
pub async fn fetch_fronts(url: String) -> http_types::Result<BTreeMap<String, String>> {
    let url = Url::parse(&url)?;
    let req = Request::new(Method::Get, url.clone());
    let connect_to = aioutils::resolve(&format!("{}:443", url.host_str().context("bad")?)).await?;

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
