use geph4_protocol::binder::client::DynBinderClient;
use http_types::{Request, Response};
use nanorpc::JrpcRequest;
use nanorpc::RpcTransport;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use structopt::StructOpt;

use crate::config::CommonOpt;

#[derive(Debug, StructOpt, Deserialize, Serialize, Clone)]
pub struct BinderProxyOpt {
    #[structopt(flatten)]
    common: CommonOpt,

    /// Where to listen for HTTP requests
    #[structopt(long)]
    listen: SocketAddr,
}

fn dbg_err<T, E: std::fmt::Display>(f: Result<T, E>) -> Result<T, E> {
    match f {
        Ok(f) => Ok(f),
        Err(e) => {
            log::warn!("error: {}", e);
            Err(e)
        }
    }
}

pub async fn main_binderproxy(opt: BinderProxyOpt) -> anyhow::Result<()> {
    log::info!("binder proxy mode started");
    let binder_client = Arc::new(opt.common.get_binder_client());
    let listener = smol::net::TcpListener::bind(opt.listen).await?;
    loop {
        let (client, _) = listener.accept().await?;
        let binder_client = binder_client.clone();
        smolscale::spawn(async_h1::accept(client, move |req| {
            let binder_client = binder_client.clone();
            async move { dbg_err(handle_req(binder_client, req).await) }
        }))
        .detach();
    }
}

async fn handle_req(
    binder_client: Arc<DynBinderClient>,
    mut req: Request,
) -> http_types::Result<Response> {
    let request: JrpcRequest = req.body_json().await?;
    let jres = binder_client.0.call_raw(request).await?;
    let mut res = Response::from(serde_json::to_value(jres)?);
    res.insert_header("Access-Control-Allow-Origin", "*");
    res.insert_header("Access-Control-Allow-Methods", "GET, POST");
    res.insert_header("Access-Control-Allow-Headers", "Content-Type");
    res.insert_header("Access-Control-Expose-Headers", "*");
    Ok(res)
}
