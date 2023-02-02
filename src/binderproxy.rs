use crate::config::CommonOpt;
use geph4_protocol::binder::protocol::BinderClient;
use nanorpc::JrpcRequest;
use nanorpc::{DynRpcTransport, RpcTransport};
use serde::{Deserialize, Serialize};
use smol::io::AsyncBufReadExt;
use std::sync::Arc;
use structopt::StructOpt;

#[derive(Debug, StructOpt, Deserialize, Serialize, Clone)]
pub struct BinderProxyOpt {
    #[structopt(flatten)]
    pub common: CommonOpt,
}

pub async fn main_binderproxy(opt: BinderProxyOpt) -> anyhow::Result<()> {
    log::info!("binder proxy mode started; send a JSON-RPC line on stdin to get a response");
    let binder_client = Arc::new(opt.common.get_binder_client());
    let mut input = smol::io::BufReader::new(smol::Unblock::new(std::io::stdin()));
    let mut line = String::new();
    loop {
        line.clear();
        input.read_line(&mut line).await?;
        let resp = binderproxy_once(binder_client.clone(), line.clone()).await?;
        println!("{resp}");
    }
}

pub async fn binderproxy_once(
    binder_client: Arc<BinderClient<DynRpcTransport>>,
    line: String,
) -> anyhow::Result<String> {
    log::info!("binder proxy once");
    let req: JrpcRequest = serde_json::from_str(&line)?;
    loop {
        match binder_client.0.call_raw(req.clone()).await {
            Ok(res) => return Ok(serde_json::to_string(&res)?),
            Err(err) => {
                log::warn!("error: {:?}", err);
            }
        }
    }
}
