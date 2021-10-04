use std::{net::SocketAddr, sync::Arc};

use crate::CommonOpt;
use geph4_binder_transport::{BinderClient, BinderError, BinderRequestData, BinderResponse};
use http_types::{Method, Request, Response};
use serde::{Deserialize, Serialize};
use smol_timeout::TimeoutExt;
use std::time::Duration;
use structopt::StructOpt;

const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, StructOpt)]
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
    let binder_client = opt.common.to_binder_client().await;
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
    binder_client: Arc<dyn BinderClient>,
    req: Request,
) -> http_types::Result<Response> {
    match req.url().path() {
        "/register" => handle_register(binder_client, req).await,
        "/captcha" => handle_captcha(binder_client, req).await,
        _ => Ok(Response::new(404)),
    }
    .map(|mut res| {
        res.insert_header("Access-Control-Allow-Origin", "*");
        res.insert_header("Access-Control-Allow-Methods", "GET, POST");
        res.insert_header("Access-Control-Allow-Headers", "Content-Type");
        res.insert_header("Access-Control-Expose-Headers", "*");
        res
    })
}

async fn handle_register(
    binder_client: Arc<dyn BinderClient>,
    mut req: Request,
) -> http_types::Result<Response> {
    if req.method() != Method::Post {
        return Ok("".into());
    }
    #[derive(Serialize, Deserialize, Debug)]
    struct Req {
        #[serde(rename = "Username")]
        username: String,
        #[serde(rename = "Password")]
        password: String,
        #[serde(rename = "CaptchaID")]
        captcha_id: String,
        #[serde(rename = "CaptchaSoln")]
        captcha_soln: String,
    }
    let request: Req = smol::future::block_on(req.take_body().into_json())?;
    match binder_client
        .request(BinderRequestData::RegisterUser {
            username: request.username,
            password: request.password,
            captcha_id: request.captcha_id,
            captcha_soln: request.captcha_soln,
        })
        .timeout(TIMEOUT)
        .await
    {
        Some(Ok(_)) => Ok(Response::new(200)),
        Some(Err(BinderError::WrongCaptcha)) => Ok(Response::new(422)),
        Some(Err(BinderError::UserAlreadyExists)) => Ok(Response::new(409)),
        _ => Ok(Response::new(500)),
    }
}

async fn handle_captcha(
    binder_client: Arc<dyn BinderClient>,
    _req: Request,
) -> http_types::Result<Response> {
    match binder_client
        .request(BinderRequestData::GetCaptcha)
        .timeout(TIMEOUT)
        .await
    {
        Some(Ok(BinderResponse::GetCaptchaResp {
            captcha_id,
            png_data,
        })) => {
            let mut resp = Response::new(200);
            resp.insert_header("Content-Type", "image/png");
            resp.insert_header("x-captcha-id", captcha_id);
            resp.set_body(png_data);
            Ok(resp)
        }
        _ => Ok(Response::new(500)),
    }
}
