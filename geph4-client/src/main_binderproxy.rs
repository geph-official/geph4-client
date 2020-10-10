use std::{net::SocketAddr, sync::Arc};

use crate::{CommonOpt, GEXEC};
use binder_transport::{BinderClient, BinderError, BinderRequestData, BinderResponse};
use http_types::{Request, Response};
use serde::{Deserialize, Serialize};
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
    let binder_client = opt.common.to_binder_client();
    let listener = smol::net::TcpListener::bind(opt.listen).await?;
    loop {
        let (client, _) = listener.accept().await?;
        let binder_client = binder_client.clone();
        GEXEC
            .spawn(async_h1::accept(client, move |req| {
                let binder_client = binder_client.clone();
                smol::unblock(move || dbg_err(handle_req(binder_client, req)))
            }))
            .detach();
    }
}

fn handle_req(binder_client: Arc<dyn BinderClient>, req: Request) -> http_types::Result<Response> {
    match req.url().path() {
        "/register" => handle_register(binder_client, req),
        "/get-captcha" => handle_get_captcha(binder_client, req),
        _ => Ok(Response::new(404)),
    }
}

fn handle_register(
    binder_client: Arc<dyn BinderClient>,
    mut req: Request,
) -> http_types::Result<Response> {
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
    match binder_client.request(
        BinderRequestData::RegisterUser {
            username: request.username,
            password: request.password,
            captcha_id: request.captcha_id,
            captcha_soln: request.captcha_soln,
        },
        TIMEOUT,
    ) {
        Ok(_) => Ok(Response::new(200)),
        Err(BinderError::WrongCaptcha) => Ok(Response::new(422)),
        Err(BinderError::UserAlreadyExists) => Ok(Response::new(409)),
        _ => Ok(Response::new(500)),
    }
}

fn handle_get_captcha(
    binder_client: Arc<dyn BinderClient>,
    _req: Request,
) -> http_types::Result<Response> {
    match binder_client.request(BinderRequestData::GetCaptcha, TIMEOUT) {
        Ok(BinderResponse::GetCaptchaResp {
            captcha_id,
            png_data,
        }) => {
            let mut resp = Response::new(200);
            resp.insert_header("Content-Type", "image/png");
            resp.insert_header("x-captcha-id", captcha_id);
            resp.set_body(png_data);
            Ok(resp)
        }
        _ => Ok(Response::new(500)),
    }
}
