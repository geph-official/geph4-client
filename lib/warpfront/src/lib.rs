use std::{
    collections::HashMap, collections::VecDeque, net::SocketAddr, pin::Pin, sync::Arc,
    time::Duration,
};

use async_tls::TlsConnector;
use bytes::Bytes;
use dashmap::DashMap;
use http_types::{Method, Request, Response, StatusCode, Url};
use parking_lot::Mutex;
use protocol::{ClientReq, ServerResp};
use smol::prelude::*;
use smol_timeout::TimeoutExt;
use spiderchan::Spider;

mod protocol;
mod session;

/// An HTTP-based, warpfront-like backhaul.
pub struct Warpfront {
    send_data: smol::channel::Sender<(Bytes, SocketAddr)>,
    recv_data: smol::channel::Receiver<(Bytes, SocketAddr)>,
    driver: Arc<smol::Executor<'static>>,
    remotes: Arc<DashMap<SocketAddr, WfEndpoint>>,
}

/// A warpfront endpoint
#[derive(Clone, Debug)]
pub struct WfEndpoint {
    front_url: String,
    real_host: String,
}

impl Warpfront {
    /// Create a new warpfront-based backhaul.
    pub async fn new(listen_addr: Option<SocketAddr>) -> std::io::Result<Warpfront> {
        let (send_data, recv_send_data) = smol::channel::bounded(100);
        let (send_recv_data, recv_data) = smol::channel::bounded(100);
        let remotes = Arc::new(DashMap::default());
        let driver: smol::Executor<'static> = smol::Executor::new();
        let task = warpfront_task(
            &driver,
            listen_addr,
            recv_send_data,
            send_recv_data,
            remotes.clone(),
        )
        .await?;
        task.detach();
        Ok(Warpfront {
            send_data,
            recv_data,
            driver: Arc::new(driver),
            remotes,
        })
    }

    /// Send data along the 
}

/// Creates a warpfront task.
async fn warpfront_task(
    driver: &smol::Executor<'static>,
    listen_addr: Option<SocketAddr>,
    recv_send_data: smol::channel::Receiver<(Bytes, SocketAddr)>,
    send_recv_data: smol::channel::Sender<(Bytes, SocketAddr)>,
    remotes: Arc<DashMap<SocketAddr, WfEndpoint>>,
) -> std::io::Result<smol::Task<()>> {
    let spider = Spider::new(100);
    let incoming_fut = if let Some(listen_addr) = listen_addr {
        let listener = smol::net::TcpListener::bind(listen_addr).await?;
        handle_server(listener, spider.clone(), send_recv_data.clone()).boxed()
    } else {
        smol::future::pending().boxed()
    };
    driver.spawn(incoming_fut).detach();
    // we have a bunch of tasks pulling upstream packets and sending them to the endpoint
    Ok(driver.spawn(async move {
        let client = ClientPool::default();
        let lexec = smol::Executor::new();
        for _ in 0..64 {
            let up_task: smol::Task<anyhow::Result<()>> = lexec.spawn(async {
                loop {
                    let (bts, dest) = recv_send_data.recv().await?;
                    if let Some(endpoint) = remotes.get(&dest) {
                        let req = ClientReq {
                            packets: vec![bts],
                            timeout_ms: 0,
                        };
                        match once_client_req(&client, req, endpoint.clone()).await {
                            Ok(resp) => {
                                for resp in resp.packets {
                                    send_recv_data.send((resp, dest)).await?;
                                }
                            }
                            Err(e) => {
                                log::warn!("warpfront {}", e);
                                smol::Timer::after(Duration::from_secs(1)).await;
                            }
                        }
                    } else {
                        spider.send(dest, bts).await;
                    }
                }
            });
            up_task.detach();
        }
        lexec.run(smol::future::pending::<()>()).await;
    }))
}

async fn once_client_req(
    client: &ClientPool,
    req: ClientReq,
    endpoint: WfEndpoint,
) -> http_types::Result<ServerResp> {
    let bts: Bytes = bincode::serialize(&req)?.into();
    let endpoint = endpoint.clone();
    let mut req = Request::new(Method::Post, endpoint.front_url.parse::<Url>()?);
    req.insert_header("Host", endpoint.real_host);
    req.set_body(bts.to_vec());
    log::debug!("uploading pkt of length {}", bts.len());
    let mut resp = client.request(req).await?;
    let bts = resp.body_bytes().await?;
    Ok(bincode::deserialize(&bts)?)
}

async fn handle_server(
    server: smol::net::TcpListener,
    spider: Spider<SocketAddr, Bytes>,
    send_recv_data: smol::channel::Sender<(Bytes, SocketAddr)>,
) -> anyhow::Result<()> {
    // for every incoming request, forward it into send_recv_data, then try to get something from recv_back within the timeout. as simple as that
    let exec = smol::Executor::new();
    exec.run(async {
        loop {
            let (tcp_conn, client_addr) = server.accept().await?;
            let spider = spider.clone();
            let send_recv_data = send_recv_data.clone();
            exec.spawn(async move {
                let topic = spider
                    .subscribe(client_addr)
                    .ok_or_else(|| anyhow::anyhow!("spider error"))?;
                let send_recv_data = send_recv_data.clone();
                async_h1::accept(tcp_conn, move |mut req| {
                    let send_recv_data = send_recv_data.clone();
                    let topic = topic.clone();
                    async move {
                        let req: ClientReq = bincode::deserialize(&req.body_bytes().await?)?;
                        for bts in req.packets {
                            send_recv_data.send((bts, client_addr)).await?;
                        }
                        let possible_resp = topic
                            .recv()
                            .timeout(Duration::from_millis(req.timeout_ms))
                            .await;
                        let resp_bts = match possible_resp {
                            None => Bytes::new(),
                            Some(Some(v)) => v,
                            _ => {
                                return Err(http_types::Error::new(
                                    500,
                                    anyhow::anyhow!("spider error"),
                                ))
                            }
                        };
                        let resp_bts: &[u8] = &resp_bts;
                        let mut res = Response::new(StatusCode::Ok);
                        res.insert_header("content-type", "application/octet-stream");
                        res.set_body(resp_bts);
                        Ok(res)
                    }
                })
                .await
            })
            .detach()
        }
    })
    .await
}

trait AsyncRW: AsyncRead + AsyncWrite {}

impl<T: AsyncRead + AsyncWrite> AsyncRW for T {}

type ConnLike = async_dup::Arc<async_dup::Mutex<Pin<Box<dyn AsyncRW + 'static + Send>>>>;

fn connify<T: AsyncRead + AsyncWrite + 'static + Send>(conn: T) -> ConnLike {
    async_dup::Arc::new(async_dup::Mutex::new(Box::pin(conn)))
}

/// A HTTP connection pool
#[derive(Default)]
struct ClientPool {
    mapping: Mutex<HashMap<String, VecDeque<ConnLike>>>,
}

impl ClientPool {
    /// Does an HTTP request.
    async fn request(&self, req: Request) -> http_types::Result<Response> {
        let endpoint = req.url().to_string();
        let conn = self.connect(&endpoint).await?;
        let res = async_h1::connect(conn.clone(), req).await?;
        self.mapping
            .lock()
            .entry(endpoint)
            .or_insert_with(VecDeque::new)
            .push_back(conn);
        Ok(res)
    }

    /// Connects to a remote endpoint, returning the connection.
    async fn connect(&self, endpoint: &str) -> std::io::Result<ConnLike> {
        if let Some(conn) = self.try_get(endpoint) {
            return Ok(conn);
        }
        let toret = {
            let url = Url::parse(endpoint).map_err(other_e)?;
            let host_string = url.host_str().ok_or_else(|| other_e("no host"))?;
            let port = url.port_or_known_default().unwrap_or(0);
            let composed = format!("{}:{}", host_string, port);
            let tcp_conn = smol::net::TcpStream::connect(composed).await?;
            match url.scheme() {
                "http" => connify(tcp_conn),
                "https" => {
                    let connector = TlsConnector::default();
                    let tls_conn = connector.connect(host_string, tcp_conn).await?;
                    connify(tls_conn)
                }
                _ => return Err(other_e("only supports HTTP and HTTPS")),
            }
        };

        Ok(toret)
    }

    fn try_get(&self, endpoint: &str) -> Option<ConnLike> {
        self.mapping
            .lock()
            .entry(endpoint.into())
            .or_insert_with(VecDeque::new)
            .pop_front()
    }
}

fn other_e<T: Into<Box<dyn std::error::Error + Send + Sync>>>(e: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn google() {
        let client = ClientPool::default();
        smolscale::block_on(async move {
            dbg!(client
                .request(Request::new(
                    http_types::Method::Get,
                    "https://www.google.com/".parse::<Url>().unwrap()
                ))
                .await
                .unwrap());
        });
    }
}
