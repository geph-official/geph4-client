use crate::{
    encrypt_binder_response, BinderClient, BinderError, BinderRequest, BinderRequestData,
    BinderResponse, BinderResult, BinderServer, EncryptedBinderRequestData,
    EncryptedBinderResponse,
};
use async_tls::TlsConnector;
use http_types::{Method, Request, StatusCode, Url};
use smol::channel::{Receiver, Sender};
use smol_timeout::TimeoutExt;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

/// An HTTP-based BinderClient implementation, driven by ureq.
#[derive(Clone)]
pub struct HttpClient {
    binder_lpk: x25519_dalek::PublicKey,
    endpoint: String,
    headers: Vec<(String, String)>,
    tls_config: rustls::ClientConfig,
}

impl HttpClient {
    /// Create a new HTTP client from the given endpoint and headers.
    pub fn new<T: ToString>(
        binder_lpk: x25519_dalek::PublicKey,
        endpoint: T,
        headers: &[(T, T)],
        tls_config: Option<rustls::ClientConfig>,
    ) -> Self {
        let mut default_tls_config = rustls::ClientConfig::default();
        default_tls_config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        HttpClient {
            binder_lpk,
            endpoint: endpoint.to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            tls_config: tls_config.unwrap_or(default_tls_config),
        }
    }
}

#[async_trait::async_trait]
impl BinderClient for HttpClient {
    async fn request(&self, brequest: BinderRequestData) -> BinderResult<BinderResponse> {
        let everything = async move {
            // open connection
            let conn = endpoint_to_conn(self.tls_config.clone(), &self.endpoint)
                .await
                .map_err(|v| BinderError::Other(v.to_string()))?;
            // send request
            let mut req = Request::new(Method::Post, Url::parse(&self.endpoint).unwrap());
            for (header, value) in self.headers.iter() {
                req.insert_header(header.as_str(), value.as_str());
            }
            // set body
            let my_esk = x25519_dalek::EphemeralSecret::new(rand::rngs::OsRng {});
            let (encrypted, reply_key) = brequest.encrypt(my_esk, self.binder_lpk);
            req.set_body(bincode::serialize(&encrypted).unwrap());
            // do the request
            let mut response = async_h1::connect(conn, req)
                .await
                .map_err(|v| BinderError::Other(v.to_string()))?;

            // read response
            let response: EncryptedBinderResponse = bincode::deserialize(
                &response
                    .body_bytes()
                    .await
                    .map_err(|v| BinderError::Other(v.to_string()))?,
            )
            .map_err(|v| BinderError::Other(v.to_string()))?;
            response
                .decrypt(reply_key)
                .ok_or_else(|| BinderError::Other("decryption failure".into()))?
        };
        everything
            .timeout(Duration::from_secs(30))
            .await
            .ok_or_else(|| BinderError::Other("HTTP timeout in 30 secs".into()))?
    }
}
/// An HTTP-based BinderServer implementation. It uses `async-h1` underneath,
/// driven by an internal executor so that it exposes a synchronous interface.
pub struct HttpServer {
    breq_recv: Receiver<BinderRequest>,
    executor: Arc<smol::Executor<'static>>,
}

impl HttpServer {
    /// Creates a new HttpServer listening on the given SocketAddr with the given secret key.
    pub fn new(
        listen_on: SocketAddr,
        my_lsk: x25519_dalek::StaticSecret,
        on_time: impl Fn(Duration) + Send + Sync + 'static,
    ) -> Self {
        let executor = Arc::new(smol::Executor::new());
        let (breq_send, breq_recv) = smol::channel::unbounded();
        executor
            .spawn(httpserver_main_loop(
                executor.clone(),
                listen_on,
                my_lsk,
                breq_send,
                on_time,
            ))
            .detach();
        Self {
            breq_recv,
            executor,
        }
    }
}

/// Returns a connection, given an endpoint. Implements a happy-eyeballs-style thing.
async fn endpoint_to_conn(
    tls_config: rustls::ClientConfig,
    endpoint: &str,
) -> std::io::Result<aioutils::ConnLike> {
    let url = Url::parse(endpoint).map_err(aioutils::to_ioerror)?;
    let host_string = url
        .host_str()
        .map(|v| v.to_owned())
        .ok_or_else(|| aioutils::to_ioerror("no host"))?;
    let port = url.port_or_known_default().unwrap_or(0);
    let composed = format!("{}:{}", host_string, port);
    let (send, recv) = smol::channel::unbounded();
    let mut _tasks: Vec<smol::Task<std::io::Result<()>>> = vec![];
    // race
    for (index, addr) in aioutils::resolve(&composed).await?.into_iter().enumerate() {
        let send = send.clone();
        let delay = Duration::from_millis(250) * index as u32;
        _tasks.push(smolscale::spawn(async move {
            smol::Timer::after(delay).await;
            let tcp_conn = smol::net::TcpStream::connect(addr).await?;
            let _ = send.send(tcp_conn).await;
            Ok(())
        }));
    }
    if let Ok(tcp_conn) = recv.recv().await {
        match url.scheme() {
            "https" => {
                let connector = TlsConnector::from(tls_config);
                let tls_conn = connector.connect(host_string, tcp_conn).await?;
                Ok(aioutils::connify(tls_conn))
            }
            _ => Ok(aioutils::connify(tcp_conn)),
        }
    } else if !_tasks.is_empty() {
        for task in _tasks {
            task.await?;
        }
        panic!("should not get here")
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "DNS did not return any results",
        ))
    }
}

impl BinderServer for HttpServer {
    /// Next request
    fn next_request(&self) -> std::io::Result<BinderRequest> {
        smol::future::block_on(
            self.executor
                .run(async move { self.breq_recv.recv().await }),
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Interrupted, e))
    }
}

async fn httpserver_main_loop(
    executor: Arc<smol::Executor<'static>>,
    listen_on: SocketAddr,
    my_lsk: x25519_dalek::StaticSecret,
    breq_send: Sender<BinderRequest>,
    on_time: impl Fn(Duration) + Send + Sync + 'static,
) -> Option<()> {
    let on_time = Arc::new(on_time);
    let listener = smol::net::TcpListener::bind(listen_on).await.unwrap();
    log::debug!("listening on {}", listen_on);
    loop {
        if let Ok((client, _)) = listener.accept().await {
            let my_lsk = my_lsk.clone();
            let breq_send = breq_send.clone();
            let peer_addr = client.peer_addr().unwrap();
            log::trace!("new connection from {}", peer_addr);
            let on_time = on_time.clone();
            // start a new task
            executor
                .spawn(async move {
                    let my_lsk = my_lsk.clone();
                    drop(
                        async_h1::accept(client, |mut req| {
                            let start = Instant::now();
                            let my_lsk = my_lsk.clone();
                            let breq_send = breq_send.clone();
                            let on_time = on_time.clone();
                            async move {
                                // first read the request
                                let req: EncryptedBinderRequestData =
                                    bincode::deserialize(&req.body_bytes().await?)?;
                                let (request_data, reply_key) =
                                    req.decrypt(&my_lsk).ok_or_else(|| {
                                        http_types::Error::from_str(
                                            http_types::StatusCode::BadRequest,
                                            "decryption failure",
                                        )
                                    })?;
                                log::trace!("got request from {}: {:?}", peer_addr, request_data);
                                // form response
                                let (oneshot_send, oneshot_recv) = smol::channel::bounded(1);
                                let breq = BinderRequest {
                                    request_data,
                                    response_send: Box::new(move |val| {
                                        drop(oneshot_send.try_send(val))
                                    }),
                                };
                                breq_send.send(breq).await?;
                                // wait for response
                                let response: BinderResult<BinderResponse> =
                                    oneshot_recv.recv().await?;
                                log::trace!("response to {}: {:?}", peer_addr, response);
                                let response = encrypt_binder_response(&response, reply_key);
                                // send response
                                let mut resp = http_types::Response::new(StatusCode::Ok);
                                resp.set_body(bincode::serialize(&response).unwrap());
                                on_time(start.elapsed());
                                Ok(resp)
                            }
                        })
                        .await,
                    );
                })
                .detach();
        } else {
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    }
}
