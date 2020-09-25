use crate::{
    encrypt_binder_response, BinderClient, BinderError, BinderRequest, BinderRequestData,
    BinderResponse, BinderResult, BinderServer, EncryptedBinderRequestData,
    EncryptedBinderResponse,
};
use http_types::StatusCode;
use smol::channel::{Receiver, Sender};
use std::{net::SocketAddr, sync::Arc, time::Duration};

/// An HTTP-based BinderClient implementation, driven by ureq.
pub struct HttpClient {
    binder_lpk: x25519_dalek::PublicKey,
    endpoint: String,
    headers: Vec<(String, String)>,
}

impl HttpClient {
    /// Create a new HTTP client from the given endpoint and headers.
    pub fn new<T: ToString>(
        binder_lpk: x25519_dalek::PublicKey,
        endpoint: T,
        headers: &[(T, T)],
    ) -> Self {
        HttpClient {
            binder_lpk,
            endpoint: endpoint.to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }
}

impl BinderClient for HttpClient {
    fn request(
        &self,
        brequest: BinderRequestData,
        timeout: std::time::Duration,
    ) -> BinderResult<BinderResponse> {
        let mut request = ureq::post(&self.endpoint);
        // set headers
        for (header, value) in self.headers.iter() {
            request.set(header, value);
        }
        // set body
        let my_esk = x25519_dalek::EphemeralSecret::new(rand::rngs::OsRng {});
        let (encrypted, reply_key) = brequest.encrypt(my_esk, self.binder_lpk);
        request.timeout(timeout);
        // do the request
        let response = request.send_bytes(&bincode::serialize(&encrypted).unwrap());
        if let Some(err) = response.synthetic_error() {
            return Err(BinderError::Other(err.to_string()));
        }
        // read response
        let response: EncryptedBinderResponse = bincode::deserialize_from(response.into_reader())?;
        response
            .decrypt(reply_key)
            .ok_or_else(|| BinderError::Other("decryption failure".into()))?
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
    pub fn new(listen_on: SocketAddr, my_lsk: x25519_dalek::StaticSecret) -> Self {
        let executor = Arc::new(smol::Executor::new());
        let (breq_send, breq_recv) = smol::channel::unbounded();
        executor
            .spawn(httpserver_main_loop(
                executor.clone(),
                listen_on,
                my_lsk,
                breq_send,
            ))
            .detach();
        Self {
            breq_recv,
            executor,
        }
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
) -> Option<()> {
    let listener = smol::net::TcpListener::bind(listen_on).await.unwrap();
    log::debug!("listening on {}", listen_on);
    loop {
        if let Ok((client, _)) = listener.accept().await {
            let my_lsk = my_lsk.clone();
            let breq_send = breq_send.clone();
            let peer_addr = client.peer_addr().unwrap();
            // start a new task
            executor
                .spawn(async move {
                    let my_lsk = my_lsk.clone();
                    drop(
                        async_h1::accept(client, |mut req| {
                            let my_lsk = my_lsk.clone();
                            let breq_send = breq_send.clone();
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
