mod wiretypes;

use std::{
    sync::{atomic::AtomicUsize, atomic::Ordering, Arc},
    time::Duration,
};

use smol_timeout::TimeoutExt;
pub use wiretypes::*;
mod http;
pub use http::*;
use rand::prelude::*;

/// Trait that all binder clients implement.
#[async_trait::async_trait]
pub trait BinderClient: Sync + Send {
    /// Send a request to the network with a certain timeout.
    async fn request(&self, request: BinderRequestData) -> BinderResult<BinderResponse>;
}

/// Trait that all binder transport servers implement.
pub trait BinderServer: Send + Sync {
    /// Receive a request from the network.
    fn next_request(&self) -> std::io::Result<BinderRequest>;
}

/// A binder request
#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub struct BinderRequest {
    pub request_data: BinderRequestData,
    #[derivative(Debug = "ignore")]
    response_send: Box<dyn FnOnce(BinderResult<BinderResponse>) + Send + Sync>,
}

impl BinderRequest {
    /// Respond to the request.
    pub fn respond(self, response: BinderResult<BinderResponse>) {
        (self.response_send)(response)
    }
}

/// A BinderClient implementation wrapping multiple BinderClients.
pub struct MultiBinderClient {
    clients: Vec<Arc<dyn BinderClient>>,
    index: AtomicUsize,
}

impl MultiBinderClient {
    /// Create a MBC that doesn't have any BinderClients.
    pub fn empty() -> Self {
        MultiBinderClient {
            clients: Vec::new(),
            index: AtomicUsize::new(0),
        }
    }

    /// Add a new MBC, returning the MBC produced.
    pub fn add_client(mut self, new: impl BinderClient + 'static) -> Self {
        self.clients.push(Arc::new(new));
        self.clients.shuffle(&mut rand::thread_rng());
        self
    }
}

impl MultiBinderClient {
    // does the request on ONE binder
    async fn request_one(&self, request: BinderRequestData) -> BinderResult<BinderResponse> {
        let mut timeout = Duration::from_secs(3);
        loop {
            let curr_idx = self.index.fetch_add(1, Ordering::Relaxed);
            let client = &self.clients[curr_idx % self.clients.len()];
            log::trace!("request_one started");
            let res = client.request(request.clone()).timeout(timeout).await;
            if let Some(Ok(res)) = res {
                log::trace!("request_one succeeded");
                self.index.fetch_sub(1, Ordering::Relaxed);
                return Ok(res);
            } else if let Some(Err(BinderError::Other(other))) = res {
                log::warn!("MultiBinderClient switching backend due to error {}", other);
            } else if let Some(e) = res {
                return e;
            } else {
                log::warn!(
                    "MultiBinderClient switching backend due to timeout {:?}",
                    timeout
                );
                timeout += Duration::from_secs(1);
            }
        }
    }

    // does the request on all binders
    async fn request_multi(&self, request: BinderRequestData) -> BinderResult<BinderResponse> {
        let (send_res, recv_res) = smol::channel::unbounded();
        let mut _tasks = vec![];
        for (idx, client) in self.clients.iter().enumerate() {
            let client = client.clone();
            let request = request.clone();
            let send_res = send_res.clone();
            _tasks.push(smolscale::spawn(async move {
                let _ = send_res.send((idx, client.request(request).await)).await;
            }));
        }
        drop(send_res);

        let mut final_res = None;
        for _ in 0.._tasks.len() {
            let (idx, res) = recv_res
                .recv()
                .await
                .expect("result channel shouldn't have closed");
            self.index.store(idx, Ordering::Relaxed);
            final_res = Some(res);
            if final_res.as_ref().unwrap().is_ok() {
                break;
            } else {
                log::warn!("request_multi failed: {:?}", final_res);
            }
        }
        final_res.unwrap()
    }
}

#[async_trait::async_trait]
impl BinderClient for MultiBinderClient {
    async fn request(&self, request: BinderRequestData) -> BinderResult<BinderResponse> {
        if request.is_idempotent() {
            self.request_multi(request).await
        } else {
            self.request_one(request).await
        }
    }
}
