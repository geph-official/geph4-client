mod wiretypes;

use std::sync::{atomic::AtomicUsize, atomic::Ordering, Arc};

pub use wiretypes::*;
mod http;
pub use http::*;
use rand::prelude::*;

/// Trait that all binder clients implement.
pub trait BinderClient: Sync + Send {
    /// Send a request to the network with a certain timeout.
    fn request(
        &self,
        request: BinderRequestData,
        timeout: std::time::Duration,
    ) -> BinderResult<BinderResponse>;
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
    fn request_one(
        &self,
        request: BinderRequestData,
        timeout: std::time::Duration,
    ) -> BinderResult<BinderResponse> {
        let curr_idx = self.index.fetch_add(1, Ordering::Relaxed);
        let client = &self.clients[curr_idx % self.clients.len()];
        match client.request(request, timeout) {
            Ok(v) => Ok(v),
            Err(e) => Err(e),
        }
    }

    // does the request on all binders
    fn request_multi(
        &self,
        request: BinderRequestData,
        timeout: std::time::Duration,
    ) -> BinderResult<BinderResponse> {
        let (send_res, recv_res) = smol::channel::unbounded();
        for (idx, client) in self.clients.iter().enumerate() {
            let client = client.clone();
            let request = request.clone();
            let send_res = send_res.clone();
            std::thread::spawn(move || {
                let result = client.request(request, timeout);
                drop(send_res.try_send((idx, result)));
            });
        }
        let (idx, res) =
            smol::future::block_on(recv_res.recv()).expect("result channel shouldn't have closed");
        self.index.store(idx, Ordering::Relaxed);
        res
    }
}

impl BinderClient for MultiBinderClient {
    fn request(
        &self,
        request: BinderRequestData,
        timeout: std::time::Duration,
    ) -> BinderResult<BinderResponse> {
        if request.is_idempotent() {
            self.request_multi(request, timeout)
        } else {
            self.request_one(request, timeout)
        }
    }
}
