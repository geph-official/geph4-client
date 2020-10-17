mod wiretypes;

use std::sync::Mutex;

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
    clients: Vec<Box<dyn BinderClient>>,
    index: Mutex<usize>,
}

impl MultiBinderClient {
    /// Create a MBC that doesn't have any BinderClients.
    pub fn empty() -> Self {
        #[allow(clippy::all)]
        MultiBinderClient {
            clients: Vec::new(),
            index: Mutex::new(0),
        }
    }

    /// Add a new MBC, returning the MBC produced.
    pub fn add_client(mut self, new: impl BinderClient + 'static) -> Self {
        self.clients.push(Box::new(new));
        self.clients.shuffle(&mut rand::thread_rng());
        self
    }
}

impl BinderClient for MultiBinderClient {
    fn request(
        &self,
        request: BinderRequestData,
        timeout: std::time::Duration,
    ) -> BinderResult<BinderResponse> {
        #[allow(clippy::all)]
        let curr_idx = *self.index.lock().unwrap();
        let client = &self.clients[curr_idx % self.clients.len()];
        match client.request(request, timeout) {
            Ok(v) => Ok(v),
            Err(e) => {
                #[allow(clippy::all)]
                let mut noo = self.index.lock().unwrap();
                *noo += 1;
                Err(e)
            }
        }
    }
}
