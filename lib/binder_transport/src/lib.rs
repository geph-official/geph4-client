mod wiretypes;

pub use wiretypes::*;
mod http;
pub use http::*;

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
