mod wiretypes;
use derivative::Derivative;
pub use wiretypes::*;
mod http;
pub use http::*;

/// Trait that all binder clients implement.
pub trait BinderClient {
    /// Send a request to the network with a certain timeout.
    fn request(
        &self,
        request: BinderRequestData,
        timeout: std::time::Duration,
    ) -> BinderResult<BinderResponse>;
}

/// Trait that all binder transport servers implement.
pub trait BinderServer {
    /// Receive a request from the network.
    fn next_request(&self) -> std::io::Result<BinderRequest>;
}

/// A binder request
#[derive(Derivative)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn http_test() {
        drop(env_logger::try_init());
        let server_lsk = x25519_dalek::StaticSecret::new(rand::thread_rng());
        let hserv = HttpServer::new("127.0.0.1:8888".parse().unwrap(), server_lsk.clone());
        // spawn a thread to listen on the hserv
        std::thread::spawn(move || loop {
            let serv = hserv.next_request();
            if let Ok(serv) = serv {
                serv.respond(Ok(BinderResponse::DummyResp));
            } else {
                break;
            }
        });
        // send stuff
        let hclient = HttpClient::new((&server_lsk).into(), "http://127.0.0.1:8888", &[]);
        assert_eq!(
            hclient
                .request(BinderRequestData::Dummy, Duration::from_secs(1))
                .unwrap(),
            BinderResponse::DummyResp
        );
    }
}
