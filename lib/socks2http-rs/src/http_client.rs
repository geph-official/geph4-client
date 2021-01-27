use crate::socks5;
use futures::{future::BoxFuture, FutureExt};
use hyper::Uri;
use pin_project::pin_project;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{self, Poll};
use tokio::net::TcpStream;
#[derive(Clone)]
pub struct SocksConnector {
    proxy: SocketAddr,
}
impl SocksConnector {
    pub fn new(addr: SocketAddr) -> SocksConnector {
        SocksConnector { proxy: addr }
    }
}
impl hyper::service::Service<Uri> for SocksConnector {
    type Error = std::io::Error;
    type Future = SocksConnecting;
    type Response = TcpStream;
    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, dst: Uri) -> Self::Future {
        let proxy = self.proxy;
        SocksConnecting {
            fut: async move {
                match crate::address::host_addr(&dst) {
                    None => {
                        use std::io::{Error, ErrorKind};
                        let err = Error::new(ErrorKind::Other, "URI must be a valid Address");
                        Err(err)
                    }
                    Some(addr) => socks5::connect(&addr, &proxy).await,
                }
            }
            .boxed(),
        }
    }
}
#[pin_project]
pub struct SocksConnecting {
    #[pin]
    fut: BoxFuture<'static, std::io::Result<TcpStream>>,
}

impl Future for SocksConnecting {
    type Output = std::io::Result<TcpStream>;
    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.project().fut.poll(cx)
    }
}
pub type SocksClient = hyper::Client<SocksConnector, hyper::Body>;
