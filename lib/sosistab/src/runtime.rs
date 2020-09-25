use async_net::AsyncToSocketAddrs;
use lazy_static::lazy_static;
use smol::prelude::*;
use smol::Async;
use smol::Executor;
use socket2::{Domain, Socket, Type};
use std::net::SocketAddr;
use std::thread;
use std::{net::UdpSocket, sync::Arc};

lazy_static! {
    static ref EXECUTOR: Arc<Executor<'static>> = {
        let ex = Arc::new(Executor::new());
        for i in 1..=num_cpus::get() {
            let builder = thread::Builder::new().name(format!("sosistab-{}", i));
            {
                let ex = ex.clone();
                builder
                    .spawn(move || {
                        smol::block_on(ex.run(smol::future::pending::<()>()));
                    })
                    .unwrap();
            }
        }
        ex
    };
}

/// Spawns a future onto the sosistab worker.
pub fn spawn<T: Send + 'static>(future: impl Future<Output = T> + Send + 'static) -> smol::Task<T> {
    async_global_executor::spawn(future)
}

/// Create a new UDP socket that has a largeish buffer and isn't bound to anything.
pub async fn new_udp_socket_bind(
    addr: impl AsyncToSocketAddrs,
) -> std::io::Result<async_dup::Arc<Async<UdpSocket>>> {
    let addr = async_net::resolve(addr).await?[0];
    let socket = Socket::new(
        match addr {
            SocketAddr::V4(_) => Domain::ipv4(),
            SocketAddr::V6(_) => Domain::ipv6(),
        },
        Type::dgram(),
        None,
    )
    .unwrap();
    drop(socket.set_only_v6(false));
    socket.bind(&addr.into())?;
    socket.set_recv_buffer_size(1000 * 1024).unwrap();
    socket.set_send_buffer_size(1000 * 1024).unwrap();
    Ok(async_dup::Arc::new(
        Async::new(socket.into_udp_socket()).unwrap(),
    ))
}

/// Create a new UDP socket bound to some address.
pub async fn new_udp_socket() -> std::io::Result<async_dup::Arc<Async<UdpSocket>>> {
    new_udp_socket_bind(anything_socket_addr()).await
}

fn anything_socket_addr() -> SocketAddr {
    "0.0.0.0:0".parse::<SocketAddr>().unwrap()
}
