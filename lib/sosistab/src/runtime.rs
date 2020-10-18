use once_cell::sync::{Lazy, OnceCell};
use smol::net::AsyncToSocketAddrs;
use smol::prelude::*;
use smol::Executor;
use socket2::{Domain, Socket, Type};
use std::sync::Arc;
use std::thread;
use std::{convert::TryInto, net::SocketAddr};

static FALLBACK: Lazy<Arc<Executor<'static>>> = Lazy::new(|| {
    let ex = Arc::new(Executor::new());
    for i in 1..=num_cpus::get() {
        let builder = thread::Builder::new().name(format!("sosistab-fallback-{}", i));
        {
            let ex = ex.clone();
            builder
                .spawn(move || {
                    smol::future::block_on(ex.run(smol::future::pending::<()>()));
                })
                .unwrap();
        }
    }
    ex
});

static USER_EXEC: OnceCell<&'static Executor> = OnceCell::new();

/// Sets the sosistab executor. If not set, a backup threadpool will be used.
pub fn set_smol_executor(exec: &'static Executor<'static>) {
    USER_EXEC.set(exec).expect("already initialized")
}

/// Spawns a future onto the sosistab worker.
pub(crate) fn spawn<T: Send + 'static>(
    future: impl Future<Output = T> + Send + 'static,
) -> smol::Task<T> {
    if let Some(ex) = USER_EXEC.get() {
        ex.spawn(future)
    } else {
        FALLBACK.spawn(future)
    }
}

/// Create a new UDP socket that has a largeish buffer and isn't bound to anything.
pub(crate) async fn new_udp_socket_bind(
    addr: impl AsyncToSocketAddrs,
) -> std::io::Result<smol::net::UdpSocket> {
    let addr = smol::net::resolve(addr).await?[0];
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
    Ok(socket.into_udp_socket().try_into().unwrap())
}

// fn anything_socket_addr() -> SocketAddr {
//     "0.0.0.0:0".parse::<SocketAddr>().unwrap()
// }
