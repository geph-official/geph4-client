use once_cell::sync::OnceCell;
use smol::prelude::*;
use smol::Executor;
use smol::{net::AsyncToSocketAddrs, Async};
use socket2::{Domain, Socket, Type};
use std::{
    convert::TryInto,
    net::{SocketAddr, UdpSocket},
};

static USER_EXEC: OnceCell<&'static Executor> = OnceCell::new();

/// Sets the sosistab executor. If not set, smolscale will be used.
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
        smolscale::spawn(future)
    }
}

/// Spawns a future onto the local sosistab worker.
pub(crate) fn spawn_local<T: Send + 'static>(
    future: impl Future<Output = T> + Send + 'static,
) -> smol::Task<T> {
    if let Some(ex) = USER_EXEC.get() {
        ex.spawn(future)
    } else {
        // TODO actually do something
        smolscale::spawn(future)
    }
}

/// Create a new UDP socket that has a largeish buffer and isn't bound to anything.
pub(crate) async fn new_udp_socket_bind(
    addr: impl AsyncToSocketAddrs,
) -> std::io::Result<Async<UdpSocket>> {
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
    socket.set_recv_buffer_size(1024 * 1024).unwrap();
    socket.set_send_buffer_size(1024 * 1024).unwrap();
    socket.bind(&addr.into())?;
    Ok(socket.into_udp_socket().try_into().unwrap())
}

// fn anything_socket_addr() -> SocketAddr {
//     "0.0.0.0:0".parse::<SocketAddr>().unwrap()
// }
