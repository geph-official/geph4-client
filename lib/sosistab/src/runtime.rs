use governor::{state::NotKeyed, NegativeMultiDecision, Quota};
use once_cell::sync::OnceCell;
use smol::prelude::*;
use smol::Async;
use smol::Executor;
use socket2::{Domain, Socket, Type};
use std::{
    convert::TryInto,
    net::{SocketAddr, UdpSocket},
    num::NonZeroU32,
};

static USER_EXEC: OnceCell<&'static Executor> = OnceCell::new();

// /// Sets the sosistab executor. If not set, smolscale will be used.
// pub(crate) fn set_smol_executor(exec: &'static Executor<'static>) {
//     USER_EXEC.set(exec).expect("already initialized")
// }

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

/// Create a new UDP socket that has a largeish buffer and isn't bound to anything.
pub(crate) fn new_udp_socket_bind(addr: SocketAddr) -> std::io::Result<Async<UdpSocket>> {
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
    Ok(socket.into_udp_socket().try_into().unwrap())
}
