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

// fn anything_socket_addr() -> SocketAddr {
//     "0.0.0.0:0".parse::<SocketAddr>().unwrap()
// }

/// A generic rate limiter.
pub(crate) struct RateLimiter {
    inner: governor::RateLimiter<
        NotKeyed,
        governor::state::InMemoryState,
        governor::clock::MonotonicClock,
    >,
    unlimited: bool,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given speed limit, in KB/s
    pub fn new(limit: u32) -> Self {
        let limit = NonZeroU32::new(limit * 1024).unwrap();
        let inner = governor::RateLimiter::new(
            Quota::per_second(limit).allow_burst(NonZeroU32::new(128 * 1024).unwrap()),
            governor::state::InMemoryState::default(),
            &governor::clock::MonotonicClock::default(),
        );
        Self {
            inner,
            unlimited: false,
        }
    }

    /// Creates a new unlimited ratelimit.
    pub fn unlimited() -> Self {
        let inner = governor::RateLimiter::new(
            Quota::per_second(NonZeroU32::new(128 * 1024).unwrap()),
            governor::state::InMemoryState::default(),
            &governor::clock::MonotonicClock::default(),
        );
        Self {
            inner,
            unlimited: true,
        }
    }

    /// Waits until the given number of bytes can be let through.
    pub async fn wait(&self, bytes: usize) {
        if bytes == 0 || self.unlimited {
            return;
        }
        let bytes = NonZeroU32::new(bytes as u32).unwrap();
        while let Err(err) = self.inner.check_n(bytes) {
            match err {
                NegativeMultiDecision::BatchNonConforming(_, until) => {
                    smol::Timer::at(until.earliest_possible()).await;
                }
                NegativeMultiDecision::InsufficientCapacity(_) => {
                    panic!("insufficient capacity in rate limiter")
                }
            }
        }
    }

    /// Checks whether the given number of bytes can be let through.
    pub fn check(&self, bytes: usize) -> bool {
        if bytes == 0 || self.unlimited {
            return true;
        }
        let bytes = NonZeroU32::new(bytes as u32).unwrap();
        self.inner.check_n(bytes).is_ok()
    }
}
