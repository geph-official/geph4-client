use async_net::AsyncToSocketAddrs;
use pnet::datalink::NetworkInterface;
use socket2::{Domain, Socket, Type};
use std::{convert::TryFrom, net::SocketAddr};

const EXCLUDE_NAME: &str = "tun-geph";

fn default_notun_interface() -> Option<NetworkInterface> {
    let all_interfaces = pnet::datalink::interfaces();
    all_interfaces
        .iter()
        .filter(|interface| {
            interface.is_up()
                && !interface.is_loopback()
                && interface.name != EXCLUDE_NAME
                && !interface.ips.is_empty()
        })
        .cloned()
        .next()
}

/// Returns a vector of socket addresses that don't go through Geph.
pub fn local_socket_addrs() -> Option<Vec<SocketAddr>> {
    let interface = default_notun_interface()?;
    Some(
        interface
            .ips
            .iter()
            .map(|v| {
                let v = v.ip();
                SocketAddr::new(v, 0)
            })
            .collect(),
    )
}

/// Connects to a remote TCP address through a non-Geph external interface.
pub async fn tcp_connect(remote: impl AsyncToSocketAddrs) -> std::io::Result<async_net::TcpStream> {
    // first, we resolve all the remote addresses.
    let remotes = async_net::resolve(remote).await?;
    let local_addrs = local_socket_addrs().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "cannot bind to any local socket address",
        )
    })?;
    let mut final_err = std::io::Error::new(
        std::io::ErrorKind::Other,
        "cannot find any remote addresses",
    );
    // then, we go through all the remote addresses, taking care to bind to the right IP version for the right remote type
    for remote in remotes {
        let local_addrs = local_addrs.clone();
        match smol::unblock(move || tcp_connect_one(remote, &local_addrs)).await {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                eprintln!(
                    "couldn't connect to the specific address {} due to {}",
                    remote, err
                );
                final_err = err
            }
        }
    }
    Err(final_err)
}

fn tcp_connect_one(
    remote: SocketAddr,
    local_addrs: &[SocketAddr],
) -> std::io::Result<async_net::TcpStream> {
    dbg!(remote);
    dbg!(local_addrs);
    let is_ipv6 = match remote {
        SocketAddr::V4(_) => false,
        SocketAddr::V6(_) => true,
    };
    let socket = Socket::new(
        if is_ipv6 {
            Domain::ipv6()
        } else {
            Domain::ipv4()
        },
        Type::stream(),
        None,
    )?;
    let my_addr = *local_addrs
        .iter()
        .find(|v| match v {
            SocketAddr::V4(_) => !is_ipv6,
            SocketAddr::V6(_) => is_ipv6,
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "cannot find matching local socket address",
            )
        })?;
    socket.bind(&my_addr.into())?;
    socket.connect(&remote.into())?;
    let socket = socket.into_tcp_stream();
    Ok(async_net::TcpStream::try_from(socket).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use smol::prelude::*;
    #[test]
    fn it_works() {
        smol::block_on(async move {
            let mut stream = tcp_connect("checkip.amazonaws.com:80").await.unwrap();
            let req = b"GET / HTTP/1.1\r\nHost: checkip.amazonaws.com\r\nConnection: close\r\n\r\n";
            stream.write_all(req).await.unwrap();

            let mut stdout = smol::Unblock::new(std::io::stdout());
            smol::io::copy(stream, &mut stdout).await.unwrap();
        })
    }
}
