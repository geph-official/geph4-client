use std::{io, net::SocketAddr};

use smallvec::SmallVec;

use crate::AsyncUdpSocket;

type SVec<T> = SmallVec<[T; 32]>;

pub async fn recv_from_many(
    sock: &AsyncUdpSocket,
    buffers: &mut [&mut [u8]],
) -> io::Result<SVec<(usize, SocketAddr)>> {
    use nix::sys::socket::RecvMmsgData;
    use nix::sys::uio::IoVec;
    use std::os::unix::prelude::*;
    sock.read_with(|sock| {
        // get fd
        let fd: RawFd = sock.as_raw_fd();
        // read into slices
        let response: SVec<(usize, Option<nix::sys::socket::SockAddr>)> = {
            let mut iovs: Vec<[IoVec<&mut [u8]>; 1]> = buffers
                .iter_mut()
                .map(|v| [IoVec::from_mut_slice(v)])
                .collect();
            let mut rmds: Vec<RecvMmsgData<'_, &mut [IoVec<&mut [u8]>]>> = iovs
                .iter_mut()
                .map(|iov| {
                    let iov: &mut [IoVec<&mut [u8]>] = iov;
                    RecvMmsgData {
                        iov,
                        cmsg_buffer: None,
                    }
                })
                .collect();
            // now do the read
            let response = nix::sys::socket::recvmmsg(
                fd,
                &mut rmds,
                nix::sys::socket::MsgFlags::empty(),
                None,
            )
            .map_err(to_ioerror)?;
            response.iter().map(|v| (v.bytes, v.address)).collect()
        };
        log::debug!("recvmmsg {}", response.len());
        Ok(response
            .into_iter()
            .enumerate()
            .filter_map(|(i, rm)| {
                let sockaddr = rm.1?;
                if let nix::sys::socket::SockAddr::Inet(inetaddr) = sockaddr {
                    Some((i, inetaddr.to_std()))
                } else {
                    None
                }
            })
            .collect())
    })
    .await
}

fn to_ioerror(errno: nix::Error) -> std::io::Error {
    if errno == nix::errno::Errno::EWOULDBLOCK || errno == nix::errno::Errno::EAGAIN {
        return std::io::Error::new(std::io::ErrorKind::WouldBlock, errno);
    }

    std::io::Error::new(std::io::ErrorKind::ConnectionAborted, errno)
}
