use std::{io::Read, pin::Pin, time::Duration};

use concurrent_queue::ConcurrentQueue;
use once_cell::sync::Lazy;
use serde::{de::DeserializeOwned, Serialize};
use smol::{channel::Receiver, prelude::*};

mod dns;
pub use dns::*;

/// Race two different futures, returning the first non-Err, or an Err if both branches error.
pub async fn try_race<T, E, F1, F2>(future1: F1, future2: F2) -> Result<T, E>
where
    F1: Future<Output = Result<T, E>>,
    F2: Future<Output = Result<T, E>>,
{
    let (send_err, recv_err) = smol::channel::bounded(2);
    let success = smol::future::race(
        async {
            match future1.await {
                Ok(v) => v,
                Err(e) => {
                    drop(send_err.try_send(e));
                    smol::future::pending().await
                }
            }
        },
        async {
            match future2.await {
                Ok(v) => v,
                Err(e) => {
                    drop(send_err.try_send(e));
                    smol::future::pending().await
                }
            }
        },
    );
}

/// Reads a bincode-deserializable value with a 16bbe length
pub async fn read_pascalish<T: DeserializeOwned>(
    reader: &mut (impl AsyncRead + Unpin),
) -> anyhow::Result<T> {
    // first read 2 bytes as length
    let mut len_bts = [0u8; 2];
    reader.read_exact(&mut len_bts).await?;
    let len = u16::from_be_bytes(len_bts);
    // then read len
    let mut true_buf = vec![0u8; len as usize];
    reader.read_exact(&mut true_buf).await?;
    // then deserialize
    Ok(bincode::deserialize(&true_buf)?)
}

/// Writes a bincode-serializable value with a 16bbe length
pub async fn write_pascalish<T: Serialize>(
    writer: &mut (impl AsyncWrite + Unpin),
    value: &T,
) -> anyhow::Result<()> {
    let serialized = bincode::serialize(value).unwrap();
    assert!(serialized.len() <= 65535);
    // write bytes
    writer
        .write_all(&(serialized.len() as u16).to_be_bytes())
        .await?;
    writer.write_all(&serialized).await?;
    Ok(())
}

const IDLE_TIMEOUT: Duration = Duration::from_secs(86400);

/// Copies a *TCP socket* to an AsyncWrite, while being as memory-efficient as posib
pub async fn copy_socket_to_with_stats(
    mut reader: smol::Async<std::net::TcpStream>,
    mut writer: impl AsyncWrite + Unpin,
    mut on_write: impl FnMut(usize),
) -> std::io::Result<()> {
    static POOL: Lazy<ConcurrentQueue<Vec<u8>>> = Lazy::new(|| ConcurrentQueue::bounded(1048576));

    let mut timeout = smol::Timer::after(IDLE_TIMEOUT);
    loop {
        let to_write = reader
            .read_with_mut(|sock| {
                let mut buffer = POOL.pop().unwrap_or_else(|_| Vec::with_capacity(16384));
                unsafe { buffer.set_len(16384) }
                let n = sock.read(&mut buffer)?;
                buffer.truncate(n);
                Ok(buffer)
            })
            .or(async {
                (&mut timeout).await;
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "copy_with_stats timeout",
                ))
            })
            .await?;
        if to_write.is_empty() {
            return Ok(());
        }
        timeout.set_after(IDLE_TIMEOUT);
        on_write(to_write.len());
        writer
            .write_all(&to_write)
            .or(async {
                (&mut timeout).await;
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "copy_with_stats timeout",
                ))
            })
            .await?;
        let _ = POOL.push(to_write);
    }
}

/// Copies an AsyncRead to an AsyncWrite, with a callback for every write.
#[inline]
pub async fn copy_with_stats(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    mut on_write: impl FnMut(usize),
) -> std::io::Result<()> {
    let mut buffer = [0u8; 8192];
    let mut timeout = smol::Timer::after(IDLE_TIMEOUT);
    loop {
        // first read into the small buffer
        let n = reader
            .read(&mut buffer)
            .or(async {
                (&mut timeout).await;
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "copy_with_stats timeout",
                ))
            })
            .await?;
        if n == 0 {
            return Ok(());
        }
        on_write(n);
        timeout.set_after(IDLE_TIMEOUT);
        writer
            .write_all(&buffer[..n])
            .or(async {
                (&mut timeout).await;
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "copy_with_stats timeout",
                ))
            })
            .await?;
    }
}

/// Copies an Read to an Write, with a callback for every write.
pub fn copy_with_stats_sync(
    mut reader: impl std::io::Read,
    mut writer: impl std::io::Write,
    mut on_write: impl FnMut(usize),
) -> std::io::Result<()> {
    let mut buffer = [0u8; 32768];
    loop {
        // first read into the small buffer
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            return Ok(());
        }
        on_write(n);
        writer.write_all(&buffer[..n])?;
    }
}

pub trait AsyncRW: AsyncRead + AsyncWrite {}

impl<T: AsyncRead + AsyncWrite> AsyncRW for T {}

pub type ConnLike = async_dup::Arc<async_dup::Mutex<Pin<Box<dyn AsyncRW + 'static + Send>>>>;

pub fn connify<T: AsyncRead + AsyncWrite + 'static + Send>(conn: T) -> ConnLike {
    async_dup::Arc::new(async_dup::Mutex::new(Box::pin(conn)))
}

pub fn to_ioerror<T: Into<Box<dyn std::error::Error + Send + Sync>>>(e: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

/// Reads from an async_channel::Receiver, but returns a vector of all available items instead of just one to save on context-switching.
pub async fn recv_chan_many<T>(ch: Receiver<T>) -> Result<Vec<T>, smol::channel::RecvError> {
    let mut toret = Vec::with_capacity(1);
    toret.push(ch.recv().await?);
    // push as many as possible
    while let Ok(val) = ch.try_recv() {
        toret.push(val);
    }
    Ok(toret)
}
