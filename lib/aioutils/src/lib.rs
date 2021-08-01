use std::{pin::Pin, time::Duration};

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
    // success future, always returns a success.
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
    // fail future. waits for two failures.
    let fail = async {
        if recv_err.recv().await.is_ok() {
            if let Ok(err) = recv_err.recv().await {
                err
            } else {
                smol::future::pending().await
            }
        } else {
            smol::future::pending().await
        }
    };
    // race success and future
    async { Ok(success.await) }
        .or(async { Err(fail.await) })
        .await
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

/// Copies an AsyncRead to an AsyncWrite, with a callback for every write.
#[inline]
pub async fn copy_with_stats(
    reader: impl AsyncRead + Unpin,
    writer: impl AsyncWrite + Unpin,
    mut on_write: impl FnMut(usize),
) -> std::io::Result<()> {
    copy_with_stats_async(reader, writer, move |n| {
        on_write(n);
        async {}
    })
    .await
}

#[inline]
pub async fn copy_with_stats_async<F: Future<Output = ()>>(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    mut on_write: impl FnMut(usize) -> F,
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
        on_write(n).await;
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

// /// Copies an Read to an Write, with a callback for every write.
// pub fn copy_with_stats_sync(
//     mut reader: impl std::io::Read,
//     mut writer: impl std::io::Write,
//     mut on_write: impl FnMut(usize),
// ) -> std::io::Result<()> {
//     let mut buffer = [0u8; 32768];
//     loop {
//         // first read into the small buffer
//         let n = reader.read(&mut buffer)?;
//         if n == 0 {
//             return Ok(());
//         }
//         on_write(n);
//         writer.write_all(&buffer[..n])?;
//     }
// }

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

pub type ConnLike = async_dup::Arc<async_dup::Mutex<Pin<Box<dyn AsyncReadWrite + 'static + Send>>>>;

pub fn connify<T: AsyncRead + AsyncWrite + 'static + Send>(conn: T) -> ConnLike {
    async_dup::Arc::new(async_dup::Mutex::new(Box::pin(conn)))
}

pub fn to_ioerror<T: Into<Box<dyn std::error::Error + Send + Sync>>>(e: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

/// Reads from an async_channel::Receiver, but returns a vector of all available items instead of just one to save on context-switching.
pub async fn recv_chan_many<T>(ch: Receiver<T>) -> Result<Vec<T>, smol::channel::RecvError> {
    let mut toret = vec![ch.recv().await?];
    // push as many as possible
    while let Ok(val) = ch.try_recv() {
        toret.push(val);
    }
    Ok(toret)
}
