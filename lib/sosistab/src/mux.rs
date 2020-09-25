use crate::*;
use async_channel::{Receiver, Sender};
use bytes::Bytes;
use std::{sync::Arc, time::Duration};
mod multiplex_actor;
mod relconn;
mod structs;
mod timeheap;
pub use relconn::RelConn;

/// A multiplex session over a sosistab session, implementing both reliable "streams" and unreliable messages.
#[derive(Clone)]
pub struct Multiplex {
    urel_send: Sender<Bytes>,
    urel_recv: Receiver<Bytes>,
    conn_open: Sender<Sender<RelConn>>,
    conn_accept: Receiver<RelConn>,
    sess_ref: Arc<Session>,
}

fn to_ioerror<T: Into<Box<dyn std::error::Error + Send + Sync>>>(val: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionReset, val)
}

impl Multiplex {
    /// Creates a new multiplexed session
    pub fn new(session: Session) -> Self {
        let (urel_send, urel_send_recv) = async_channel::bounded(100);
        let (urel_recv_send, urel_recv) = async_channel::bounded(100);
        let (conn_open, conn_open_recv) = async_channel::bounded(100);
        let (conn_accept_send, conn_accept) = async_channel::bounded(100);
        let session = Arc::new(session);
        let sess_cloned = session.clone();
        runtime::spawn(async move {
            let retval = multiplex_actor::multiplex(
                sess_cloned,
                urel_send_recv,
                urel_recv_send,
                conn_open_recv,
                conn_accept_send,
            )
            .await;
            log::debug!("multiplex actor returned {:?}", retval);
            panic!("{:?}", retval);
        })
        .detach();
        Multiplex {
            urel_send,
            urel_recv,
            conn_open,
            conn_accept,
            sess_ref: session,
        }
    }

    /// Sends an unreliable message to the other side
    pub async fn send_urel(&self, msg: Bytes) -> std::io::Result<()> {
        self.urel_send.send(msg).await.map_err(to_ioerror)
    }

    /// Receive an unreliable message
    pub async fn recv_urel(&self) -> std::io::Result<Bytes> {
        self.urel_recv.recv().await.map_err(to_ioerror)
    }

    /// Gets a reference to the underlying Session
    pub fn get_session(&self) -> &Session {
        &self.sess_ref
    }

    /// Open a reliable conn to the other end.
    pub async fn open_conn(&self) -> std::io::Result<RelConn> {
        loop {
            let (send, recv) = async_channel::unbounded();
            self.conn_open.send(send).await.map_err(to_ioerror)?;
            if let Ok(rc) = recv.recv().await {
                break Ok(rc);
            }
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    }

    /// Accept a reliable conn from the other end.
    pub async fn accept_conn(&self) -> std::io::Result<RelConn> {
        self.conn_accept.recv().await.map_err(to_ioerror)
    }
}
