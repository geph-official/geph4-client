use crate::*;
use bytes::Bytes;
use flume::{Receiver, Sender};
use std::{sync::Arc, time::Duration};
mod multiplex_actor;
mod relconn;
mod structs;
pub use relconn::RelConn;

/// A multiplex session over a sosistab session, implementing both reliable "streams" and unreliable messages.
#[derive(Clone)]
pub struct Multiplex {
    urel_send: Sender<Bytes>,
    urel_recv: Receiver<Bytes>,
    conn_open: Sender<(Option<String>, Sender<RelConn>)>,
    conn_accept: Receiver<RelConn>,
    sess_ref: Arc<Session>,
}

fn to_ioerror<T: Into<Box<dyn std::error::Error + Send + Sync>>>(val: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionReset, val)
}

impl Multiplex {
    /// Creates a new multiplexed session
    pub fn new(session: Session) -> Self {
        let (urel_send, urel_send_recv) = flume::bounded(0);
        let (urel_recv_send, urel_recv) = flume::bounded(0);
        let (conn_open, conn_open_recv) = flume::unbounded();
        let (conn_accept_send, conn_accept) = flume::bounded(100);
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
        self.urel_send.send_async(msg).await.map_err(to_ioerror)
    }

    /// Receive an unreliable message
    pub async fn recv_urel(&self) -> std::io::Result<Bytes> {
        self.urel_recv.recv_async().await.map_err(to_ioerror)
    }

    /// Gets a reference to the underlying Session
    pub fn get_session(&self) -> &Session {
        &self.sess_ref
    }

    /// Open a reliable conn to the other end.
    pub async fn open_conn(&self, additional: Option<String>) -> std::io::Result<RelConn> {
        let (send, recv) = flume::unbounded();
        self.conn_open
            .send_async((additional.clone(), send))
            .await
            .map_err(to_ioerror)?;
        if let Ok(rc) = recv.recv_async().await {
            return Ok(rc);
        }
        Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"))
    }

    /// Accept a reliable conn from the other end.
    pub async fn accept_conn(&self) -> std::io::Result<RelConn> {
        self.conn_accept.recv_async().await.map_err(to_ioerror)
    }
}
