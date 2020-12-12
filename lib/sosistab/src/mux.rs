use crate::*;
use bytes::Bytes;
use smol::channel::{Receiver, Sender};
use std::sync::Arc;
mod multiplex_actor;
mod relconn;
mod structs;
pub use relconn::RelConn;

/// A multiplex session over a sosistab session, implementing both reliable "streams" and unreliable messages.
pub struct Multiplex {
    urel_send: Sender<Bytes>,
    urel_recv: Receiver<Bytes>,
    conn_open: Sender<(Option<String>, Sender<RelConn>)>,
    conn_accept: Receiver<RelConn>,
    sess_ref: Arc<Session>,
    _task: smol::Task<()>,
}

fn to_ioerror<T: Into<Box<dyn std::error::Error + Send + Sync>>>(val: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionReset, val)
}

impl Multiplex {
    /// Creates a new multiplexed session
    pub fn new(session: Session) -> Self {
        let (urel_send, urel_send_recv) = smol::channel::bounded(100);
        let (urel_recv_send, urel_recv) = smol::channel::bounded(1000);
        let (conn_open, conn_open_recv) = smol::channel::unbounded();
        let (conn_accept_send, conn_accept) = smol::channel::bounded(100);
        let session = Arc::new(session);
        let sess_cloned = session.clone();
        let _task = runtime::spawn(async move {
            let retval = multiplex_actor::multiplex(
                sess_cloned,
                urel_send_recv,
                urel_recv_send,
                conn_open_recv,
                conn_accept_send,
            )
            .await;
            tracing::debug!("multiplex actor returned {:?}", retval);
        });
        Multiplex {
            urel_send,
            urel_recv,
            conn_open,
            conn_accept,
            sess_ref: session,
            _task,
        }
    }

    /// Sends an unreliable message to the other side
    #[tracing::instrument(skip(self), level = "trace")]
    pub async fn send_urel(&self, msg: Bytes) -> std::io::Result<()> {
        self.urel_send.send(msg).await.map_err(to_ioerror)
    }

    /// Receive an unreliable message
    #[tracing::instrument(skip(self), level = "trace")]
    pub async fn recv_urel(&self) -> std::io::Result<Bytes> {
        self.urel_recv.recv().await.map_err(to_ioerror)
    }

    /// Gets a reference to the underlying Session
    pub fn get_session(&self) -> &Session {
        &self.sess_ref
    }

    /// Open a reliable conn to the other end.
    pub async fn open_conn(&self, additional: Option<String>) -> std::io::Result<RelConn> {
        let (send, recv) = smol::channel::unbounded();
        self.conn_open
            .send((additional.clone(), send))
            .await
            .map_err(to_ioerror)?;
        if let Ok(s) = recv.recv().await {
            Ok(s)
        } else {
            smol::future::pending().await
        }
    }

    /// Accept a reliable conn from the other end.
    pub async fn accept_conn(&self) -> std::io::Result<RelConn> {
        self.conn_accept.recv().await.map_err(to_ioerror)
    }
}
