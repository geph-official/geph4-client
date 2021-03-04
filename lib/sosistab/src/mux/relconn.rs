use crate::*;
use async_dup::Arc as DArc;
use async_dup::Mutex as DMutex;
use bipe::{BipeReader, BipeWriter};
use bytes::Bytes;
use connvars::ConnVars;
use mux::structs::{Message, RelKind};

use smol::channel::{Receiver, Sender};
use smol::prelude::*;
use std::{pin::Pin, sync::Arc, task::Context, task::Poll, time::Duration};
mod bipe;
mod connvars;
mod inflight;

pub const MSS: usize = 1100;
const MAX_WAIT_SECS: u64 = 60;

#[derive(Clone)]
pub struct RelConn {
    send_write: DArc<DMutex<BipeWriter>>,
    recv_read: DArc<DMutex<BipeReader>>,
    additional_info: Option<String>,
}

impl RelConn {
    pub(crate) fn new(
        state: RelConnState,
        output: Sender<Message>,
        dropper: impl FnOnce() + Send + 'static,
        additional_info: Option<String>,
    ) -> (Self, RelConnBack) {
        let (send_write, recv_write) = bipe::bipe(1024 * 1024);
        let (send_read, recv_read) = bipe::bipe(10 * 1024 * 1024);
        let (send_wire_read, recv_wire_read) = smol::channel::bounded(64);
        let aic = additional_info.clone();
        let _task = runtime::spawn(async move {
            if let Err(e) = relconn_actor(
                state,
                recv_write,
                send_read,
                recv_wire_read,
                output,
                aic,
                dropper,
            )
            .await
            {
                tracing::debug!("relconn_actor died: {}", e)
            }
        });
        (
            RelConn {
                send_write: DArc::new(DMutex::new(send_write)),
                recv_read: DArc::new(DMutex::new(recv_read)),
                additional_info,
            },
            RelConnBack {
                send_wire_read,
                _task: Arc::new(_task),
            },
        )
    }

    pub fn additional_info(&self) -> Option<&str> {
        self.additional_info.as_deref()
    }

    pub async fn shutdown(&mut self) {
        drop(self.send_write.close().await)
    }
}

impl AsyncRead for RelConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let recv_read = &mut self.recv_read;
        smol::pin!(recv_read);
        recv_read.poll_read(cx, buf)
    }
}

impl AsyncWrite for RelConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let send_write = &mut self.send_write;
        smol::pin!(send_write);
        send_write.poll_write(cx, buf)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let send_write = &mut self.send_write;
        smol::pin!(send_write);
        send_write.poll_close(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let send_write = &mut self.send_write;
        smol::pin!(send_write);
        send_write.poll_flush(cx)
    }
}

pub(crate) enum RelConnState {
    SynReceived {
        stream_id: u16,
    },
    SynSent {
        stream_id: u16,
        tries: usize,
        result: Sender<()>,
    },
    SteadyState {
        stream_id: u16,
        conn_vars: Box<ConnVars>,
    },
    Reset {
        stream_id: u16,
        death: smol::Timer,
    },
}
use RelConnState::*;

// static RELCONN_COUNT: Lazy<AtomicUsize> = Lazy::new(AtomicUsize::default);

async fn relconn_actor(
    mut state: RelConnState,
    mut recv_write: BipeReader,
    mut send_read: BipeWriter,
    recv_wire_read: Receiver<Message>,
    send_wire_write: Sender<Message>,
    additional_info: Option<String>,
    dropper: impl FnOnce(),
) -> anyhow::Result<()> {
    // dbg!(RELCONN_COUNT.fetch_add(1, Ordering::Relaxed));

    let _guard = scopeguard::guard((), |_| {
        // dbg!(RELCONN_COUNT.fetch_sub(1, Ordering::Relaxed));
        dropper()
    });
    let transmit = |msg| {
        let _ = send_wire_write.try_send(msg);
    };
    loop {
        smol::future::yield_now().await;
        state = match state {
            SynReceived { stream_id } => {
                tracing::trace!("C={} SynReceived, sending SYN-ACK", stream_id);
                // send a synack
                transmit(Message::Rel {
                    kind: RelKind::SynAck,
                    stream_id,
                    seqno: 0,
                    payload: Bytes::new(),
                });
                SteadyState {
                    stream_id,
                    conn_vars: Box::new(ConnVars::default()),
                }
            }
            SynSent {
                stream_id,
                tries,
                result,
            } => {
                let wait_interval = 500u64;
                tracing::debug!("C={} SynSent, tried {} times", stream_id, tries);
                if tries > 100 {
                    anyhow::bail!("timeout")
                }
                let synack_evt = async {
                    loop {
                        match recv_wire_read.recv().await? {
                            Message::Rel { .. } => return Ok::<_, anyhow::Error>(true),
                            _ => continue,
                        }
                    }
                };
                let success = synack_evt
                    .or(async {
                        smol::Timer::after(Duration::from_millis(wait_interval as u64)).await;
                        Ok(false)
                    })
                    .await?;
                if success {
                    tracing::trace!("C={} SynSent got SYN-ACK", stream_id);
                    result.send(()).await?;
                    SteadyState {
                        stream_id,
                        conn_vars: Box::new(ConnVars::default()),
                    }
                } else {
                    tracing::trace!("C={} SynSent timed out", stream_id);
                    transmit(Message::Rel {
                        kind: RelKind::Syn,
                        stream_id,
                        seqno: 0,
                        payload: Bytes::copy_from_slice(
                            additional_info
                                .as_ref()
                                .unwrap_or(&"".to_string())
                                .as_bytes(),
                        ),
                    });
                    SynSent {
                        stream_id,
                        tries: tries + 1,
                        result,
                    }
                }
            }
            SteadyState {
                stream_id,
                mut conn_vars,
            } => {
                if let Err(err) = conn_vars
                    .process_one(
                        stream_id,
                        &mut recv_write,
                        &mut send_read,
                        &recv_wire_read,
                        transmit,
                    )
                    .await
                {
                    tracing::warn!("process error {:?}", err);
                    Reset {
                        stream_id,
                        death: smol::Timer::after(Duration::from_secs(MAX_WAIT_SECS)),
                    }
                } else {
                    SteadyState {
                        stream_id,
                        conn_vars,
                    }
                }
            }
            Reset {
                stream_id,
                mut death,
            } => {
                drop(send_read.close().await);
                tracing::trace!("C={} RESET", stream_id);
                transmit(Message::Rel {
                    kind: RelKind::Rst,
                    stream_id,
                    seqno: 0,
                    payload: Bytes::new(),
                });
                let die = smol::future::race(
                    async {
                        (&mut death).await;
                        true
                    },
                    async {
                        if let Ok(Message::Rel { kind, .. }) = recv_wire_read.recv().await {
                            kind == RelKind::Rst
                        } else {
                            smol::future::pending().await
                        }
                    },
                )
                .await;
                if die {
                    anyhow::bail!("exiting from reset")
                }
                Reset { stream_id, death }
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct RelConnBack {
    send_wire_read: Sender<Message>,
    _task: Arc<smol::Task<()>>,
}

impl RelConnBack {
    pub async fn process(&self, input: Message) {
        let res = self.send_wire_read.send(input).await;
        if let Err(e) = res {
            tracing::trace!("relconn failed to accept pkt: {}", e)
        }
    }
}
