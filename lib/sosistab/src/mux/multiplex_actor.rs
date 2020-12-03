use crate::*;
use bytes::Bytes;
use dashmap::DashMap;
use mux::relconn::{RelConn, RelConnBack, RelConnState};
use mux::structs::*;
use rand::prelude::*;
use smol::channel::{Receiver, Sender};
use smol::prelude::*;
use std::sync::Arc;

pub async fn multiplex(
    session: Arc<Session>,
    urel_send_recv: Receiver<Bytes>,
    urel_recv_send: Sender<Bytes>,
    conn_open_recv: Receiver<(Option<String>, Sender<RelConn>)>,
    conn_accept_send: Sender<RelConn>,
) -> anyhow::Result<()> {
    let conn_tab = Arc::new(ConnTable::default());
    let (glob_send, glob_recv) = smol::channel::bounded(1000);
    let (dead_send, dead_recv) = smol::channel::unbounded();
    loop {
        // fires on receiving messages
        let recv_evt = async {
            let msg = session
                .recv_bytes()
                .await
                .ok_or_else(|| anyhow::anyhow!("underlying session is dead"))?;
            let msg = bincode::deserialize::<Message>(&msg);
            if let Ok(msg) = msg {
                match msg {
                    // unreliable
                    Message::Urel(bts) => {
                        log::trace!("urel recv {}B", bts.len());
                        drop(urel_recv_send.try_send(bts));
                    }
                    // connection opening
                    Message::Rel {
                        kind: RelKind::Syn,
                        stream_id,
                        payload,
                        ..
                    } => {
                        if conn_tab.get_stream(stream_id).is_some() {
                            log::trace!("syn recv {} REACCEPT", stream_id);
                            session
                                .send_bytes(
                                    bincode::serialize(&Message::Rel {
                                        kind: RelKind::SynAck,
                                        stream_id,
                                        seqno: 0,
                                        payload: Bytes::new(),
                                    })
                                    .unwrap()
                                    .into(),
                                )
                                .await;
                        } else {
                            let dead_send = dead_send.clone();
                            log::trace!("syn recv {} ACCEPT", stream_id);
                            let lala = String::from_utf8_lossy(&payload).to_string();
                            let additional_info = if &lala == "" { None } else { Some(lala) };
                            let (new_conn, new_conn_back) = RelConn::new(
                                RelConnState::SynReceived { stream_id },
                                glob_send.clone(),
                                move || {
                                    let _ = dead_send.try_send(stream_id);
                                },
                                additional_info,
                            );
                            // the RelConn itself is responsible for sending the SynAck. Here we just store the connection into the table, accept it, and be done with it.
                            conn_tab.set_stream(stream_id, new_conn_back);
                            drop(conn_accept_send.send(new_conn).await);
                        }
                    }
                    // associated with existing connection
                    Message::Rel {
                        stream_id, kind, ..
                    } => {
                        if let Some(handle) = conn_tab.get_stream(stream_id) {
                            log::trace!("handing over {:?} to {}", kind, stream_id);
                            handle.process(msg)
                        } else {
                            log::trace!("discarding {:?} to nonexistent {}", kind, stream_id);
                            if kind != RelKind::Rst {
                                session
                                    .send_bytes(
                                        bincode::serialize(&Message::Rel {
                                            kind: RelKind::Rst,
                                            stream_id,
                                            seqno: 0,
                                            payload: Bytes::new(),
                                        })
                                        .unwrap()
                                        .into(),
                                    )
                                    .await;
                            }
                        }
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        };
        // fires on sending messages
        let send_evt = async {
            let to_send = glob_recv.recv().await?;
            session
                .send_bytes(bincode::serialize(&to_send).unwrap().into())
                .await;
            Ok::<(), anyhow::Error>(())
        };
        // fires on a new unreliable sending request
        let urel_send_evt = async {
            let to_send = urel_send_recv.recv().await?;
            log::trace!("urel send {}B", to_send.len());
            glob_send.send(Message::Urel(to_send)).await?;
            Ok::<(), anyhow::Error>(())
        };
        // fires on a new stream open request
        let conn_open_evt = async {
            let (additional_data, result_chan) = conn_open_recv.recv().await?;
            let conn_tab = conn_tab.clone();
            let glob_send = glob_send.clone();
            let dead_send = dead_send.clone();
            runtime::spawn(async move {
                let stream_id = {
                    let stream_id = conn_tab.find_id();
                    if let Some(stream_id) = stream_id {
                        let (send_sig, recv_sig) = smol::channel::bounded(1);
                        let (conn, conn_back) = RelConn::new(
                            RelConnState::SynSent {
                                stream_id,
                                tries: 0,
                                result: send_sig,
                            },
                            glob_send.clone(),
                            move || {
                                let _ = dead_send.try_send(stream_id);
                            },
                            additional_data.clone(),
                        );
                        runtime::spawn(async move {
                            recv_sig.recv().await.ok()?;
                            result_chan.send(conn).await.ok()?;
                            Some(())
                        })
                        .detach();
                        conn_tab.set_stream(stream_id, conn_back);
                        stream_id
                    } else {
                        return;
                    }
                };
                log::trace!("conn open send {}", stream_id);
                drop(
                    glob_send
                        .send(Message::Rel {
                            kind: RelKind::Syn,
                            stream_id,
                            seqno: 0,
                            payload: Bytes::copy_from_slice(
                                additional_data.clone().unwrap_or_default().as_bytes(),
                            ),
                        })
                        .await,
                );
            })
            .detach();
            Ok::<(), anyhow::Error>(())
        };
        // dead stuff
        let dead_evt = async {
            let lala = dead_recv.recv().await?;
            log::debug!("removing stream {} from table", lala);
            conn_tab.del_stream(lala);
            Ok(())
        };
        // await on them all
        recv_evt
            .or(urel_send_evt.or(send_evt.or(conn_open_evt.or(dead_evt))))
            .await?;
    }
}

#[derive(Default)]
struct ConnTable {
    /// Maps IDs to RelConn back handles.
    sid_to_stream: DashMap<u16, RelConnBack>,
}

impl ConnTable {
    fn get_stream(&self, sid: u16) -> Option<RelConnBack> {
        let x = self.sid_to_stream.get(&sid)?;
        Some(x.clone())
    }

    fn set_stream(&self, id: u16, handle: RelConnBack) {
        self.sid_to_stream.insert(id, handle);
    }

    fn del_stream(&self, id: u16) {
        self.sid_to_stream.remove(&id);
    }

    fn find_id(&self) -> Option<u16> {
        if self.sid_to_stream.len() >= 65535 {
            log::warn!("ran out of descriptors ({})", self.sid_to_stream.len());
            return None;
        }
        loop {
            let possible_id: u16 = rand::thread_rng().gen();
            if self.sid_to_stream.get(&possible_id).is_none() {
                log::debug!(
                    "found id {} out of {}",
                    possible_id,
                    self.sid_to_stream.len()
                );
                break Some(possible_id);
            }
        }
    }
}
