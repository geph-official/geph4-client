use crate::*;
use async_dup::Arc as DArc;
use async_dup::Mutex as DMutex;
use bipe::{BipeReader, BipeWriter};
use bytes::{Bytes, BytesMut};
use flume::{Receiver, Sender};
use mux::structs::{Message, RelKind, Reorderer, Seqno, VarRateLimit};
use smol::prelude::*;
use std::{
    collections::BTreeSet,
    collections::VecDeque,
    pin::Pin,
    sync::atomic::AtomicU32,
    sync::atomic::Ordering,
    sync::Arc,
    task::Context,
    task::Poll,
    time::{Duration, Instant},
};
mod bipe;
mod inflight;

const MSS: usize = 1100;
const MAX_WAIT_SECS: u64 = 60;

#[derive(Clone)]
pub struct RelConn {
    send_write: DArc<DMutex<BipeWriter>>,
    recv_read: DArc<DMutex<BipeReader>>,
}

impl RelConn {
    pub(crate) fn new(
        state: RelConnState,
        output: Sender<Message>,
        dropper: impl FnOnce() + Send + 'static,
    ) -> (Self, RelConnBack) {
        let (send_write, recv_write) = bipe::bipe(65536);
        let (send_read, recv_read) = bipe::bipe(1024 * 1024);
        let (send_wire_read, recv_wire_read) = flume::unbounded();
        runtime::spawn(relconn_actor(
            state,
            recv_write,
            send_read,
            recv_wire_read,
            output,
            dropper,
        ))
        .detach();
        (
            RelConn {
                send_write: DArc::new(DMutex::new(send_write)),
                recv_read: DArc::new(DMutex::new(recv_read)),
            },
            RelConnBack { send_wire_read },
        )
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
use inflight::Inflight;
use RelConnState::*;

async fn relconn_actor(
    mut state: RelConnState,
    mut recv_write: BipeReader,
    mut send_read: BipeWriter,
    recv_wire_read: Receiver<Message>,
    send_wire_write: Sender<Message>,
    dropper: impl FnOnce(),
) -> anyhow::Result<()> {
    let _guard = scopeguard::guard((), |_| dropper());
    // match on our current state repeatedly
    #[derive(Debug, Clone)]
    enum Evt {
        Rto((Seqno, bool)),
        AckTimer,
        NewWrite(Bytes),
        NewPkt(Message),
        Closing,
    }
    let (send_buf, recv_buf) = flume::bounded(10000);
    let transmit = |msg| async {
        drop(send_buf.send_async(msg).await);
        smol::future::yield_now().await;
    };
    let mut fragments: VecDeque<Bytes> = VecDeque::new();
    let limiter = Arc::new(VarRateLimit::new());
    let implied_rate = Arc::new(AtomicU32::new(100));
    let irr = implied_rate.clone();
    let lim = limiter.clone();
    let _task: smol::Task<Option<()>> = runtime::spawn(async move {
        loop {
            let msg = recv_buf.recv_async().await.ok()?;
            lim.wait(irr.load(Ordering::Relaxed)).await;
            send_wire_write.send_async(msg).await.ok()?;
        }
    });
    loop {
        state = match state {
            SynReceived { stream_id } => {
                log::trace!("C={} SynReceived, sending SYN-ACK", stream_id);
                // send a synack
                transmit(Message::Rel {
                    kind: RelKind::SynAck,
                    stream_id,
                    seqno: 0,
                    payload: Bytes::new(),
                })
                .await;
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
                let wait_interval = 2u64.saturating_pow(tries as u32);
                log::trace!("C={} SynSent, tried {} times", stream_id, tries);
                if wait_interval > MAX_WAIT_SECS {
                    anyhow::bail!("timeout in SynSent");
                }
                let synack_evt = async {
                    loop {
                        match recv_wire_read.recv_async().await? {
                            Message::Rel { .. } => return Ok::<_, anyhow::Error>(true),
                            _ => continue,
                        }
                    }
                };
                let success = synack_evt
                    .or(async {
                        smol::Timer::after(Duration::from_secs(wait_interval as u64)).await;
                        Ok(false)
                    })
                    .await?;
                if success {
                    log::trace!("C={} SynSent got SYN-ACK", stream_id);
                    SteadyState {
                        stream_id,
                        conn_vars: Box::new(ConnVars::default()),
                    }
                } else {
                    log::trace!("C={} SynSent timed out", stream_id);
                    transmit(Message::Rel {
                        kind: RelKind::Syn,
                        stream_id,
                        seqno: 0,
                        payload: Bytes::new(),
                    })
                    .await;
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
                let event = {
                    implied_rate.store(
                        (conn_vars.cwnd / conn_vars.inflight.min_rtt().as_secs_f64()) as u32,
                        Ordering::Relaxed,
                    );
                    let writeable = conn_vars.inflight.inflight() <= conn_vars.cwnd as usize
                        && conn_vars.inflight.len() < 10000
                        && !conn_vars.closing;
                    let force_ack = conn_vars.ack_seqnos.len() >= 128;

                    let ack_timer = conn_vars.delayed_ack_timer;
                    let ack_timer = async {
                        if force_ack {
                            return Ok(Evt::AckTimer);
                        }
                        if let Some(time) = ack_timer {
                            smol::Timer::at(time).await;
                            Ok::<Evt, anyhow::Error>(Evt::AckTimer)
                        } else {
                            smol::future::pending().await
                        }
                    };
                    let rto_timer = conn_vars.inflight.wait_first();
                    let rto_timeout = async { Ok::<Evt, anyhow::Error>(Evt::Rto(rto_timer.await)) };
                    let new_write = async {
                        if writeable {
                            if fragments.is_empty() {
                                let to_write = {
                                    let mut bts = BytesMut::with_capacity(MSS);
                                    bts.extend_from_slice(&[0; MSS]);
                                    let n = recv_write.read(&mut bts).await;
                                    if let Ok(n) = n {
                                        let bts = bts.freeze();
                                        Some(bts.slice(0..n))
                                    } else {
                                        None
                                    }
                                };
                                if let Some(to_write) = to_write {
                                    fragments.push_back(to_write);
                                    Ok(Evt::NewWrite(fragments.pop_front().unwrap()))
                                } else {
                                    Ok(Evt::Closing)
                                }
                            } else {
                                Ok::<Evt, anyhow::Error>(Evt::NewWrite(
                                    fragments.pop_front().unwrap(),
                                ))
                            }
                        } else {
                            Ok(smol::future::pending().await)
                        }
                    };
                    let new_pkt = async {
                        Ok::<Evt, anyhow::Error>(Evt::NewPkt(recv_wire_read.recv_async().await?))
                    };
                    ack_timer.or(rto_timeout.or(new_write.or(new_pkt))).await
                };
                match event {
                    Ok(Evt::Closing) => {
                        conn_vars.closing = true;
                        if conn_vars.inflight.len() > 0 {
                            SteadyState {
                                stream_id,
                                conn_vars,
                            }
                        } else {
                            Reset {
                                stream_id,
                                death: smol::Timer::after(Duration::from_secs(MAX_WAIT_SECS)),
                            }
                        }
                    }
                    Ok(Evt::Rto((seqno, _is_timeout))) => {
                        // retransmit packet
                        // assert!(!conn_vars.inflight.len() == 0);
                        if conn_vars.inflight.len() > 0 {
                            if let Some(v) = conn_vars.inflight.get_seqno(seqno) {
                                let payload = v.payload.clone();
                                let retrans = v.retrans;
                                // eprintln!(
                                //     "retrans {} {} for the {} time",
                                //     seqno, is_timeout, v.retrans
                                // );
                                if retrans == 1 {
                                    // if is_timeout {
                                    //     conn_vars.congestion_rto()
                                    // } else {
                                    conn_vars.congestion_loss();
                                    // }
                                }
                                if retrans > 8 {
                                    anyhow::bail!("full timeout")
                                }
                                conn_vars.retrans_count += 1;
                                // eprintln!(
                                //     "{}/{} retrans",
                                //     conn_vars.retrans_count, conn_vars.next_free_seqno
                                // );
                                transmit(payload).await;
                            }
                        }
                        // new state
                        SteadyState {
                            stream_id,
                            conn_vars,
                        }
                    }
                    Ok(Evt::NewPkt(Message::Rel {
                        kind: RelKind::Rst,
                        stream_id,
                        ..
                    })) => Reset {
                        stream_id,
                        death: smol::Timer::after(Duration::from_secs(MAX_WAIT_SECS)),
                    },
                    Ok(Evt::NewPkt(Message::Rel {
                        kind: RelKind::DataAck,
                        payload,
                        seqno,
                        ..
                    })) => {
                        log::trace!("new ACK pkt with {} seqnos", payload.len() / 2);
                        for seqno in
                            bincode::deserialize::<BTreeSet<Seqno>>(&payload).unwrap_or_default()
                        {
                            if conn_vars.inflight.mark_acked(seqno) {
                                conn_vars.congestion_ack();
                            }
                        }
                        conn_vars.inflight.mark_acked_lt(seqno);
                        if conn_vars.inflight.len() == 0 && conn_vars.closing {
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
                    Ok(Evt::NewPkt(Message::Rel {
                        kind: RelKind::Data,
                        seqno,
                        payload,
                        stream_id,
                    })) => {
                        log::trace!("new data pkt with seqno={}", seqno);
                        conn_vars.ack_seqnos.insert(seqno);
                        if conn_vars.delayed_ack_timer.is_none() {
                            conn_vars.delayed_ack_timer =
                                Instant::now().checked_add(Duration::from_millis(10));
                        }
                        conn_vars.reorderer.insert(seqno, payload);
                        let times = conn_vars.reorderer.take();
                        conn_vars.lowest_unseen += times.len() as u64;
                        let mut success = true;
                        for pkt in times {
                            success |= send_read.write(&pkt).await.is_ok();
                        }
                        if success {
                            SteadyState {
                                stream_id,
                                conn_vars,
                            }
                        } else {
                            Reset {
                                stream_id,
                                death: smol::Timer::after(Duration::from_secs(MAX_WAIT_SECS)),
                            }
                        }
                    }
                    Ok(Evt::NewWrite(bts)) => {
                        assert!(bts.len() <= MSS);
                        let seqno = conn_vars.next_free_seqno;
                        conn_vars.next_free_seqno += 1;
                        let msg = Message::Rel {
                            kind: RelKind::Data,
                            stream_id,
                            seqno,
                            payload: bts,
                        };
                        // put msg into inflight
                        conn_vars.inflight.insert(seqno, msg.clone());

                        transmit(msg).await;

                        SteadyState {
                            stream_id,
                            conn_vars,
                        }
                    }
                    Ok(Evt::AckTimer) => {
                        // eprintln!("acking {} seqnos", conn_vars.ack_seqnos.len());
                        let encoded_acks = bincode::serialize(&conn_vars.ack_seqnos).unwrap();
                        transmit(Message::Rel {
                            kind: RelKind::DataAck,
                            stream_id,
                            seqno: conn_vars.lowest_unseen,
                            payload: Bytes::copy_from_slice(&encoded_acks),
                        })
                        .await;
                        conn_vars.ack_seqnos.clear();
                        conn_vars.delayed_ack_timer = None;
                        SteadyState {
                            stream_id,
                            conn_vars,
                        }
                    }
                    err => {
                        log::trace!("forced to RESET due to {:?}", err);
                        Reset {
                            stream_id,
                            death: smol::Timer::after(Duration::from_secs(MAX_WAIT_SECS)),
                        }
                    }
                }
            }
            Reset {
                stream_id,
                mut death,
            } => {
                drop(send_read.close().await);
                log::trace!("C={} RESET", stream_id);
                transmit(Message::Rel {
                    kind: RelKind::Rst,
                    stream_id,
                    seqno: 0,
                    payload: Bytes::new(),
                })
                .await;
                let die = smol::future::race(
                    async {
                        (&mut death).await;
                        true
                    },
                    async {
                        if let Ok(Message::Rel { kind, .. }) = recv_wire_read.recv_async().await {
                            kind == RelKind::Rst
                        } else {
                            smol::future::pending().await
                        }
                    },
                )
                .await;
                if die {
                    anyhow::bail!("60 seconds in reset up")
                }
                Reset { stream_id, death }
            }
        }
    }
}

pub(crate) struct RelConnBack {
    send_wire_read: Sender<Message>,
}

impl RelConnBack {
    pub async fn process(&self, input: Message) {
        drop(self.send_wire_read.send_async(input).await)
    }
}

pub(crate) struct ConnVars {
    inflight: Inflight,
    next_free_seqno: Seqno,
    retrans_count: u64,

    delayed_ack_timer: Option<Instant>,
    ack_seqnos: BTreeSet<Seqno>,

    reorderer: Reorderer<Bytes>,
    lowest_unseen: Seqno,
    // read_buffer: VecDeque<Bytes>,
    slow_start: bool,
    ssthresh: f64,
    cwnd: f64,
    last_loss: Instant,

    cwnd_max: f64,
    cubic_secs: f64,
    last_cubic: Instant,

    closing: bool,
}

impl Default for ConnVars {
    fn default() -> Self {
        ConnVars {
            inflight: Inflight::default(),
            next_free_seqno: 0,
            retrans_count: 0,

            delayed_ack_timer: None,
            ack_seqnos: BTreeSet::new(),

            reorderer: Reorderer::default(),
            lowest_unseen: 0,

            slow_start: true,
            ssthresh: 10000.0,
            cwnd: 16.0,
            last_loss: Instant::now(),
            cwnd_max: 100.0,
            cubic_secs: 0.0,
            last_cubic: Instant::now(),

            closing: false,
        }
    }
}

impl ConnVars {
    fn congestion_ack(&mut self) {
        if self.slow_start {
            self.cwnd += 1.0;
            if self.cwnd > self.ssthresh {
                self.slow_start = false;
                // self.cwnd_max = self.cwnd / 0.8;
                // let now = Instant::now();
                // self.last_loss = now;
                // self.cubic_secs = 0.0;
                // self.cubic_update(now);
            }
        } else {
            let n = (0.23 * self.cwnd.powf(0.4)).max(1.0) * 8.0;
            self.cwnd = (self.cwnd + n / self.cwnd).min(10000.0);
            // self.cubic_update(Instant::now());
            log::trace!("ACK CWND => {}", self.cwnd);
        }
    }

    fn congestion_loss(&mut self) {
        let now = Instant::now();
        if now.saturating_duration_since(self.last_loss) > self.inflight.srtt() * 2 {
            let old_cwnd = self.cwnd;
            self.slow_start = false;
            self.last_loss = Instant::now();
            self.cwnd = (self.cwnd * 0.5).max(self.inflight.bdp());
            // self.cwnd_max = (self.inflight.bdp() / 0.8).max(self.cwnd);
            // let now = Instant::now();
            // self.last_loss = now;
            // self.cubic_secs = 0.0;
            // self.cubic_update(now);
            log::debug!(
                "LOSS CWND => {} (old_cwnd {}) bdp {} srtt {}ms",
                self.cwnd,
                old_cwnd,
                self.inflight.bdp(),
                self.inflight.srtt().as_millis()
            );
        }
    }

    fn cubic_update(&mut self, now: Instant) {
        let delta_t = now
            .saturating_duration_since(self.last_cubic)
            .as_secs_f64()
            .min(0.1);
        self.last_cubic = now;
        self.cubic_secs += delta_t;
        let t = self.cubic_secs * 3.0;
        let k = (self.cwnd_max / 2.0).powf(0.333);
        let wt = 0.4 * (t - k).powf(3.0) + self.cwnd_max;
        let new_cwnd = wt.min(10000.0);
        self.cwnd = new_cwnd;
        // self.cwnd = 300.0;
    }
}
