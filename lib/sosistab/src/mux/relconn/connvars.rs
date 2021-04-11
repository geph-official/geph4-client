use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use rustc_hash::FxHashSet;
use smol::channel::Receiver;

use crate::{mux::structs::*, safe_deserialize};

use super::{
    bipe::{BipeReader, BipeWriter},
    inflight::Inflight,
    MSS,
};
use smol::prelude::*;

pub(crate) struct ConnVars {
    pub pre_inflight: VecDeque<Message>,
    pub inflight: Inflight,
    pub next_free_seqno: Seqno,
    pub retrans_count: u64,

    pub delayed_ack_timer: Option<Instant>,
    pub ack_seqnos: FxHashSet<Seqno>,

    pub reorderer: Reorderer<Bytes>,
    pub lowest_unseen: Seqno,
    // read_buffer: VecDeque<Bytes>,
    slow_start: bool,
    ssthresh: f64,
    pub cwnd: f64,
    last_loss: Instant,

    flights: u64,
    last_flight: Instant,

    loss_rate: f64,

    pub closing: bool,

    write_fragments: VecDeque<Bytes>,

    in_recovery: bool,
    // limiter: VarRateLimit,
}

impl Default for ConnVars {
    fn default() -> Self {
        ConnVars {
            pre_inflight: VecDeque::new(),
            inflight: Inflight::new(),
            next_free_seqno: 0,
            retrans_count: 0,

            delayed_ack_timer: None,
            ack_seqnos: FxHashSet::default(),

            reorderer: Reorderer::default(),
            lowest_unseen: 0,

            slow_start: true,
            cwnd: 64.0,
            ssthresh: -500.0,
            last_loss: Instant::now(),

            flights: 0,
            last_flight: Instant::now(),

            loss_rate: 0.0,

            closing: false,

            write_fragments: VecDeque::new(),

            in_recovery: false,
            // limiter: VarRateLimit::new(),
        }
    }
}

const ACK_BATCH: usize = 64;

// match on our current state repeatedly
#[derive(Debug)]
enum ConnVarEvt {
    Rto(Seqno),
    AckTimer,
    NewWrite(Bytes),
    NewPkt(Message),
    Closing,
    Retry,
}

impl ConnVars {
    /// Process a *single* event. Returns false when the thing should be closed.
    pub async fn process_one(
        &mut self,
        stream_id: u16,
        recv_write: &mut BipeReader,
        send_read: &mut BipeWriter,
        recv_wire_read: &Receiver<Message>,
        transmit: impl Fn(Message),
    ) -> anyhow::Result<()> {
        let _implied_rate = self.pacing_rate() as u32;
        // let cwnd_choked =
        //     self.inflight.inflight() <= self.cwnd as usize && self.inflight.len() < 10000;
        match self.next_event(recv_write, recv_wire_read).await {
            Ok(ConnVarEvt::Retry) => Ok(()),
            Ok(ConnVarEvt::Closing) => {
                self.closing = true;
                if self.inflight.unacked() > 0 {
                    Ok(())
                } else {
                    anyhow::bail!("closing when inflight is zero")
                }
            }
            Ok(ConnVarEvt::Rto(seqno)) => {
                if let Some(payload) = self.inflight.retransmit(seqno) {
                    tracing::debug!(
                        "** RETRANSMIT {} (inflight = {}, cwnd = {}, left = {}) **",
                        seqno,
                        self.inflight.inflight(),
                        self.cwnd as u64,
                        self.inflight.unacked() - self.inflight.inflight(),
                    );
                    self.congestion_loss();
                    self.retrans_count += 1;
                    // self.limiter.wait(implied_rate).await;
                    transmit(payload);
                }
                Ok(())
            }
            Ok(ConnVarEvt::NewPkt(Message::Rel {
                kind: RelKind::Rst, ..
            })) => anyhow::bail!("received RST"),
            Ok(ConnVarEvt::NewPkt(Message::Rel {
                kind: RelKind::DataAck,
                payload,
                seqno,
                ..
            })) => {
                let seqnos = safe_deserialize::<Vec<Seqno>>(&payload)?;
                tracing::trace!("new ACK pkt with {} seqnos", seqnos.len());
                for seqno in seqnos {
                    if self.inflight.mark_acked(seqno) {
                        self.congestion_ack();
                    }
                }
                self.inflight.mark_acked_lt(seqno);
                let outstanding = self.inflight.unacked() - self.inflight.inflight();
                if outstanding == 0 {
                    self.in_recovery = false;
                }
                // implied_rate.store(conn_vars.pacing_rate() as u32, Ordering::Relaxed);
                if self.inflight.unacked() == 0 && self.closing {
                    anyhow::bail!("inflight is zero, and we are now closing")
                } else {
                    Ok(())
                }
            }
            Ok(ConnVarEvt::NewPkt(Message::Rel {
                kind: RelKind::Data,
                seqno,
                payload,
                ..
            })) => {
                tracing::trace!("new data pkt with seqno={}", seqno);
                if self.delayed_ack_timer.is_none() {
                    self.delayed_ack_timer = Instant::now().checked_add(Duration::from_millis(1));
                }
                if self.reorderer.insert(seqno, payload) {
                    self.ack_seqnos.insert(seqno);
                }
                let times = self.reorderer.take();
                self.lowest_unseen += times.len() as u64;
                let mut success = true;
                for pkt in times {
                    success |= send_read.write(&pkt).await.is_ok();
                }
                if success {
                    Ok(())
                } else {
                    anyhow::bail!("cannot write into send_read")
                }
            }
            Ok(ConnVarEvt::NewWrite(bts)) => {
                assert!(bts.len() <= MSS);
                // self.limiter.wait(implied_rate).await;
                let seqno = self.next_free_seqno;
                self.next_free_seqno += 1;
                let msg = Message::Rel {
                    kind: RelKind::Data,
                    stream_id,
                    seqno,
                    payload: bts,
                };
                // put msg into inflight
                self.inflight.insert(seqno, msg.clone());

                transmit(msg);

                Ok(())
            }
            Ok(ConnVarEvt::AckTimer) => {
                // eprintln!("acking {} seqnos", conn_vars.ack_seqnos.len());
                let mut ack_seqnos: Vec<_> = self.ack_seqnos.iter().collect();
                assert!(ack_seqnos.len() <= ACK_BATCH);
                ack_seqnos.sort_unstable();
                let encoded_acks = bincode::serialize(&ack_seqnos).unwrap();
                if encoded_acks.len() > 1000 {
                    tracing::warn!("encoded_acks {} bytes", encoded_acks.len());
                }
                transmit(Message::Rel {
                    kind: RelKind::DataAck,
                    stream_id,
                    seqno: self.lowest_unseen,
                    payload: Bytes::copy_from_slice(&encoded_acks),
                });
                self.ack_seqnos.clear();
                self.delayed_ack_timer = None;

                Ok(())
            }
            Err(err) => {
                tracing::debug!("forced to RESET due to {:?}", err);
                anyhow::bail!(err);
            }
            evt => {
                tracing::debug!("unrecognized event: {:#?}", evt);
                Ok(())
            }
        }
    }

    async fn next_event(
        &mut self,
        recv_write: &mut BipeReader,
        recv_wire_read: &Receiver<Message>,
    ) -> anyhow::Result<ConnVarEvt> {
        let can_retransmit = self.inflight.inflight() <= self.cwnd as usize && !self.closing;
        let can_write = can_retransmit && self.inflight.unacked() <= self.cwnd as usize;
        let force_ack = self.ack_seqnos.len() >= ACK_BATCH;
        assert!(self.ack_seqnos.len() <= ACK_BATCH);

        let ack_timer = self.delayed_ack_timer;
        let ack_timer = async {
            if force_ack {
                return Ok(ConnVarEvt::AckTimer);
            }
            if let Some(time) = ack_timer {
                smol::Timer::at(time).await;
                Ok::<ConnVarEvt, anyhow::Error>(ConnVarEvt::AckTimer)
            } else {
                smol::future::pending().await
            }
        };
        let rto_timeout = if !can_retransmit {
            async { smol::future::pending().await }.boxed()
        } else if let Some((rto_seqno, rto_time)) = self.inflight.first_rto() {
            async move {
                smol::Timer::at(rto_time).await;
                Ok::<ConnVarEvt, anyhow::Error>(ConnVarEvt::Rto(rto_seqno))
            }
            .boxed()
        } else {
            async { smol::future::pending().await }.boxed()
        };
        let new_write = async {
            if can_write {
                if self.write_fragments.is_empty() {
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
                        self.write_fragments.push_back(to_write);
                        Ok(ConnVarEvt::NewWrite(
                            self.write_fragments.pop_front().unwrap(),
                        ))
                    } else {
                        Ok(ConnVarEvt::Closing)
                    }
                } else {
                    Ok::<ConnVarEvt, anyhow::Error>(ConnVarEvt::NewWrite(
                        self.write_fragments.pop_front().unwrap(),
                    ))
                }
            } else {
                Ok(smol::future::pending().await)
            }
        };
        let new_pkt = async {
            Ok::<ConnVarEvt, anyhow::Error>(ConnVarEvt::NewPkt(recv_wire_read.recv().await?))
        };
        let final_timeout = async {
            smol::Timer::after(Duration::from_secs(600)).await;
            anyhow::bail!("final timeout within relconn actor")
        };
        let retry_timeout = if can_retransmit {
            async { Ok(smol::future::pending().await) }.boxed()
        } else {
            async {
                smol::Timer::after(Duration::from_millis(10)).await;
                Ok(ConnVarEvt::Retry)
            }
            .boxed()
        };
        ack_timer
            .or(new_pkt.or(rto_timeout.or(new_write.or(final_timeout.or(retry_timeout)))))
            .await
    }

    fn pacing_rate(&self) -> f64 {
        // calculate implicit rate
        self.cwnd / self.inflight.min_rtt().as_secs_f64()
    }

    fn congestion_ack(&mut self) {
        let now = Instant::now();
        if now.saturating_duration_since(self.last_flight) > self.inflight.srtt() {
            self.flights += 1;
            self.last_flight = now
        }
        self.loss_rate *= 0.99;

        let bic_inc = if self.cwnd < self.ssthresh {
            (self.ssthresh - self.cwnd) / 2.0
        } else {
            self.cwnd - self.ssthresh
        }
        .max(0.23 * self.cwnd.powf(0.4) * 3.0) // at least as fast as 3xHSTCP
        .min(self.cwnd)
        .min(256.0);
        self.cwnd += bic_inc / self.cwnd;
    }

    fn congestion_loss(&mut self) {
        self.slow_start = false;
        self.loss_rate = self.loss_rate * 0.99 + 0.01;
        let now = Instant::now();
        if !self.in_recovery
            && now.saturating_duration_since(self.last_loss) > self.inflight.min_rtt()
        {
            self.in_recovery = true;
            let beta = 0.25;
            if self.cwnd < self.ssthresh {
                self.ssthresh = self.cwnd * (2.0 - beta) / 2.0;
            } else {
                self.ssthresh = self.cwnd;
            }

            self.cwnd *= 1.0 - beta;
            self.cwnd = self.cwnd.max(3.0);
            tracing::debug!(
                "LOSS CWND => {:.2}; loss rate {:.2}, srtt {}ms (var {}ms)",
                self.cwnd,
                self.loss_rate,
                self.inflight.srtt().as_millis(),
                self.inflight.rtt_var().as_millis(),
            );
            self.last_loss = now;
        }
    }
}
