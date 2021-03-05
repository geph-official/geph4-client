use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use rustc_hash::FxHashSet;
use smol::channel::Receiver;

use crate::{mux::structs::*, VarRateLimit};

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

    limiter: VarRateLimit,
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

            limiter: VarRateLimit::new(),
        }
    }
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
        // match on our current state repeatedly
        #[derive(Debug)]
        enum Evt {
            Rto,
            AckTimer,
            NewWrite(Bytes),
            NewPkt(Message),
            Closing,
        }
        let event = {
            let writeable = self.inflight.inflight() <= self.cwnd as usize
                && self.inflight.len() < 10000
                && !self.closing;
            let force_ack = self.ack_seqnos.len() >= 32;
            assert!(self.ack_seqnos.len() <= 32);

            let ack_timer = self.delayed_ack_timer;
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
            let rto_timer = self.inflight.wait_first();
            let rto_timeout = async {
                rto_timer.await;
                Ok::<Evt, anyhow::Error>(Evt::Rto)
            };
            let new_write = async {
                if writeable {
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
                            Ok(Evt::NewWrite(self.write_fragments.pop_front().unwrap()))
                        } else {
                            Ok(Evt::Closing)
                        }
                    } else {
                        Ok::<Evt, anyhow::Error>(Evt::NewWrite(
                            self.write_fragments.pop_front().unwrap(),
                        ))
                    }
                } else {
                    Ok(smol::future::pending().await)
                }
            };
            let new_pkt =
                async { Ok::<Evt, anyhow::Error>(Evt::NewPkt(recv_wire_read.recv().await?)) };
            let final_timeout = async {
                smol::Timer::after(Duration::from_secs(600)).await;
                anyhow::bail!("final timeout within relconn actor")
            };
            ack_timer
                .or(new_pkt.or(rto_timeout.or(new_write.or(final_timeout))))
                .await
        };
        let implied_rate = self.pacing_rate() as u32;
        // let cwnd_choked =
        //     self.inflight.inflight() <= self.cwnd as usize && self.inflight.len() < 10000;
        match event {
            Ok(Evt::Closing) => {
                self.closing = true;
                if self.inflight.len() > 0 {
                    Ok(())
                } else {
                    anyhow::bail!("closing when inflight is zero")
                }
            }
            Ok(Evt::Rto) => {
                let seqno = self.inflight.pop_first();
                // retransmit packet
                // assert!(!conn_vars.inflight.len() == 0);
                if let Ok(seqno) = seqno {
                    if self.inflight.len() > 0 {
                        if let Some(v) = self.inflight.get_seqno(seqno) {
                            let payload = v.payload.clone();
                            let retrans = v.retrans;
                            self.congestion_loss();
                            if retrans > 8 {
                                anyhow::bail!("full timeout")
                            }
                            self.retrans_count += 1;
                            // self.limiter.wait(implied_rate).await;
                            transmit(payload);
                        }
                    }
                }

                Ok(())
            }
            Ok(Evt::NewPkt(Message::Rel {
                kind: RelKind::Rst, ..
            })) => anyhow::bail!("received RST"),
            Ok(Evt::NewPkt(Message::Rel {
                kind: RelKind::DataAck,
                payload,
                seqno,
                ..
            })) => {
                let seqnos = bincode::deserialize::<Vec<Seqno>>(&payload)?;
                tracing::trace!("new ACK pkt with {} seqnos", seqnos.len());
                for seqno in seqnos {
                    if self.inflight.mark_acked(seqno) {
                        self.congestion_ack();
                    }
                }
                self.inflight.mark_acked_lt(seqno);
                // implied_rate.store(conn_vars.pacing_rate() as u32, Ordering::Relaxed);
                if self.inflight.len() == 0 && self.closing {
                    anyhow::bail!("inflight is zero, and we are now closing")
                } else {
                    Ok(())
                }
            }
            Ok(Evt::NewPkt(Message::Rel {
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
            Ok(Evt::NewPkt(_)) => anyhow::bail!("unrecognized packet"),
            Ok(Evt::NewWrite(bts)) => {
                assert!(bts.len() <= MSS);
                self.limiter.wait(implied_rate).await;
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
            Ok(Evt::AckTimer) => {
                // eprintln!("acking {} seqnos", conn_vars.ack_seqnos.len());
                let mut ack_seqnos: Vec<_> = self.ack_seqnos.iter().collect();
                assert!(ack_seqnos.len() <= 32);
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
                tracing::warn!("forced to RESET due to {:?}", err);
                anyhow::bail!(err);
            }
        }
    }

    pub fn pacing_rate(&self) -> f64 {
        // calculate implicit rate
        self.cwnd / self.inflight.min_rtt().as_secs_f64()
    }

    pub fn congestion_ack(&mut self) {
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
        .max(3.0)
        .min(128.0);
        self.cwnd += bic_inc / self.cwnd;
    }

    pub fn congestion_loss(&mut self) {
        self.slow_start = false;
        self.loss_rate = self.loss_rate * 0.99 + 0.01;
        let now = Instant::now();
        if now.saturating_duration_since(self.last_loss) > self.inflight.rto() {
            let beta = 0.2;
            if self.cwnd < self.ssthresh {
                self.ssthresh = self.cwnd * (2.0 - beta) / 2.0;
            } else {
                self.ssthresh = self.cwnd;
            }

            self.cwnd *= 1.0 - beta;
            tracing::debug!(
                "LOSS CWND => {:.2}; loss rate {:.2}, srtt {}ms (var {}ms), rate {:.1}",
                self.cwnd,
                self.loss_rate,
                self.inflight.srtt().as_millis(),
                self.inflight.rtt_var().as_millis(),
                self.inflight.rate()
            );
            self.last_loss = now;
        }
    }
}
