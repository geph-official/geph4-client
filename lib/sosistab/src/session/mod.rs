use crate::fec::FrameEncoder;
use crate::{crypt::AeadError, mux::Multiplex, runtime, StatsGatherer};
use crate::{crypt::NgAead, protocol::DataFrameV2};
use bytes::Bytes;

use machine::RecvMachine;
use parking_lot::Mutex;
use rloss::RecvLossCalc;
use smol::channel::{Receiver, Sender};
use smol::prelude::*;
use stats::StatsCalculator;

use std::{sync::Arc, time::Duration};
use thiserror::Error;
mod machine;
mod rloss;
mod stats;

#[derive(Debug, Clone)]
pub(crate) struct SessionConfig {
    pub version: u64,
    pub session_key: Vec<u8>,
    pub role: Role,
    pub gather: Arc<StatsGatherer>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Role {
    Server,
    Client,
}

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("session dropped")]
    SessionDropped,
}

/// This struct represents a **session**: a single end-to-end connection between a client and a server. This can be thought of as analogous to `TcpStream`, except all reads and writes are datagram-based and unreliable. [Session] is thread-safe and can be wrapped in an [Arc](std::sync::Arc) to be shared between threads.
///
/// [Session] should be used directly only if an unreliable connection is all you need. For most applications, use [Multiplex](crate::mux::Multiplex), which wraps a [Session] and provides QUIC-like reliable streams as well as unreliable messages, all multiplexed over a single [Session].
pub struct Session {
    send_tosend: Sender<Bytes>,
    recv_decoded: Receiver<Bytes>,
    statistics: Arc<StatsGatherer>,
    dropper: Vec<Box<dyn FnOnce() + Send + Sync + 'static>>,
    _task: smol::Task<()>,
}

impl Drop for Session {
    fn drop(&mut self) {
        for v in self.dropper.drain(0..) {
            v()
        }
    }
}

impl Session {
    /// Creates a Session.
    pub(crate) fn new(cfg: SessionConfig) -> (Self, SessionBack) {
        let (send_tosend, recv_tosend) = smol::channel::bounded(512);
        let gather = cfg.gather.clone();
        let calculator = Arc::new(StatsCalculator::new(gather.clone()));
        let rloss = Arc::new(Mutex::new(RecvLossCalc::new(1.0)));
        let machine = Mutex::new(RecvMachine::new(
            calculator.clone(),
            rloss.clone(),
            &cfg.session_key,
            cfg.role,
        ));

        let (send_decoded, recv_decoded) = smol::channel::bounded(512);
        let (send_outgoing, recv_outgoing) = smol::channel::bounded(64);
        let session_back = SessionBack {
            machine,
            send_decoded,
            recv_outgoing,
        };
        let send_crypt_key = match cfg.role {
            Role::Server => blake3::keyed_hash(crate::crypt::DN_KEY, &cfg.session_key),
            Role::Client => blake3::keyed_hash(crate::crypt::UP_KEY, &cfg.session_key),
        };
        let send_crypt = NgAead::new(send_crypt_key.as_bytes());
        let ctx = SessionSendCtx {
            cfg,
            statg: calculator,
            gather: gather.clone(),
            rloss,
            recv_tosend,
            send_crypt,
            send_outgoing,
        };

        let task = runtime::spawn(session_send_loop(ctx));
        let session = Session {
            send_tosend,
            recv_decoded,
            statistics: gather,
            dropper: Vec::new(),
            _task: task,
        };
        (session, session_back)
    }

    /// Adds a closure to be run when the Session is dropped. This can be used to manage associated "worker" resources.
    pub fn on_drop<T: FnOnce() + Send + Sync + 'static>(&mut self, thing: T) {
        self.dropper.push(Box::new(thing))
    }

    /// Takes a [Bytes] to be sent and stuffs it into the session.
    pub async fn send_bytes(&self, to_send: Bytes) -> Result<(), SessionError> {
        self.statistics
            .increment("total_sent_bytes", to_send.len() as f32);
        if self.send_tosend.send(to_send).await.is_err() {
            self.recv_decoded.close();
            Err(SessionError::SessionDropped)
        } else {
            Ok(())
        }
    }

    /// Waits until the next application input is decoded by the session.
    pub async fn recv_bytes(&self) -> Result<Bytes, SessionError> {
        let recv = self
            .recv_decoded
            .recv()
            .await
            .map_err(|_| SessionError::SessionDropped)?;
        self.statistics
            .increment("total_recv_bytes", recv.len() as f32);
        Ok(recv)
    }

    /// "Upgrades" this session into a [Multiplex]
    pub fn multiplex(self) -> Multiplex {
        Multiplex::new(self)
    }
}

/// "Back side" of a Session.
pub(crate) struct SessionBack {
    machine: Mutex<RecvMachine>,
    send_decoded: Sender<Bytes>,
    recv_outgoing: Receiver<Bytes>,
}

impl SessionBack {
    /// Given an incoming raw packet, injects it into the sessionback. If decryption fails, returns an error.
    pub fn inject_incoming(&self, pkt: &[u8]) -> Result<(), AeadError> {
        let decoded = self.machine.lock().process(pkt)?;
        if let Some(decoded) = decoded {
            for decoded in decoded {
                let _ = self.send_decoded.try_send(decoded);
            }
        }
        Ok(())
    }

    /// Wait for an outgoing packet from the session.
    pub async fn next_outgoing(&self) -> Result<Bytes, SessionError> {
        self.recv_outgoing
            .recv()
            .await
            .ok()
            .ok_or(SessionError::SessionDropped)
    }
}

struct SessionSendCtx {
    cfg: SessionConfig,
    statg: Arc<StatsCalculator>,
    gather: Arc<StatsGatherer>,
    rloss: Arc<Mutex<RecvLossCalc>>,
    recv_tosend: Receiver<Bytes>,
    send_crypt: NgAead,
    send_outgoing: Sender<Bytes>,
}

// #[tracing::instrument(skip(ctx))]
async fn session_send_loop(ctx: SessionSendCtx) {
    // sending loop
    if ctx.cfg.version == 1 {
        return;
    } else {
        let version = ctx.cfg.version;
        session_send_loop_nextgen(ctx, version).await;
    }
}

const BURST_SIZE: usize = 40;

#[tracing::instrument(skip(ctx))]
async fn session_send_loop_nextgen(ctx: SessionSendCtx, version: u64) -> Option<()> {
    enum Event {
        NewPayload(Bytes),
        FecTimeout,
    }

    const FEC_TIMEOUT_MS: u64 = 20;

    // FEC timer: when this expires, send parity packets regardless if we have assembled BURST_SIZE data packets.
    let mut fec_timer = smol::Timer::after(Duration::from_millis(FEC_TIMEOUT_MS));
    // Vector of "unfecked" frames.
    let mut unfecked: Vec<(u64, Bytes)> = Vec::new();
    let mut fec_encoder = FrameEncoder::new(10); // around 4 percent
    let mut frame_no = 0;
    loop {
        // either we have something new to send, or the FEC timer expired.
        let event: Option<Event> = async {
            if unfecked.is_empty() {
                smol::future::pending::<()>().await;
            }
            if unfecked.len() < BURST_SIZE {
                // we need to wait, because the burst size isn't there yet
                (&mut fec_timer).await;
            }
            Some(Event::FecTimeout)
        }
        .or(async { Some(Event::NewPayload(ctx.recv_tosend.recv().await.ok()?)) })
        .await;
        let loss = ctx.rloss.lock().calculate_loss();
        let loss_u8 = (loss * 254.0) as u8;
        ctx.gather.update("recv_loss", loss as f32);
        match event? {
            // we have something to send as a data packet.
            Event::NewPayload(send_payload) => {
                let send_framed = DataFrameV2::Data {
                    frame_no,
                    high_recv_frame_no: ctx.statg.high_recv_frame_no(),
                    total_recv_frames: ctx.statg.total_recv_frames(),
                    body: send_payload.clone(),
                };
                // we now add to unfecked
                unfecked.push((frame_no, send_payload));
                let send_padded = send_framed.pad(loss_u8);
                ctx.statg.ping_send(frame_no);
                let send_encrypted = ctx.send_crypt.encrypt(&send_padded);
                ctx.send_outgoing.send(send_encrypted).await.ok()?;
                // increment frame no
                frame_no += 1;
                // reset fec timer
                fec_timer.set_after(Duration::from_millis(FEC_TIMEOUT_MS));
            }
            // we have something to send, as a FEC packet.
            Event::FecTimeout => {
                // reset fec timer
                fec_timer.set_after(Duration::from_millis(FEC_TIMEOUT_MS));
                if unfecked.is_empty() {
                    continue;
                }
                let measured_loss = ctx.statg.loss_u8();
                if measured_loss == 0 {
                    unfecked.clear();
                    continue;
                }

                assert!(unfecked.len() <= BURST_SIZE);
                // encode
                let first_frame_no = unfecked[0].0;
                let data_count = unfecked.len();
                let expanded = fec_encoder.encode(
                    ctx.statg.loss_u8(),
                    &unfecked.iter().map(|v| v.1.clone()).collect::<Vec<_>>(),
                );
                let pad_size = unfecked.iter().map(|v| v.1.len()).max().unwrap_or_default() + 2;
                let parity = &expanded[unfecked.len()..];
                unfecked.clear();
                tracing::trace!("FecTimeout; sending {} parities", parity.len());
                let parity_count = parity.len();
                // encode parity, taking along the first data frame no to identify the run
                for (index, parity) in parity.iter().enumerate() {
                    let send_framed = DataFrameV2::Parity {
                        data_frame_first: first_frame_no,
                        data_count: data_count as u8,
                        parity_count: parity_count as u8,
                        parity_index: index as u8,
                        body: parity.clone(),
                        pad_size,
                    };
                    let send_padded = send_framed.pad(loss_u8);
                    let send_encrypted = ctx.send_crypt.encrypt(&send_padded);
                    ctx.send_outgoing.send(send_encrypted).await.ok()?;
                }
            }
        }
    }
}
