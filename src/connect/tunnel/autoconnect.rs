use std::{
    collections::VecDeque,
    ops::{Deref, DerefMut},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use event_listener::Event;
use parking_lot::Mutex;
use smol::{future::FutureExt, Task};
use sosistab2::Pipe;

pub struct AutoconnectPipe<P: Pipe> {
    status: Mutex<Inner<P>>,
    make_pipe: Arc<dyn Fn() -> Task<P> + Send + Sync + 'static>,
    recv_from: Mutex<Arc<P>>,
    signal_change: Event,

    protocol: String,
    peer_metadata: String,
    peer_addr: String,

    last_recv: Mutex<Instant>,
    last_sends: Mutex<VecDeque<Instant>>,

    reconnector: Mutex<Option<Task<()>>>,
}

impl<P: Pipe> AutoconnectPipe<P> {
    /// Creates a new autoconnecting pipe.
    pub fn new(pipe: P, recreate: impl Fn() -> Task<P> + Send + Sync + 'static) -> Self {
        let pipe = Arc::new(pipe);
        Self {
            status: Mutex::new(Inner::Connected(pipe.clone())),
            make_pipe: Arc::new(recreate),
            recv_from: Mutex::new(pipe.clone()),
            signal_change: Event::new(),

            protocol: pipe.protocol().to_string(),
            peer_metadata: pipe.peer_metadata().to_string(),
            peer_addr: pipe.peer_addr(),

            last_recv: Mutex::new(Instant::now()),
            last_sends: Default::default(),

            reconnector: Mutex::new(None),
        }
    }
}

#[async_trait]
impl<P: Pipe> Pipe for AutoconnectPipe<P> {
    async fn send(&self, to_send: Bytes) {
        // If a certain time since the last recv, transition into connecting
        {
            let mut inner = self.status.lock();
            if let Inner::Connected(p) = inner.deref() {
                let last_recv = *self.last_recv.lock();
                if last_recv.elapsed() > Duration::from_secs(5) {
                    let last_sends = self.last_sends.lock();
                    // if there was more than 3 packets fitting the criterion, then we are oh so dead
                    let probably_dead = last_sends
                        .iter()
                        .filter(|pkt_time| {
                            pkt_time > &&last_recv && pkt_time.elapsed() > Duration::from_secs(1)
                        })
                        .count()
                        > 3;

                    if probably_dead {
                        log::debug!("reconnecting {} / {}...", self.protocol(), self.peer_addr);
                        let next_slot = Arc::new(Mutex::new(None));
                        let make_pipe = self.make_pipe.clone();
                        *self.reconnector.lock() = Some(smolscale::spawn({
                            let next_slot = next_slot.clone();
                            async move {
                                let pipe = make_pipe().await;
                                *next_slot.lock() = Some(Arc::new(pipe))
                            }
                        }));
                        *inner = Inner::Reconnecting(p.clone(), next_slot, Instant::now());
                    }
                }
            }
        }
        // If connecting is done, transition back into connected
        {
            let mut inner = self.status.lock();
            if let Inner::Reconnecting(_, next, time) = inner.deref_mut() {
                let lala = next.lock().take();
                if let Some(lala) = lala {
                    *self.recv_from.lock() = lala.clone();
                    self.signal_change.notify(usize::MAX);
                    log::debug!(
                        "reconnected {} / {} after {:?}!",
                        self.protocol(),
                        self.peer_addr,
                        time.elapsed()
                    );
                    *self.last_recv.lock() = Instant::now();
                    *inner = Inner::Connected(lala)
                }
            }
        }
        let pipe = {
            let status = self.status.lock();
            match status.deref() {
                Inner::Connected(p) => {
                    let mut sends = self.last_sends.lock();
                    sends.push_back(Instant::now());
                    if sends.len() > 100 {
                        sends.pop_front();
                    }
                    p.clone()
                }
                Inner::Reconnecting(p, _, _) => p.clone(),
            }
        };
        pipe.send(to_send).await
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        loop {
            let evt = self.signal_change.listen();
            let rr = self.recv_from.lock().clone();
            let break_now = async {
                let res = rr.recv().await;
                Some(res)
            }
            .or(async {
                evt.await;
                None
            });
            if let Some(res) = break_now.await {
                *self.last_recv.lock() = Instant::now();
                return res;
            }
        }
    }

    fn protocol(&self) -> &str {
        &self.protocol
    }

    fn peer_metadata(&self) -> &str {
        &self.peer_metadata
    }

    fn peer_addr(&self) -> String {
        self.peer_addr.clone()
    }
}

enum Inner<P: Pipe> {
    Connected(Arc<P>),
    Reconnecting(Arc<P>, Arc<Mutex<Option<Arc<P>>>>, Instant),
}
