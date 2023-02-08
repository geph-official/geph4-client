use std::{
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
    last_send: Mutex<Instant>,

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
            last_send: Mutex::new(Instant::now()),

            reconnector: Mutex::new(None),
        }
    }
}

#[async_trait]
impl<P: Pipe> Pipe for AutoconnectPipe<P> {
    async fn send(&self, to_send: Bytes) {
        // TODO if a certain time since the last recv, transition into connecting
        {
            let mut inner = self.status.lock();
            if let Inner::Connected(p) = inner.deref() {
                let last_recv = *self.last_recv.lock();
                if last_recv.elapsed() > Duration::from_secs(5) {
                    let last_send = *self.last_send.lock();
                    if last_send > last_recv && last_send.elapsed() > Duration::from_secs(1) {
                        log::debug!("reconnecting {}...", self.peer_addr);
                        let next_slot = Arc::new(Mutex::new(None));
                        let make_pipe = self.make_pipe.clone();
                        *self.reconnector.lock() = Some(smolscale::spawn({
                            let next_slot = next_slot.clone();
                            async move {
                                let pipe = make_pipe().await;
                                *next_slot.lock() = Some(Arc::new(pipe))
                            }
                        }));
                        *inner = Inner::Reconnecting(p.clone(), next_slot);
                    }
                }
            }
        }
        // If connecting is done, transition back into connected
        {
            let mut inner = self.status.lock();
            if let Inner::Reconnecting(_, next) = inner.deref_mut() {
                let lala = next.lock().take();
                if let Some(lala) = lala {
                    *self.recv_from.lock() = lala.clone();
                    self.signal_change.notify(usize::MAX);
                    log::debug!("reconnected {}!", self.peer_addr);
                    *self.last_recv.lock() = Instant::now();
                    *inner = Inner::Connected(lala)
                }
            }
        }
        let pipe = {
            let status = self.status.lock();
            match status.deref() {
                Inner::Connected(p) => {
                    *self.last_send.lock() = Instant::now();
                    p.clone()
                }
                Inner::Reconnecting(p, _) => p.clone(),
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
    Reconnecting(Arc<P>, Arc<Mutex<Option<Arc<P>>>>),
}
