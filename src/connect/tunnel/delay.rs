use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use smol::{channel::Sender, Task};
use sosistab2::Pipe;

pub struct DelayPipe<P: Pipe> {
    inner: Arc<P>,
    send_outgoing: Sender<(Bytes, Instant)>,
    delay: Duration,
    _task: Task<anyhow::Result<()>>,
}

impl<P: Pipe> DelayPipe<P> {
    /// Creates a new Pipe that delays outgoing packets for the given duration.
    pub fn new(pipe: P, delay: Duration) -> Self {
        let pipe = Arc::new(pipe);
        let (send_outgoing, recv_outgoing) = smol::channel::unbounded();
        let out_pipe = pipe.clone();
        let _task = smolscale::spawn(async move {
            loop {
                let (pkt, deadline) = recv_outgoing.recv().await?;
                smol::Timer::at(deadline).await;
                out_pipe.send(pkt).await;
            }
        });
        Self {
            inner: pipe,
            send_outgoing,
            delay,
            _task,
        }
    }
}
#[async_trait]
impl<P: Pipe> Pipe for DelayPipe<P> {
    async fn send(&self, to_send: Bytes) {
        let _ = self
            .send_outgoing
            .send((to_send, Instant::now() + self.delay))
            .await;
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        self.inner.recv().await
    }

    fn protocol(&self) -> &str {
        self.inner.protocol()
    }

    fn peer_metadata(&self) -> &str {
        self.inner.peer_metadata()
    }

    fn peer_addr(&self) -> String {
        self.inner.peer_addr()
    }
}
