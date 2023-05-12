use std::{
    marker::PhantomData,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;

use smol::{
    channel::{Receiver, Sender},
    future::FutureExt,
    Task,
};
use sosistab2::Pipe;

pub struct AutoconnectPipe<P: Pipe> {
    protocol: String,
    peer_metadata: String,
    peer_addr: String,

    send_up: Sender<Bytes>,
    recv_down: Receiver<Bytes>,

    _task: Task<()>,

    _p: PhantomData<P>,
}

impl<P: Pipe> AutoconnectPipe<P> {
    /// Creates a new autoconnecting pipe.
    pub fn new(pipe: P, recreate: impl Fn() -> Task<P> + Send + Sync + 'static) -> Self {
        let protocol = pipe.protocol().to_string();
        let peer_metadata = pipe.peer_metadata().to_string();
        let peer_addr = pipe.peer_addr();
        let (send_up, recv_up) = smol::channel::unbounded();
        let (send_down, recv_down) = smol::channel::unbounded();
        let _task = smolscale::spawn(autoconnect_loop(
            recv_up,
            send_down,
            pipe,
            recreate,
            protocol.clone(),
            peer_addr.clone(),
        ));
        Self {
            _task,

            send_up,
            recv_down,

            protocol,
            peer_metadata,
            peer_addr,

            _p: Default::default(),
        }
    }
}

#[async_trait]
impl<P: Pipe> Pipe for AutoconnectPipe<P> {
    async fn send(&self, to_send: Bytes) {
        let _ = self.send_up.send(to_send).await;
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        self.recv_down
            .recv()
            .await
            .map_err(|_e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "shuffler died"))
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

async fn autoconnect_loop<P: Pipe>(
    recv_up: Receiver<Bytes>,
    send_down: Sender<Bytes>,
    init_pipe: P,
    recreate: impl Fn() -> Task<P> + Send + Sync + 'static,

    protocol: String,
    endpoint: String,
) {
    scopeguard::defer!({
        log::debug!("**** AUTOCONNECT LOOP STOPPED ****");
    });

    enum Event<P> {
        Up(Bytes),
        Down(Bytes),
        Replaced(P),
    }
    let mut current_pipe = init_pipe;
    let mut replace_task: Option<(Receiver<P>, Task<()>)> = None;
    let recreate = Arc::new(recreate);
    loop {
        let up_event = async {
            let up = recv_up.recv().await?;
            anyhow::Ok(Event::Up(up))
        };
        let dn_event = async {
            anyhow::Ok(if let Ok(val) = current_pipe.recv().await {
                Event::Down(val)
            } else {
                smol::future::pending().await
            })
        };
        let replace_event = async {
            if let Some((recv, _)) = replace_task.as_ref() {
                anyhow::Ok(Event::Replaced(recv.recv().await?))
            } else {
                smol::future::pending().await
            }
        };

        match up_event.or(replace_event.or(dn_event)).await {
            Ok(Event::Up(up)) => {
                current_pipe.send(up).await;
                // on average, we need 5 packets to break through
                if replace_task.is_none() && fastrand::f64() < 0.2 {
                    let (send, recv) = smol::channel::bounded(1);
                    let protocol = protocol.clone();
                    let endpoint = endpoint.clone();
                    let recreate = recreate.clone();
                    replace_task = Some((
                        recv,
                        smolscale::spawn(async move {
                            smol::Timer::after(Duration::from_secs(5)).await;
                            let start = Instant::now();
                            log::debug!("reconnecting {protocol}/{endpoint}...");
                            let replacement = recreate().await;
                            log::debug!(
                                "reconnected {protocol}/{endpoint} in {:?}!",
                                start.elapsed()
                            );
                            let _ = send.try_send(replacement);
                        }),
                    ));
                }
            }
            Ok(Event::Down(dn)) => {
                replace_task = None;
                let _ = send_down.try_send(dn);
            }
            Ok(Event::Replaced(p)) => {
                current_pipe = p;
                replace_task = None;
            }
            Err(err) => {
                log::warn!("error: {:?}", err);
                smol::Timer::after(Duration::from_secs(1)).await;
            }
        }
    }
}
