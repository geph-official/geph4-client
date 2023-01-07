use bytes::Bytes;
use geph4_protocol::binder::client::CachedBinderClient;
use parking_lot::RwLock;
use smol::channel::{Receiver, Sender};
use smol_str::SmolStr;
use std::net::SocketAddr;

use sosistab2::MuxStream;
use std::{
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};
use tunnel_actor::tunnel_actor;
pub mod activity;
pub mod getsess;

pub mod tunnel_actor;

use std::net::Ipv4Addr;

use self::activity::notify_activity;

#[derive(Clone)]
pub enum EndpointSource {
    Independent { endpoint: String },
    Binder(BinderTunnelParams),
}

#[derive(Clone)]
pub struct BinderTunnelParams {
    pub ccache: Arc<CachedBinderClient>,
    pub exit_server: Option<String>,
    pub use_bridges: bool,
    pub force_bridge: Option<Ipv4Addr>,
    pub force_protocol: Option<String>,
}

#[derive(Clone)]
pub(crate) struct TunnelCtx {
    pub endpoint: EndpointSource,
    pub recv_socks5_conn: Receiver<(String, Sender<MuxStream>)>,
    pub vpn_client_ip: Arc<AtomicU32>,

    pub connect_status: Arc<RwLock<ConnectionStatus>>,
    recv_vpn_outgoing: Receiver<Bytes>,
    send_vpn_incoming: Sender<Bytes>,

    status_callback: Arc<dyn Fn(TunnelStatus) + Send + Sync + 'static>,
}

/// A status update from a [ClientTunnel].
#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq, Hash)]
#[non_exhaustive]
pub enum TunnelStatus {
    /// Just about to connect to a given address, with the given protocol
    PreConnect { addr: SocketAddr, protocol: SmolStr },
}

/// A ConnectionStatus shows the status of the tunnel.
#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum ConnectionStatus {
    Connecting,
    Connected { protocol: SmolStr, address: SmolStr },
}

impl ConnectionStatus {
    pub fn connected(&self) -> bool {
        matches!(self, Self::Connected { .. })
    }
}

/// A tunnel starts and keeps alive the best sosistab session it can under given constraints.
/// A sosistab Session is *a single end-to-end connection between a client and a server.*
/// This can be thought of as analogous to TcpStream, except all reads and writes are datagram-based and unreliable.
pub struct ClientTunnel {
    endpoint: EndpointSource,
    client_ip_addr: Arc<AtomicU32>,
    connect_status: Arc<RwLock<ConnectionStatus>>,

    send_vpn_outgoing: Sender<Bytes>,
    recv_vpn_incoming: Receiver<Bytes>,

    open_socks5_conn: Sender<(String, Sender<MuxStream>)>,

    _task: Arc<smol::Task<anyhow::Result<()>>>,
}

impl ClientTunnel {
    /// Creates a new ClientTunnel.
    pub fn new(
        endpoint: EndpointSource,
        status_callback: impl Fn(TunnelStatus) + Send + Sync + 'static,
    ) -> Self {
        let (send_socks5, recv_socks5) = smol::channel::unbounded();
        let (send_outgoing, recv_outgoing) = smol::channel::bounded(10000);
        let (send_incoming, recv_incoming) = smol::channel::bounded(10000);
        let current_state = Arc::new(AtomicU32::new(0));

        let _last_ping_ms = Arc::new(AtomicU32::new(0));

        let connect_status = Arc::new(RwLock::new(ConnectionStatus::Connecting));
        let ctx = TunnelCtx {
            endpoint: endpoint.clone(),
            recv_socks5_conn: recv_socks5,
            vpn_client_ip: current_state.clone(),

            connect_status: connect_status.clone(),
            send_vpn_incoming: send_incoming,
            recv_vpn_outgoing: recv_outgoing,
            status_callback: Arc::new(status_callback),
        };
        let task = Arc::new(smolscale::spawn(tunnel_actor(ctx)));

        ClientTunnel {
            endpoint,
            client_ip_addr: current_state,
            send_vpn_outgoing: send_outgoing,
            recv_vpn_incoming: recv_incoming,
            open_socks5_conn: send_socks5,

            connect_status,
            _task: task,
        }
    }

    /// Returns the current connection status.
    pub fn status(&self) -> ConnectionStatus {
        if self.client_ip_addr.load(Ordering::Relaxed) == 0 {
            ConnectionStatus::Connecting
        } else {
            self.connect_status.read().clone()
        }
    }

    /// Returns a sosistab stream to the given remote host.
    pub async fn connect_stream(&self, remote: &str) -> anyhow::Result<MuxStream> {
        let (send, recv) = smol::channel::bounded(1);
        self.open_socks5_conn
            .send((remote.to_string(), send))
            .await?;
        Ok(recv.recv().await?)
    }

    pub async fn send_vpn(&self, msg: Bytes) -> anyhow::Result<()> {
        notify_activity();
        self.send_vpn_outgoing.send(msg).await?;
        Ok(())
    }

    pub async fn recv_vpn(&self) -> anyhow::Result<Bytes> {
        let msg = self.recv_vpn_incoming.recv().await?;
        Ok(msg)
    }

    pub async fn get_vpn_client_ip(&self) -> Ipv4Addr {
        loop {
            let current_state = self.client_ip_addr.load(Ordering::Relaxed);

            if current_state == 0 {
                smol::Timer::after(Duration::from_millis(500)).await;
            } else {
                return Ipv4Addr::from(current_state);
            }
        }
    }

    pub fn get_endpoint(&self) -> EndpointSource {
        self.endpoint.clone()
    }
}
