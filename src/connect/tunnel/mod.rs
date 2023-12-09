
use bytes::Bytes;

use derivative::Derivative;
use geph_nat::GephNat;
use parking_lot::RwLock;

use smol::channel::{Receiver, Sender};
use smol_str::SmolStr;
use std::{net::SocketAddr, ops::Deref};

use sosistab2::Stream;
use std::sync::Arc;
use tunnel_actor::tunnel_actor;
pub mod activity;
mod getsess;

mod autoconnect;
mod delay;
mod tunnel_actor;

use std::net::Ipv4Addr;

use crate::conninfo_store::ConnInfoStore;

use self::activity::notify_activity;

#[derive(Clone)]
pub enum EndpointSource {
    Independent { endpoint: String },
    Binder(Arc<ConnInfoStore>, BinderTunnelParams),
}

#[derive(Clone)]
pub struct BinderTunnelParams {
    pub exit_server: Option<String>,
    pub use_bridges: bool,
    pub force_bridge: Option<Ipv4Addr>,
    pub force_protocol: Option<String>,
}

#[derive(Clone)]
struct TunnelCtx {
    endpoint: EndpointSource,
    recv_socks5_conn: Receiver<(String, Sender<Stream>)>,

    connect_status: Arc<RwLock<ConnectionStatus>>,
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
#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub enum ConnectionStatus {
    Connecting,
    Connected {
        protocol: SmolStr,
        address: SmolStr,
        #[derivative(Debug = "ignore")]
        vpn_client_ip: Option<(Ipv4Addr, Arc<GephNat>)>,
    },
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

    connect_status: Arc<RwLock<ConnectionStatus>>,

    send_vpn_outgoing: Sender<Bytes>,
    recv_vpn_incoming: Receiver<Bytes>,

    open_socks5_conn: Sender<(String, Sender<Stream>)>,

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

        let connect_status = Arc::new(RwLock::new(ConnectionStatus::Connecting));
        let ctx = TunnelCtx {
            endpoint: endpoint.clone(),
            recv_socks5_conn: recv_socks5,

            connect_status: connect_status.clone(),
            send_vpn_incoming: send_incoming,
            recv_vpn_outgoing: recv_outgoing,
            status_callback: Arc::new(status_callback),
        };
        let task = Arc::new(smolscale::spawn(tunnel_actor(ctx)));

        ClientTunnel {
            endpoint,

            send_vpn_outgoing: send_outgoing,
            recv_vpn_incoming: recv_incoming,
            open_socks5_conn: send_socks5,

            connect_status,
            _task: task,
        }
    }

    /// Returns the current connection status.
    pub fn status(&self) -> ConnectionStatus {
        self.connect_status.read().clone()
    }

    /// Returns a sosistab stream to the given remote host.
    pub async fn connect_stream(&self, remote: &str) -> anyhow::Result<Stream> {
        let (send, recv) = smol::channel::bounded(1);
        self.open_socks5_conn
            .send((remote.to_string(), send))
            .await?;
        Ok(recv.recv().await?)
    }

    pub async fn send_vpn(&self, msg: &[u8]) -> anyhow::Result<()> {
        notify_activity();
        let mangled_msg = {
            let status = self.connect_status.read();
            if let ConnectionStatus::Connected {
                protocol: _,
                address: _,
                vpn_client_ip: Some((_, nat)),
            } = status.deref()
            {
                nat.mangle_upstream_pkt(msg)
            } else {
                None
            }
        };
        if let Some(msg) = mangled_msg {
            self.send_vpn_outgoing.send(msg).await?;
        }
        Ok(())
    }

    pub async fn recv_vpn(&self) -> anyhow::Result<Bytes> {
        loop {
            let msg = self.recv_vpn_incoming.recv().await?;
            let status = self.connect_status.read();
            if let ConnectionStatus::Connected {
                protocol: _,
                address: _,
                vpn_client_ip: Some((_, nat)),
            } = status.deref()
            {
                if let Some(msg) = nat.mangle_downstream_pkt(&msg) {
                    return Ok(msg);
                }
            } else {
                anyhow::bail!(
                    "cannot processed received VPN when connection status is not connected"
                )
            }
        }
    }

    pub fn get_endpoint(&self) -> EndpointSource {
        self.endpoint.clone()
    }
}
