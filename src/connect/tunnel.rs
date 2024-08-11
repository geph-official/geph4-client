use bytes::Bytes;

use derivative::Derivative;
use geph5_broker_protocol::Credential;
use geph5_client::{BridgeMode, BrokerSource, Config};
use geph_nat::GephNat;
use parking_lot::RwLock;

use sillad::Pipe;
use smol::channel::{Receiver, Sender};
use smol_str::SmolStr;
use std::net::SocketAddr;

use sosistab2::Stream;
use std::sync::Arc;

use std::net::Ipv4Addr;

use crate::{config::ConnectOpt, conninfo_store::ConnInfoStore};

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
}

/// A ConnectionStatus shows the status of the tunnel.
#[derive(Clone, Derivative)]
#[derivative(Debug)]
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
    client: geph5_client::Client,
}

impl ClientTunnel {
    /// Creates a new ClientTunnel.
    pub fn new(opt: ConnectOpt) -> Self {
        let (username, password) = match opt.auth.auth_kind {
            Some(crate::config::AuthKind::AuthPassword { username, password }) => {
                (username, password)
            }
            _ => todo!(),
        };
        let client = geph5_client::Client::start(Config {
            socks5_listen: None,
            http_proxy_listen: None,

            control_listen: None,
            exit_constraint: geph5_client::ExitConstraint::Auto,
            bridge_mode: if opt.use_bridges {
                BridgeMode::ForceBridges
            } else {
                BridgeMode::Auto
            },
            cache: None,
            broker: Some(BrokerSource::Fronted {
                front: "https://vuejs.org".into(),
                host: "svitania-naidallszei-2.netlify.app".into(),
            }),
            vpn: false,
            spoof_dns: true,
            passthrough_china: false,
            dry_run: false,
            credentials: Credential::LegacyUsernamePassword { username, password },
        });
        Self { client }
    }

    /// Returns the current connection status.
    pub async fn status(&self) -> ConnectionStatus {
        let conn_info = self.client.control_client().conn_info().await.unwrap();
        match conn_info {
            geph5_client::ConnInfo::Connecting => ConnectionStatus::Connecting,
            geph5_client::ConnInfo::Connected(info) => ConnectionStatus::Connected {
                protocol: info.protocol.into(),
                address: info.bridge.into(),
            },
        }
    }

    /// Returns a sosistab stream to the given remote host.
    pub async fn connect_stream(&self, remote: &str) -> anyhow::Result<Box<dyn Pipe>> {
        self.client.open_conn(remote).await
    }

    pub async fn send_vpn(&self, msg: &[u8]) -> anyhow::Result<()> {
        self.client.send_vpn_packet(msg.to_vec().into()).await
    }

    pub async fn recv_vpn(&self) -> anyhow::Result<Bytes> {
        self.client.recv_vpn_packet().await
    }
}
