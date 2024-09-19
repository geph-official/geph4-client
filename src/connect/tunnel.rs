use bytes::Bytes;

use derivative::Derivative;
use geph5_broker_protocol::Credential;
use geph5_client::{BridgeMode, ExitConstraint};

use sillad::Pipe;
use smol::Task;
use smol_str::SmolStr;
use std::{
    sync::atomic::Ordering,
    time::{Duration, SystemTime},
};
use stdcode::StdcodeSerializeExt;
use tmelcrypt::Hashable;

use crate::{
    config::{ConnectOpt, GEPH5_CONFIG_TEMPLATE},
    connect::stats::{STATS_RECV_BYTES, STATS_SEND_BYTES},
};

use super::stats::{gatherer::StatItem, STATS_GATHERER};

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
    _stat_reporter: Task<()>,
}

impl ClientTunnel {
    /// Creates a new ClientTunnel.
    pub fn new(opt: ConnectOpt) -> Self {
        let (username, password) = match &opt.auth.auth_kind {
            Some(crate::config::AuthKind::AuthPassword { username, password }) => {
                (username.clone(), password.clone())
            }
            _ => todo!(),
        };
        let mut config = GEPH5_CONFIG_TEMPLATE.clone();
        config.credentials = Credential::LegacyUsernamePassword { username, password };
        config.bridge_mode = if opt.use_bridges {
            BridgeMode::ForceBridges
        } else {
            BridgeMode::Auto
        };
        config.cache = Some(
            opt.auth
                .credential_cache
                .clone()
                .join(format!("cache-{}.db", opt.auth.stdcode().hash())),
        );
        if let Some(exit) = opt.exit_server {
            config.exit_constraint = ExitConstraint::Hostname(exit);
        }

        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            if opt.vpn_mode.is_some() {
                config.vpn = true;
            }
        }

        log::debug!("cache path: {:?}", config.cache);
        let client = geph5_client::Client::start(config);
        let handle = client.control_client();
        let stat_reporter = smolscale::spawn(async move {
            loop {
                smol::Timer::after(Duration::from_secs(1)).await;
                let info = handle.conn_info().await.unwrap();
                let recv_bytes = handle.stat_num("total_rx_bytes".into()).await.unwrap();
                let send_bytes = handle.stat_num("total_tx_bytes".into()).await.unwrap();
                STATS_RECV_BYTES.store(recv_bytes as _, Ordering::Relaxed);
                STATS_SEND_BYTES.store(send_bytes as _, Ordering::Relaxed);
                match info {
                    geph5_client::ConnInfo::Connecting => {}
                    geph5_client::ConnInfo::Connected(conn) => STATS_GATHERER.push(StatItem {
                        time: SystemTime::now(),
                        endpoint: conn.bridge.into(),
                        protocol: conn.protocol.into(),
                        ping: Duration::from_secs_f64(
                            handle.stat_num("ping".into()).await.unwrap(),
                        ),
                        send_bytes: send_bytes as u64,
                        recv_bytes: recv_bytes as u64,
                    }),
                }
            }
        });
        Self {
            client,
            _stat_reporter: stat_reporter,
        }
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
