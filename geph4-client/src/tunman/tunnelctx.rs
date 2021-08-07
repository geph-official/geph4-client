use std::sync::Arc;

use geph4_binder_transport::ExitDescriptor;
use parking_lot::RwLock;
use smol::channel::{Receiver, Sender};

use crate::{cache::ClientCache, main_connect::ConnectOpt};

use super::TunnelState;

/// TunnelCtx encapsulates all the context needed for running a tunnel
#[derive(Clone)]
pub struct TunnelCtx {
    pub opt: ConnectOpt,
    pub ccache: Arc<ClientCache>,
    pub recv_socks5_conn: Receiver<(String, Sender<sosistab::RelConn>)>,
    pub current_state: Arc<RwLock<TunnelState>>,
    pub selected_exit: ExitDescriptor,
}
