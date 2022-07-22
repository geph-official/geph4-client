use async_net::Ipv4Addr;
use geph4_protocol::VpnMessage;
pub struct Nat {
    map: RwLock<HashMap<Ipv4Addr, Ipv4Addr>>,
}

impl Nat {
    pub fn mangle_upstream_pkt(&mut self, msg: VpnMessage) -> VpnMessage {
        todo!()
    }

    pub fn mangle_downstream_pkt(&mut self, msg: VpnMessage) -> VpnMessage {
        todo!()
    }
}
