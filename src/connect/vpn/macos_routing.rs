use std::time::Duration;

use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::net::IpAddr;

use crate::connect::TUNNEL;

static WHITELIST: Lazy<DashMap<IpAddr, smol::Task<()>>> = Lazy::new(DashMap::new);
pub fn setup_routing(tun_name: &str) {
    while !TUNNEL.status().connected() {
        log::debug!("waiting for connection before routing things through VPN...");
        std::thread::sleep(Duration::from_secs(1));
    }
    // Do the actual routing
    log::info!("forcing traffic through VPN!");
    let uname = whoami::username();
    let interface = default_net::get_default_interface().expect("cannot get default interface");
    let iname = interface.name;
    std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "echo \"pass out quick on {iname} route-to {tun_name} user != {uname}\" | pfctl -ef -"
        ))
        .status()
        .expect("could not run pfctl");
}
