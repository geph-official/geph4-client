use std::time::Duration;

use async_net::IpAddr;
use dashmap::DashMap;
use default_net::Interface;
use geph4_protocol::tunnel::TunnelStatus;
use once_cell::sync::Lazy;

use crate::connect::{TUNNEL, TUNNEL_STATUS_CALLBACK};

static WHITELIST: Lazy<DashMap<IpAddr, smol::Task<()>>> = Lazy::new(DashMap::new);

// Adds the given destination to the whitelist of destinations that do NOT go through Geph
fn add_once(real_tun_name: &str, gateway: IpAddr, dest: IpAddr) -> anyhow::Result<()> {
    // TODO this is totally incapable of handling ipv6
    log::debug!("*actually* whitelisting {}", dest);

    std::process::Command::new("/sbin/route")
        .arg("add")
        .arg("-host")
        .arg(dest.to_string())
        .arg("-interface")
        .arg(real_tun_name)
        .status()?;
    Ok(())
}

pub fn setup_routing(tun_name: &str) {
    let tun_name = tun_name.to_string();
    *TUNNEL_STATUS_CALLBACK.write() = Box::new(move |addr| {
        if let TunnelStatus::PreConnect { addr, protocol: _ } = addr {
            let addr = addr.ip();
            log::debug!("adding {addr} to the whitelist");
            WHITELIST.insert(
                addr,
                smolscale::spawn(async move {
                    match default_net::get_default_interface() {
                        Ok(default_interface) => {
                            log::debug!(
                                "the current default interface is: {}",
                                default_interface.name
                            );
                            loop {
                                // add the route once
                                if let Some(gateway) = default_interface.gateway.clone() {
                                    add_once(&default_interface.name, gateway.ip_addr, addr);
                                }

                                smol::Timer::after(Duration::from_secs(10)).await;
                            }
                        }
                        Err(err) => {
                            log::error!("no default interface: {}", err)
                        }
                    }
                }),
            );
        }
    });
    while !TUNNEL.is_connected() {
        log::debug!("waiting for connection before routing things through VPN...");
        std::thread::sleep(Duration::from_secs(1));
    }
    // Do the actual routing
    log::info!("forcing traffic through VPN!");
    std::process::Command::new("/sbin/route")
        .arg("add")
        .arg("0.0.0.0/1")
        .arg("-interface")
        .arg(&tun_name)
        .status()
        .unwrap();
    std::process::Command::new("/sbin/route")
        .arg("add")
        .arg("128.0.0.0/1")
        .arg("-interface")
        .arg(&tun_name)
        .status()
        .unwrap();
}
