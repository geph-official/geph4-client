use std::{process::Command, time::Duration};

use crate::{config::CacheStaleGuard, connect::tunnel::TunnelStatus};
use dashmap::DashMap;
use itertools::Itertools;
use once_cell::sync::Lazy;
use signal_hook::iterator::Signals;
use std::net::{IpAddr, Ipv4Addr};

use crate::connect::{CONNECT_CONFIG, TUNNEL, TUNNEL_STATUS_CALLBACK};

struct SingleWhitelister {
    dest: IpAddr,
}

impl Drop for SingleWhitelister {
    fn drop(&mut self) {
        log::debug!("DROPPING whitelist to {}", self.dest);
        Command::new("sh")
            .arg("-c")
            .arg(format!(
                "/usr/bin/env ip rule del to {} lookup main pref 1",
                self.dest
            ))
            .status()
            .expect("cannot run iptables");
    }
}

impl SingleWhitelister {
    fn new(dest: IpAddr) -> Self {
        Command::new("sh")
            .arg("-c")
            .arg(format!(
                "/usr/bin/env ip rule add to {} lookup main pref 1",
                dest
            ))
            .status()
            .expect("cannot run iptables");
        Self { dest }
    }
}

static WHITELIST: Lazy<DashMap<IpAddr, SingleWhitelister>> = Lazy::new(DashMap::new);

pub fn setup_routing() {
    std::thread::spawn(|| {
        *TUNNEL_STATUS_CALLBACK.write() = Box::new(|status| {
            if let TunnelStatus::PreConnect { addr, protocol: _ } = status {
                WHITELIST.entry(addr.ip()).or_insert_with(move || {
                    log::debug!("making whitelist entry for {}", addr);
                    SingleWhitelister::new(addr.ip())
                });
            }
        });

        while !TUNNEL.status().connected() {
            log::debug!("waiting for tunnel to connect...");
            std::thread::sleep(Duration::from_secs(1));
        }

        let _stale_guard = CacheStaleGuard::new();

        // set the DNS server
        let mut dns_listen = CONNECT_CONFIG.dns_listen;
        dns_listen.set_ip(Ipv4Addr::new(127, 0, 0, 1).into());
        std::env::set_var("GEPH_DNS", dns_listen.to_string());
        let cmd = include_str!("linux_routing_setup.sh");
        let mut child = Command::new("sh").arg("-c").arg(cmd).spawn().unwrap();
        child.wait().expect("iptables was not set up properly");
        unsafe {
            libc::atexit(teardown_routing);
        }
        // teardown process
        let mut signals = Signals::new([libc::SIGABRT, libc::SIGTERM, libc::SIGINT])
            .expect("did not register signal handler properly");
        for _ in signals.forever() {
            teardown_routing();
            std::process::exit(-1)
        }
    });
}

extern "C" fn teardown_routing() {
    log::debug!("teardown_routing starting!");
    WHITELIST.clear();
    let cmd = include_str!("linux_routing_setup.sh")
        .lines()
        .filter(|l| l.contains("-D") || l.contains("del") || l.contains("flush"))
        .join("\n");
    let mut child = Command::new("sh").arg("-c").arg(cmd).spawn().unwrap();
    child.wait().expect("iptables was not set up properly");
}
