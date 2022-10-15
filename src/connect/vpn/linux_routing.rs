use std::{process::Command, time::Duration};

use async_net::Ipv4Addr;
use itertools::Itertools;
use signal_hook::iterator::Signals;

use crate::connect::{CONNECT_CONFIG, TUNNEL};

pub fn setup_routing() {
    std::thread::spawn(|| {
        while !TUNNEL.is_connected() {
            log::debug!("waiting for tunnel to connect...");
            std::thread::sleep(Duration::from_secs(1));
        }
        log::warn!("** ------------------------------------------ **");
        log::warn!("** WARNING: Currently, geph4-client in \"tun-route\" mode will exclude all traffic running with the same user ({}) as Geph **", whoami::username());
        log::warn!("** You are STRONGLY advised to create a separate user with CAP_NET_ADMIN privileges for running geph4-client! **");
        log::warn!("** ------------------------------------------ **");
        // set the DNS server
        let mut dns_listen = CONNECT_CONFIG.dns_listen;
        dns_listen.set_ip(Ipv4Addr::new(127, 0, 0, 1).into());
        std::env::set_var("GEPH_DNS", dns_listen.to_string());
        let cmd = include_str!("linux_routing_setup.sh");
        let mut child = Command::new("sh").arg("-c").arg(cmd).spawn().unwrap();
        child.wait().expect("iptables was not set up properly");
        // teardown process
        let mut signals = Signals::new(&[libc::SIGABRT, libc::SIGTERM, libc::SIGINT])
            .expect("did not register signal handler properly");
        std::thread::spawn(move || {
            for _ in signals.forever() {
                teardown_routing();
                std::process::exit(-1)
            }
        });
        unsafe {
            libc::atexit(teardown_routing);
        }
    });
}

extern "C" fn teardown_routing() {
    log::debug!("teardown_routing starting!");
    let cmd = include_str!("linux_routing_setup.sh")
        .lines()
        .filter(|l| l.contains("-D") || l.contains("del"))
        .join("\n");
    let mut child = Command::new("sh").arg("-c").arg(cmd).spawn().unwrap();
    child.wait().expect("iptables was not set up properly");
}
