use std::{process::Command, time::Duration};

use geph4_protocol::tunnel::EndpointSource;
use itertools::Itertools;
use signal_hook::iterator::Signals;

use crate::connect::{CACHED_BINDER_CLIENT, TUNNEL};

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
