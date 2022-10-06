use std::process::Command;

pub fn setup_routing() {
    log::warn!("** ------------------------------------------ **");
    log::warn!("** WARNING: Currently, geph4-client in \"tun-route\" mode will exclude all traffic running with the same user ({}) as Geph **", whoami::username());
    log::warn!("** You are STRONGLY advised to create a separate user with CAP_NET_ADMIN privileges for running geph4-client! **");
    log::warn!("** ------------------------------------------ **");
    let cmd = include_str!("linux_routing_setup.sh");
    let mut child = Command::new("sh").arg("-c").arg(cmd).spawn().unwrap();
    child.wait().expect("iptables was not set up properly");
}
