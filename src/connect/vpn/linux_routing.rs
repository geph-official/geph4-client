use std::{process::Command, time::Duration};

use crate::connect::ConnectContext;
use anyhow::Context;
use async_signal::{Signal, Signals};
use clone_macro::clone;
use dashmap::DashMap;
use itertools::Itertools;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use smol::stream::StreamExt;

use std::net::IpAddr;

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

static LOCK: smol::lock::Mutex<()> = smol::lock::Mutex::new(());

pub(super) async fn routing_loop(ctx: ConnectContext) -> anyhow::Result<()> {
    let _lock = LOCK
        .try_lock()
        .expect("only one VPN instance can run at the same");

    // first whitelist all
    log::debug!("whitelisting all");
    whitelist_once(&ctx).await?;

    // then spawn a background task to continually whitelist
    let _bg_whitelist = smolscale::spawn(clone!([ctx], async move {
        loop {
            let _ = whitelist_once(&ctx).await;
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    }));

    // then wait for connection to become fully functional
    log::debug!("waiting for tunnel to become fully functional");
    ctx.tunnel.connect_stream("1.1.1.1:53").await?;

    // setup routing
    // redirect DNS to 1.1.1.1
    log::debug!("setting up VPN routing");
    std::env::set_var("GEPH_DNS", "1.1.1.1:53");
    let cmd = include_str!("linux_routing_setup.sh");
    let mut child = smol::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .spawn()
        .unwrap();
    child
        .status()
        .await
        .context("iptables was not set up properly")?;

    unsafe {
        libc::atexit(teardown_routing);
    }

    scopeguard::defer!(teardown_routing());

    let mut signals = Signals::new([Signal::Term, Signal::Quit, Signal::Int])
        .context("did not register signal handler properly")?;

    while let Some(_signal) = signals.next().await {
        teardown_routing();
        std::process::exit(-1)
    }

    Ok(())
}

async fn whitelist_once(ctx: &ConnectContext) -> anyhow::Result<()> {
    let bridge = ctx.conn_info.bridges().await?;
    for bridge in bridge {
        let addr = bridge.endpoint.ip();
        WHITELIST.entry(addr).or_insert_with(move || {
            log::debug!("making whitelist entry for {}", addr);
            SingleWhitelister::new(addr)
        });
    }
    Ok(())
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
