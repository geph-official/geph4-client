use anyhow::Context;
use smol::future::FutureExt;

use super::ConnectContext;
use crate::config::VpnMode;

#[cfg(target_os = "linux")]
mod linux_routing;

#[cfg(target_os = "windows")]
mod windows_routing;

#[cfg(unix)]
use std::os::unix::prelude::FromRawFd;

pub(super) async fn vpn_loop(ctx: ConnectContext) -> anyhow::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if ctx.opt.vpn_mode == Some(VpnMode::InheritedFd) {
        let fd_num: i32 = std::env::var("GEPH_VPN_FD")
            .ok()
            .and_then(|e| e.parse().ok())
            .expect("must set GEPH_VPN_FD to a file descriptor in order to use inherited-fd mode");
        return unsafe { fd_vpn_loop(ctx, fd_num).await };
    }

    #[cfg(target_os = "windows")]
    if ctx.opt.vpn_mode == Some(VpnMode::WinDivert) {
        return windows_routing::start_routing(ctx).await;
    }

    smol::future::pending().await
}

#[cfg(any(target_os = "linux", target_os = "android"))]
async unsafe fn fd_vpn_loop(ctx: ConnectContext, fd_num: i32) -> anyhow::Result<()> {
    log::info!("entering fd_vpn_loop");

    use futures_util::{AsyncReadExt, AsyncWriteExt};

    let mut up_file = async_dup::Arc::new(async_dup::Mutex::new(
        smol::Async::new(std::fs::File::from_raw_fd(fd_num)).context("cannot init up_file")?,
    ));

    let mut dn_file = up_file.clone();

    let up_loop = async {
        let mut bts = vec![0; 65536];
        loop {
            let n = up_file.read(&mut bts).await?;

            ctx.tunnel.send_vpn(&bts[..n]).await?;
        }
    };
    let dn_loop = async {
        loop {
            let bts = ctx.tunnel.recv_vpn().await?;
            dn_file.write_all(&bts).await?;
        }
    };
    up_loop.race(dn_loop).await
}
