use anyhow::Context;
use futures_util::{
    io::{BufReader, BufWriter},
    AsyncReadExt, AsyncWriteExt,
};
use smol::future::FutureExt;

use super::ConnectContext;
use crate::config::VpnMode;

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

    if ctx.opt.vpn_mode == Some(VpnMode::Stdio) {
        return stdio_vpn_loop(ctx).await;
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

async fn stdio_vpn_loop(ctx: ConnectContext) -> anyhow::Result<()> {
    let (stdin, stdout) = (
        smol::Unblock::new(std::io::stdin()),
        smol::Unblock::new(std::io::stdout()),
    );
    let mut stdin = BufReader::new(stdin);
    let mut stdout = BufWriter::new(stdout);

    // The upload task
    let tunnel = ctx.tunnel.clone();
    let upload_task = async {
        loop {
            let mut len_bytes = [0u8; 2];
            stdin.read_exact(&mut len_bytes).await?;
            let len = u16::from_le_bytes(len_bytes) as usize;

            let mut buffer = vec![0u8; len];
            stdin.read_exact(&mut buffer).await?;
            tunnel.send_vpn(&buffer).await?;
        }
    };

    // Download task
    let download_task = async {
        loop {
            let down_pkt = ctx.tunnel.recv_vpn().await?;
            let len_bytes = (down_pkt.len() as u16).to_le_bytes();
            stdout.write_all(&len_bytes).await?;
            stdout.write_all(&down_pkt).await?;
            stdout.flush().await?;
        }
    };

    download_task.race(upload_task).await
}
