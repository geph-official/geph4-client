use std::{sync::atomic::Ordering, time::Duration};

use anyhow::Context;
use futures_util::TryFutureExt;
use psl::Psl;
use smol_timeout::TimeoutExt;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::{
    china,
    connect::{
        stats::{STATS_RECV_BYTES, STATS_SEND_BYTES},
        tunnel::activity::notify_activity,
        TUNNEL,
    },
};

/// Handles a socks5 client from localhost
async fn handle_socks5(s5client: smol::net::TcpStream, exclude_prc: bool) -> anyhow::Result<()> {
    s5client.set_nodelay(true)?;
    use socksv5::v5::*;
    let _handshake = read_handshake(s5client.clone()).await?;
    write_auth_method(s5client.clone(), SocksV5AuthMethod::Noauth).await?;
    let request = read_request(s5client.clone()).await?;
    let port = request.port;
    let v4addr: Option<Ipv4Addr>;
    let addr: String = match &request.host {
        SocksV5Host::Domain(dom) => {
            v4addr = String::from_utf8_lossy(dom).parse().ok();
            format!("{}:{}", String::from_utf8_lossy(dom), request.port)
        }
        SocksV5Host::Ipv4(v4) => {
            let v4addr_inner = Ipv4Addr::new(v4[0], v4[1], v4[2], v4[3]);
            SocketAddr::V4(SocketAddrV4::new(
                {
                    v4addr = Some(v4addr_inner);
                    v4addr.unwrap()
                },
                request.port,
            ))
            .to_string()
        }
        _ => anyhow::bail!("not supported"),
    };

    let is_private = if let Some(v4addr) = v4addr {
        v4addr.is_private() || v4addr.is_loopback()
    } else {
        !psl::List
            .suffix(addr.split(':').next().unwrap().as_bytes())
            .map(|suf| suf.typ().is_some())
            .unwrap_or_default()
    };

    // true if the connection should not go through geph
    let must_direct = is_private
        || (exclude_prc
            && (china::is_chinese_host(addr.split(':').next().unwrap())
                || v4addr.map(china::is_chinese_ip).unwrap_or(false)));
    if must_direct {
        log::debug!("bypassing {}", addr);
        let conn = smol::net::TcpStream::connect(&addr).await?;
        write_request_status(
            s5client.clone(),
            SocksV5RequestStatus::Success,
            request.host,
            port,
        )
        .await?;
        smol::future::race(
            geph4_aioutils::copy_with_stats(conn.clone(), s5client.clone(), |_| ()),
            geph4_aioutils::copy_with_stats(s5client.clone(), conn.clone(), |_| ()),
        )
        .await?;
    } else {
        let conn = TUNNEL
            .connect_stream(&addr)
            .timeout(Duration::from_secs(120))
            .await
            .context("open connection timeout")??;
        write_request_status(
            s5client.clone(),
            SocksV5RequestStatus::Success,
            request.host,
            port,
        )
        .await?;
        smol::future::race(
            geph4_aioutils::copy_with_stats(conn.clone(), s5client.clone(), |n| {
                STATS_RECV_BYTES.fetch_add(n as u64, Ordering::Relaxed);
                notify_activity();
            }),
            geph4_aioutils::copy_with_stats(s5client, conn, |n| {
                STATS_SEND_BYTES.fetch_add(n as u64, Ordering::Relaxed);
                notify_activity();
            }),
        )
        .await?;
    }
    Ok(())
}

pub async fn socks5_loop(socks5_listen: SocketAddr, exclude_prc: bool) -> anyhow::Result<()> {
    let socks5_listener = smol::net::TcpListener::bind(socks5_listen)
        .await
        .context("cannot bind socks5")?;
    log::debug!("socks5 started");
    loop {
        let (s5client, _) = socks5_listener
            .accept()
            .await
            .context("cannot accept socks5")?;

        smolscale::spawn(
            async move { handle_socks5(s5client, exclude_prc).await }
                .map_err(|e| log::debug!("socks5 died with: {:?}", e)),
        )
        .detach()
    }
}
