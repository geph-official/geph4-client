use async_dup::Arc;
use async_net::SocketAddr;
use async_tls::{client::TlsStream, TlsConnector};
use smol::{
    channel::{Receiver, Sender},
    prelude::*,
};
use smol_timeout::TimeoutExt;
use sosistab::mux::RelConn;
use std::time::Duration;

use crate::kalive::Keepalive;

/// Handle DNS requests from localhost
pub async fn dns_loop(addr: SocketAddr, keepalive: Keepalive) -> anyhow::Result<()> {
    let socket = smol::net::UdpSocket::bind(addr).await?;
    let mut buf = [0; 2048];
    let pool = Arc::new(DnsPool::new(keepalive));
    log::debug!("DNS loop started");
    loop {
        let (n, c_addr) = socket.recv_from(&mut buf).await?;
        let buff = buf[..n].to_vec();
        let socket = socket.clone();
        let pool = pool.clone();
        smolscale::spawn(async move {
            let fut = || async {
                socket
                    .send_to(&pool.request(&buff).await?, c_addr)
                    .await
                    .ok()?;
                Some(())
            };
            for _ in 0u32..5 {
                if fut().await.is_some() {
                    return;
                }
            }
        })
        .detach();
    }
}

/// A DNS connection pool
pub struct DnsPool {
    send_conn: Sender<TlsStream<RelConn>>,
    recv_conn: Receiver<TlsStream<RelConn>>,
    keepalive: Keepalive,
}

impl DnsPool {
    /// Create a new pool based on a Keepalive
    pub fn new(keepalive: Keepalive) -> Self {
        let (send_conn, recv_conn) = smol::channel::unbounded();
        Self {
            send_conn,
            recv_conn,
            keepalive,
        }
    }

    /// Do a DNS request.
    pub async fn request(&self, buff: &[u8]) -> Option<Vec<u8>> {
        let dns_timeout = Duration::from_secs(10);
        let mut conn = {
            let lala = self.recv_conn.try_recv();
            match lala {
                Ok(v) => v,
                _ => {
                    let tcp_conn = self
                        .keepalive
                        .connect("1.0.0.1:853")
                        .timeout(dns_timeout)
                        .await?
                        .ok()?;
                    TlsConnector::default()
                        .connect("cloudflare-dns.com", tcp_conn)
                        .await
                        .ok()?
                }
            }
        };
        conn.write_all(&(buff.len() as u16).to_be_bytes())
            .timeout(dns_timeout)
            .await?
            .ok()?;
        conn.write_all(&buff).timeout(dns_timeout).await?.ok()?;
        conn.flush().timeout(dns_timeout).await?.ok()?;
        let mut n_buf = [0; 2];
        conn.read_exact(&mut n_buf)
            .timeout(dns_timeout)
            .await?
            .ok()?;
        let mut true_buf = vec![0u8; u16::from_be_bytes(n_buf) as usize];
        conn.read_exact(&mut true_buf)
            .timeout(dns_timeout)
            .await?
            .ok()?;
        self.send_conn.try_send(conn).unwrap();
        Some(true_buf)
    }
}
