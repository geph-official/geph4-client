mod address;
mod consts;
mod http_client;
mod http_local;
mod socks5;
use std::net::SocketAddr;

pub async fn run_tokio(
    local_listen_addr: SocketAddr,
    proxy_address: SocketAddr,
) -> anyhow::Result<()> {
    http_local::run(local_listen_addr, proxy_address).await?;
    Ok(())
}
