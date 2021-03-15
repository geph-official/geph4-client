use std::net::SocketAddr;

/// Resolves a string into a vector of SocketAddrs.
#[cfg(target_os = "windows")]
pub async fn resolve(host_port: &str) -> std::io::Result<Vec<SocketAddr>> {
    use dnsclient::{r#async::DNSClient, UpstreamServer};
    log::warn!("using custom DNS implementation to resolve {}", host_port);
    let exploded: Vec<&str> = host_port.split(':').collect();
    let port: u16 = exploded
        .get(1)
        .cloned()
        .ok_or_else(|| crate::to_ioerror("no port in address"))?
        .parse()
        .map_err(crate::to_ioerror)?;
    let resolver = DNSClient::new(vec![
        UpstreamServer::new("1.1.1.1:53".parse::<SocketAddr>().unwrap()),
        UpstreamServer::new("9.9.9.9:53".parse::<SocketAddr>().unwrap()),
        UpstreamServer::new("74.82.42.42:53".parse::<SocketAddr>().unwrap()),
        UpstreamServer::new("114.114.114.114:53".parse::<SocketAddr>().unwrap()),
    ]);
    let result = resolver
        .query_a(exploded[0])
        .await
        .map_err(crate::to_ioerror)?;
    Ok(result
        .into_iter()
        .map(|ip| SocketAddr::new(ip.into(), port))
        .collect())
}

#[cfg(not(target_os = "windows"))]
pub async fn resolve(host_port: &str) -> std::io::Result<Vec<SocketAddr>> {
    resolve_inner(host_port.into()).await
}

pub async fn resolve_inner(host_port: String) -> std::io::Result<Vec<SocketAddr>> {
    smol::net::resolve(host_port).await
}
