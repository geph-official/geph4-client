use std::collections::HashSet;

use anyhow::Context;
use http_types::{Method, Request, Url};
use once_cell::sync::Lazy;
use std::net::{IpAddr, Ipv4Addr};
use treebitmap::IpLookupTable;

/// List of all Chinese domains.
static DOMAINS: Lazy<HashSet<String>> = Lazy::new(|| {
    let ss = include_str!("china-domains.txt");
    ss.split_ascii_whitespace()
        .filter(|v| v.len() > 1)
        .map(|v| v.to_string())
        .collect()
});

static IPLOOKUP: Lazy<IpLookupTable<Ipv4Addr, ()>> = Lazy::new(|| {
    let ss = include_str!("china-ips.txt");
    let mut toret = IpLookupTable::new();
    for line in ss.split_ascii_whitespace() {
        let vv: Vec<_> = line.split('/').collect();
        let ip: Ipv4Addr = vv[0].parse().unwrap();
        let plen: u32 = vv[1].parse().unwrap();
        toret.insert(ip, plen, ());
    }
    toret
});

/// Returns true if the given IP is Chinese
pub fn is_chinese_ip(ip: Ipv4Addr) -> bool {
    IPLOOKUP.longest_match(ip).is_some()
}

/// Returns true if the given host is Chinese
pub fn is_chinese_host(host: &str) -> bool {
    // explode by dots
    let exploded: Vec<_> = host.split('.').collect();
    // join & lookup in loop
    for i in 0..exploded.len() {
        let candidate = (exploded[i..]).join(".");
        if DOMAINS.contains(&candidate) {
            return true;
        }
    }
    false
}

/// Returns whether or not we're in China.
#[cached::proc_macro::cached(result = true)]
pub async fn test_china() -> http_types::Result<bool> {
    let req = Request::new(
        Method::Get,
        Url::parse("http://checkip.amazonaws.com").unwrap(),
    );
    let connect_to = geph4_aioutils::resolve("checkip.amazonaws.com:80").await?;

    let response = {
        let connection =
            smol::net::TcpStream::connect(connect_to.first().context("no addrs for checkip")?)
                .await?;
        async_h1::connect(connection, req)
            .await?
            .body_string()
            .await?
    };
    let response = response.trim();
    let parsed: IpAddr = response.parse()?;
    match parsed {
        IpAddr::V4(inner) => Ok(is_chinese_ip(inner)),
        IpAddr::V6(_) => Err(anyhow::anyhow!("cannot tell for ipv6").into()),
    }
}
