use std::collections::HashSet;

use async_net::Ipv4Addr;
use once_cell::sync::Lazy;
use regex::{Regex, RegexBuilder};
use treebitmap::IpLookupTable;

/// Regex that matches all Chinese domains.
static DOMAINS: Lazy<HashSet<String>> = Lazy::new(|| {
    let ss = include_str!("china-domains.txt");
    ss.split('\n')
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
        let candidate = (&exploded[i..]).join(".");
        if DOMAINS.contains(&candidate) {
            return true;
        }
    }
    false
}
