use std::{
    path::PathBuf,
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::fronts::parse_fronts;
use bytes::Bytes;
use geph4_protocol::binder::client::{CachedBinderClient, DynBinderClient};
use geph4_protocol::binder::protocol::BinderClient;
use once_cell::sync::{Lazy, OnceCell};

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use structopt::StructOpt;

static INIT_CONFIG: OnceCell<Opt> = OnceCell::new();

/// Must be called *before* CONFIG is ever referenced
pub fn override_config(opt: Opt) {
    INIT_CONFIG.get_or_init(|| opt);
}

/// The global configuration of the client.
pub static CONFIG: Lazy<Opt> = Lazy::new(|| INIT_CONFIG.get_or_init(Opt::from_args).clone());

#[derive(Debug, StructOpt, Deserialize, Serialize, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Opt {
    Connect(ConnectOpt),
    BridgeTest(crate::main_bridgetest::BridgeTestOpt),
    Sync(crate::sync::SyncOpt),
    BinderProxy(crate::binderproxy::BinderProxyOpt),
    Debugpack(crate::debugpack::DebugPackOpt),
}

#[derive(Debug, StructOpt, Clone, Deserialize, Serialize)]
pub struct ConnectOpt {
    #[structopt(flatten)]
    pub common: CommonOpt,

    #[structopt(flatten)]
    pub auth: AuthOpt,

    #[structopt(long)]
    /// Whether or not to use bridges
    pub use_bridges: bool,

    #[structopt(long)]
    /// Overrides everything else, forcing connection to a particular sosistab URL (of the form pk@host:port). This also disables any form of authentication.
    pub override_connect: Option<String>,

    #[structopt(long)]
    /// Force a particular bridge
    pub force_bridge: Option<Ipv4Addr>,

    #[structopt(long, default_value = "1")]
    /// Number of local UDP ports to use per session. This works around situations where unlucky ECMP routing sends flows down a congested path even when other paths exist, by "averaging out" all the possible routes.
    pub udp_shard_count: usize,

    #[structopt(long, default_value = "30")]
    /// Lifetime of a single UDP port. Geph will switch to a different port within this many seconds.
    pub udp_shard_lifetime: u64,

    #[structopt(long, default_value = "2")]
    /// Number of TCP connections to use per session. This works around lossy links, per-connection rate limiting, etc.
    pub tcp_shard_count: usize,

    #[structopt(long, default_value = "10")]
    /// Lifetime of a single TCP connection. Geph will switch to a different TCP connection within this many seconds.
    pub tcp_shard_lifetime: u64,

    #[structopt(long, default_value = "127.0.0.1:9910")]
    /// Where to listen for HTTP proxy connections
    pub http_listen: SocketAddr,
    #[structopt(long, default_value = "127.0.0.1:9909")]
    /// Where to listen for SOCKS5 connections
    pub socks5_listen: SocketAddr,
    #[structopt(long, default_value = "127.0.0.1:9809")]
    /// Where to listen for REST-based local connections
    pub stats_listen: SocketAddr,

    #[structopt(long, default_value = "127.0.0.1:15353")]
    /// Where to listen for proxied DNS requests.
    pub dns_listen: SocketAddr,

    #[structopt(long)]
    /// Which exit server to connect to. If there isn't an exact match, the exit server with the most similar hostname is picked. If not given, a random server will be selected.
    pub exit_server: Option<String>,

    #[structopt(long)]
    /// Whether or not to exclude PRC domains
    pub exclude_prc: bool,

    #[structopt(long)]
    /// Whether or not to wait for VPN commands on stdio
    pub stdio_vpn: bool,

    #[structopt(long)]
    /// Whether or not to stick to the same set of bridges
    pub sticky_bridges: bool,

    #[structopt(long)]
    /// Specify whether and how to create a L3 VPN tunnel. Possible options are:
    /// - nothing (no VPN)
    /// - "inherited-fd" (reads a TUN device file descriptor number, inherited from the parent process, from the GEPH_VPN_FD environment variable)
    /// - "tun-no-route" (Unix only; creates and configures a TUN device named "tun-geph", but does not change the routing table)
    /// - "tun-route" (Unix only; creates and configures a TUN device, as well as executing platform-specific actions to force all non-Geph traffic through the tunnel)
    /// - "windivert" (Windows only; uses WinDivert to capture non-Geph traffic to feed into the VPN)
    pub vpn_mode: Option<VpnMode>,

    #[structopt(long)]
    /// Forces the protocol selected to match the given regex.
    pub force_protocol: Option<String>,

    #[structopt(long)]
    /// SSH-style local-remote port forwarding. For example, "0.0.0.0:8888:::example.com:22" will forward local port 8888 to example.com:22. Must be in form host:port:::host:port! May have multiple ones.
    pub forward_ports: Vec<String>,
}

/// An enum represennting the various VPN modes.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq, Hash, Serialize, Deserialize)]
pub enum VpnMode {
    InheritedFd,
    TunNoRoute,
    TunRoute,
    WinDivert,
    Stdio,
}

impl FromStr for VpnMode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "inherited-fd" => Ok(Self::InheritedFd),
            "tun-no-route" => Ok(Self::TunNoRoute),
            "tun-route" => Ok(Self::TunRoute),
            "windivert" => Ok(Self::WinDivert),
            "stdio" => Ok(Self::Stdio),

            x => anyhow::bail!("unrecognized VPN mode {}", x),
        }
    }
}

#[derive(Debug, StructOpt, Clone, Deserialize, Serialize)]
pub struct CommonOpt {
    #[structopt(
        long,
        default_value = "https://www.netlify.com/v4/next-gen,https://vuejs.org/v4/next-gen,https://www.cdn77.com/next-gen,https://ajax.aspnetcdn.com/next-gen,https://dtnins2n354c4.cloudfront.net/v4/next-gen"
    )]
    /// HTTP(S) address of the binder, FRONTED
    binder_http_fronts: String,

    #[structopt(
        long,
        default_value = "svitania-naidallszei.netlify.app,svitania-naidallszei.netlify.app,1049933718.rsc.cdn77.org,gephbinder-4.azureedge.net,dtnins2n354c4.cloudfront.net"
    )]
    /// HTTP(S) actual host of the binder
    binder_http_hosts: String,

    #[structopt(
        long,
        default_value = "124526f4e692b589511369687498cce57492bf4da20f8d26019c1cc0c80b6e4b",
        parse(from_str = str_to_x25519_pk)
    )]
    /// x25519 master key of the binder
    binder_master: x25519_dalek::PublicKey,

    #[structopt(
        long,
        default_value = "4e01116de3721cc702f4c260977f4a1809194e9d3df803e17bb90db2a425e5ee",
        parse(from_str = str_to_mizaru_pk)
    )]
    /// mizaru master key of the binder, for FREE
    binder_mizaru_free: mizaru::PublicKey,

    #[structopt(
        long,
        default_value = "44ab86f527fbfb5a038cc51a49e0467be6eb532c4b9c6cb5cdb430926c95bdab",
        parse(from_str = str_to_mizaru_pk)
    )]
    /// mizaru master key of the binder, for PLUS
    binder_mizaru_plus: mizaru::PublicKey,

    #[structopt(long, default_value = "file::memory:?cache=shared")]
    pub debugpack_path: String,
}

impl CommonOpt {
    /// Connects to the binder, given these parameters.
    pub fn get_binder_client(&self) -> DynBinderClient {
        BinderClient(parse_fronts(
            *self.binder_master.as_bytes(),
            self.binder_http_fronts
                .split(',')
                .zip(self.binder_http_hosts.split(','))
                .map(|(k, v)| (k.to_string(), v.to_string())),
        ))
    }
}

#[derive(Debug, StructOpt, Clone, Deserialize, Serialize)]
pub struct AuthOpt {
    #[structopt(
        long,
        default_value = "auto",
        parse(from_str = str_to_path)
    )]
    /// where to store Geph's credential cache. The default value is "auto", meaning a platform-specific path that Geph gets to pick.
    pub credential_cache: PathBuf,

    #[structopt(long, default_value = "")]
    /// username
    pub username: String,

    #[structopt(long, default_value = "")]
    /// password
    pub password: String,
}

fn str_to_path(src: &str) -> PathBuf {
    // if it's auto then generate
    if src == "auto" {
        let mut config_dir = dirs::config_dir().unwrap();
        config_dir.push("geph4-credentials");
        config_dir
    } else {
        PathBuf::from(src)
    }
}

fn str_to_x25519_pk(src: &str) -> x25519_dalek::PublicKey {
    let raw_bts = hex::decode(src).unwrap();
    let raw_bts: [u8; 32] = raw_bts.as_slice().try_into().unwrap();
    x25519_dalek::PublicKey::from(raw_bts)
}

fn str_to_mizaru_pk(src: &str) -> mizaru::PublicKey {
    let raw_bts = hex::decode(src).unwrap();
    let raw_bts: [u8; 32] = raw_bts.as_slice().try_into().unwrap();
    mizaru::PublicKey(raw_bts)
}

/// If greater than zero, then cache can be stale.
static CACHE_STALELOCK_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Keep this alive to allow the cache to be stale.
#[non_exhaustive]
pub struct CacheStaleGuard {}

impl Drop for CacheStaleGuard {
    fn drop(&mut self) {
        let lc = CACHE_STALELOCK_COUNT.fetch_sub(1, Ordering::SeqCst);
        log::debug!("lockcount decr {lc}");
    }
}

impl CacheStaleGuard {
    pub fn new() -> Self {
        let lc = CACHE_STALELOCK_COUNT.fetch_add(1, Ordering::SeqCst);
        log::debug!("lockcount incr {lc}");
        Self {}
    }
}

/// Given the common and authentication options, produce a binder client.
pub fn get_cached_binder_client(
    common_opt: &CommonOpt,
    auth_opt: &AuthOpt,
) -> anyhow::Result<CachedBinderClient> {
    let mut dbpath = auth_opt.credential_cache.clone();
    // create a dbpath based on hashing the username together with the password
    let quasi_user_id = hex::encode(
        blake3::keyed_hash(
            blake3::hash(auth_opt.password.as_bytes()).as_bytes(),
            auth_opt.username.as_bytes(),
        )
        .as_bytes(),
    );
    dbpath.push(&quasi_user_id);
    std::fs::create_dir_all(&dbpath)?;
    let cbc = CachedBinderClient::new(
        {
            let dbpath = dbpath.clone();
            move |key| {
                let mut dbpath = dbpath.clone();
                dbpath.push(format!("{}.json", key));
                let r = std::fs::read(dbpath).ok()?;
                let (tstamp, bts): (u64, Bytes) = bincode::deserialize(&r).ok()?;
                if tstamp > SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs()
                    || CACHE_STALELOCK_COUNT.load(Ordering::SeqCst) > 0
                {
                    Some(bts)
                } else {
                    None
                }
            }
        },
        {
            let dbpath = dbpath.clone();
            move |k, v, expires| {
                let noviy_taymstamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + expires.as_secs();
                let to_write =
                    bincode::serialize(&(noviy_taymstamp, Bytes::copy_from_slice(v))).unwrap();
                let mut dbpath = dbpath.clone();
                dbpath.push(format!("{}.json", k));
                let _ = std::fs::write(dbpath, to_write);
            }
        },
        common_opt.get_binder_client(),
        &auth_opt.username,
        &auth_opt.password,
    );
    Ok(cbc)
}
