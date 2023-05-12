use bytes::Bytes;
use ed25519_dalek::ed25519::signature::Signature;
use ed25519_dalek::{PublicKey, Verifier};
use futures_util::{stream::FuturesUnordered, Future, StreamExt};
use geph4_protocol::binder::protocol::{BridgeDescriptor, ExitDescriptor};

use itertools::Itertools;
use native_tls::TlsConnector;
use rand::Rng;
use regex::Regex;
use smol_str::SmolStr;
use smol_timeout::TimeoutExt;
use sosistab2::{Multiplex, MuxPublic, MuxSecret, ObfsTlsPipe, ObfsUdpPipe, ObfsUdpPublic, Pipe};

use crate::connect::tunnel::{autoconnect::AutoconnectPipe, delay::DelayPipe, TunnelStatus};

use super::{BinderTunnelParams, EndpointSource, TunnelCtx};
use anyhow::Context;
use std::{
    collections::{BTreeSet, HashSet},
    net::SocketAddr,
    sync::Weak,
};

use std::{convert::TryFrom, sync::Arc, time::Duration};

pub fn parse_independent_endpoint(endpoint: &str) -> anyhow::Result<(SocketAddr, [u8; 32])> {
    // parse endpoint addr
    let pk_and_url = endpoint.split('@').collect::<Vec<_>>();
    let server_pk = <[u8; 32]>::try_from(
        hex::decode(pk_and_url.first().context("URL not in form PK@host:port")?)
            .context("PK is not hex")?,
    )
    .ok()
    .context("cannot parse server pk")?;
    let server_addr: SocketAddr = pk_and_url
        .get(1)
        .context("URL not in form PK@host:port")?
        .parse()
        .context("cannot parse host:port")?;
    Ok((server_addr, server_pk))
}

fn verify_exit_signatures(
    bridges: &[BridgeDescriptor],
    signing_key: PublicKey,
) -> anyhow::Result<()> {
    for b in bridges.iter() {
        // The exit signed this bridge with an empty signature, so we have to verify with an empty signature
        let mut clean_bridge = b.clone();
        clean_bridge.exit_signature = Bytes::new();

        let signature = &Signature::from_bytes(b.exit_signature.as_ref())
            .context("failed to deserialize exit signature")?;
        let bridge_msg = bincode::serialize(&clean_bridge).unwrap();
        let bridge_log_id = format!("[{}] {}/{}", b.protocol, b.exit_hostname, b.endpoint);
        match signing_key.verify(bridge_msg.as_slice(), signature) {
            Ok(_) => {
                log::debug!("successfully verified bridge signature for {bridge_log_id}");
            }
            Err(err) => {
                anyhow::bail!(
                    "failed to verify exit signature for {bridge_log_id}, error: {:?}",
                    err
                )
            }
        }
    }
    Ok(())
}

pub(crate) async fn get_session(ctx: TunnelCtx) -> anyhow::Result<Arc<sosistab2::Multiplex>> {
    match &ctx.endpoint {
        EndpointSource::Independent { endpoint } => {
            let (addr, raw_key) = parse_independent_endpoint(endpoint)?;
            let obfs_pk = ObfsUdpPublic::from_bytes(raw_key);
            let sessid = rand::thread_rng().gen::<u128>().to_string();
            let mplex = Multiplex::new(MuxSecret::generate(), None);
            for _ in 0..4 {
                let pipe = ObfsUdpPipe::connect(addr, obfs_pk, &sessid).await?;
                let sessid = sessid.clone();
                let pipe = AutoconnectPipe::new(pipe, move || {
                    let sessid = sessid.clone();
                    smolscale::spawn(async move {
                        loop {
                            if let Some(Ok(pipe)) = ObfsUdpPipe::connect(addr, obfs_pk, &sessid)
                                .timeout(Duration::from_secs(10))
                                .await
                            {
                                return pipe;
                            }
                            smol::Timer::after(Duration::from_secs(1)).await;
                        }
                    })
                });
                mplex.add_pipe(pipe);
            }
            Ok(Arc::new(mplex))
        }
        EndpointSource::Binder(binder_tunnel_params) => {
            let selected_exit = binder_tunnel_params
                .ccache
                .get_closest_exit(&binder_tunnel_params.exit_server.clone().unwrap_or_default())
                .await
                .context("cannot get closest exit")?;
            log::info!("using exit {}", selected_exit.hostname);
            let bridges = binder_tunnel_params
                .ccache
                .get_bridges_v2(&selected_exit.hostname, false)
                .await
                .context("cannot get bridges")?;
            if bridges.is_empty() {
                anyhow::bail!("no sosistab2 routes to {}", selected_exit.hostname)
            }

            log::debug!("{} routes", bridges.len());

            let e2e_key = MuxPublic::from_bytes(*selected_exit.sosistab_e2e_pk.as_bytes());
            let multiplex = Arc::new(sosistab2::Multiplex::new(
                MuxSecret::generate(),
                Some(e2e_key),
            ));

            verify_exit_signatures(&bridges, selected_exit.signing_key)?;

            // add *all* the bridges!
            let sess_id = format!("sess-{}", rand::thread_rng().gen::<u128>());
            {
                let ctx = ctx.clone();
                let multiplex = multiplex.clone();
                let sess_id = sess_id.clone();
                smolscale::spawn(async move {
                    add_bridges(&ctx, &sess_id, &multiplex, &bridges)
                        .timeout(Duration::from_secs(30))
                        .await;
                })
                .detach();
            }

            // weak here to prevent a reference cycle!
            let weak_multiplex = Arc::downgrade(&multiplex);
            multiplex.add_drop_friend(smolscale::spawn(replace_dead(
                ctx.clone(),
                binder_tunnel_params.clone(),
                selected_exit,
                sess_id,
                weak_multiplex,
            )));

            Ok(multiplex)
        }
    }
}

async fn add_bridges(
    ctx: &TunnelCtx,
    sess_id: &str,
    mplex: &Multiplex,
    bridges: &[BridgeDescriptor],
) {
    // we pick only the 3 best out of every protocol
    let protocols: BTreeSet<SmolStr> = bridges.iter().map(|b| b.protocol.clone()).collect();
    let mut outer = FuturesUnordered::new();
    for protocol in protocols {
        let bridges = bridges
            .iter()
            .filter(|s| s.protocol == protocol)
            .collect_vec();
        outer.push(async {
            let uo = FuturesUnordered::new();
            for bridge in bridges {
                if let EndpointSource::Binder(params) = &ctx.endpoint {
                    if params.use_bridges && bridge.is_direct {
                        continue;
                    }
                    if let Some(regex) = &params.force_protocol {
                        let compiled = Regex::new(regex).expect("invalid protocol force");
                        if !compiled.is_match(&bridge.protocol) {
                            continue;
                        }
                    }
                }
                uo.push(async {
                    for _ in 0..10 {
                        match connect_once(ctx.clone(), bridge.clone(), sess_id).await {
                            Ok(pipe) => {
                                log::debug!("add pipe {} / {}", pipe.protocol(), pipe.peer_addr());
                                mplex.add_pipe(pipe);
                                return;
                            }
                            Err(err) => {
                                log::warn!(
                                    "pipe creation failed for {} ({}): {:?}",
                                    bridge.endpoint,
                                    bridge.protocol,
                                    err
                                );
                                smol::Timer::after(Duration::from_secs(1)).await;
                            }
                        }
                    }
                })
            }
            let mut stream = uo.take(3);
            while stream.next().await.is_some() {}
        });
    }
    while outer.next().await.is_some() {}
}

async fn connect_udp(desc: BridgeDescriptor, meta: String) -> anyhow::Result<ObfsUdpPipe> {
    let cookie: ObfsUdpPublic =
        bincode::deserialize(&desc.cookie).context("cannot decode pipe cookie")?;
    ObfsUdpPipe::connect(desc.endpoint, cookie, &meta)
        .timeout(Duration::from_secs(10))
        .await
        .context("pipe connection timeout")?
}

async fn connect_tls(desc: BridgeDescriptor, meta: String) -> anyhow::Result<ObfsTlsPipe> {
    let mut config = TlsConnector::builder();
    config
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .min_protocol_version(None)
        .max_protocol_version(None)
        .use_sni(false);
    let fake_domain = format!("{}.com", eff_wordlist::short::random_word());
    let connection = ObfsTlsPipe::connect(
        desc.endpoint,
        &fake_domain,
        config,
        desc.cookie.clone(),
        &meta,
    )
    .timeout(Duration::from_secs(10))
    .await
    .context("pipe connection timeout")??;
    Ok(connection)
}

async fn autoconnect_with<P: Pipe, F: Future<Output = anyhow::Result<P>> + Send + 'static>(
    f: impl Fn() -> F + Send + Sync + 'static,
) -> anyhow::Result<AutoconnectPipe<P>> {
    let connection = f().await?;
    let protocol = connection.protocol().to_string();
    let endpoint = connection.peer_addr();
    let f = Arc::new(f);
    Ok(AutoconnectPipe::new(connection, move || {
        let protocol = protocol.clone();
        let endpoint = endpoint.clone();
        let f = f.clone();
        smolscale::spawn(async move {
            for wait in 0u64.. {
                match f().await {
                    Ok(val) => return val,
                    Err(err) => log::warn!(
                        "problem reconnecting to {} / {}: {:?}",
                        protocol,
                        endpoint,
                        err
                    ),
                }
                smol::Timer::after(Duration::from_secs_f64(1.5f64.powf(wait as f64))).await;
            }
            unreachable!()
        })
    }))
}

async fn connect_once(
    ctx: TunnelCtx,
    desc: BridgeDescriptor,
    meta: &str,
) -> anyhow::Result<Box<dyn Pipe>> {
    log::debug!("trying to connect to {} / {}", desc.protocol, desc.endpoint);
    (ctx.status_callback)(TunnelStatus::PreConnect {
        addr: desc.endpoint,
        protocol: desc.protocol.clone(),
    });
    let desc = desc.clone();
    let meta = meta.to_string();
    let inner: Box<dyn Pipe> = match desc.protocol.as_str() {
        "sosistab2-obfsudp" => {
            let desc = desc.clone();
            Box::new(autoconnect_with(move || connect_udp(desc.clone(), meta.clone())).await?)
        }
        "sosistab2-obfstls" => {
            let desc = desc.clone();
            Box::new(DelayPipe::new(
                autoconnect_with(move || connect_tls(desc.clone(), meta.clone())).await?,
                Duration::from_millis(20),
            ))
        }
        other => {
            anyhow::bail!("unknown protocol {other}")
        }
    };
    Ok(inner)
}

async fn replace_dead(
    ctx: TunnelCtx,
    binder_tunnel_params: BinderTunnelParams,
    selected_exit: ExitDescriptor,
    sess_id: String,
    weak_multiplex: Weak<Multiplex>,
) {
    let ccache = binder_tunnel_params.ccache.clone();
    let mut previous_bridges: Option<Vec<BridgeDescriptor>> = None;
    loop {
        smol::Timer::after(Duration::from_secs(120)).await;
        loop {
            let fallible_part = async {
                let current_bridges = ccache
                    .get_bridges_v2(&selected_exit.hostname, false)
                    .await?;
                let multiplex = weak_multiplex.upgrade().context("multiplex is dead")?;
                for (i, pipe) in multiplex.iter_pipes().enumerate() {
                    log::debug!("pipe {i}: [{}] {}", pipe.protocol(), pipe.peer_addr());
                }

                if let Some(previous_bridges) = previous_bridges.replace(current_bridges.clone()) {
                    // first remove anything that is not in the new bridges
                    multiplex.retain(|pipe| {
                        current_bridges
                            .iter()
                            .any(|np| np.endpoint.to_string() == pipe.peer_addr())
                    });
                    let current_live_pipes: HashSet<String> =
                        multiplex.iter_pipes().map(|p| p.peer_addr()).collect();
                    let to_add = current_bridges
                        .clone()
                        .into_iter()
                        .filter(|br| {
                            !current_live_pipes.contains(&br.endpoint.to_string())
                                && (!previous_bridges
                                    .iter()
                                    .any(|pipe| pipe.endpoint == br.endpoint)
                                    || br.is_direct)
                        })
                        .collect_vec();
                    log::debug!(
                        "** {} bridges that are either not in old, or direct **",
                        to_add.len()
                    );
                    add_bridges(&ctx, &sess_id, &multiplex, &to_add)
                        .timeout(Duration::from_secs(30))
                        .await
                        .context("add_bridges timed out")?;
                }
                anyhow::Ok(())
            };
            if let Err(err) = fallible_part.await {
                log::warn!("error refreshing bridges: {:?}", err)
            } else {
                break;
            }
        }
    }
}
