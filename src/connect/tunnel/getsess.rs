use futures_util::{stream::FuturesUnordered, Future, StreamExt};
use geph4_protocol::binder::protocol::{BridgeDescriptor, ExitDescriptor};

use itertools::Itertools;
use native_tls::{Protocol, TlsConnector};
use rand::Rng;
use regex::Regex;
use smol_str::SmolStr;
use smol_timeout::TimeoutExt;
use sosistab2::{Multiplex, MuxPublic, MuxSecret, ObfsTlsPipe, ObfsUdpPipe, ObfsUdpPublic, Pipe};

use crate::connect::tunnel::{autoconnect::AutoconnectPipe, delay::DelayPipe, TunnelStatus};

use super::{BinderTunnelParams, EndpointSource, TunnelCtx};
use anyhow::Context;
use std::{collections::BTreeSet, net::SocketAddr, sync::Weak};

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
            // The bridge descriptor is laid out in a rather weird format: the "sosistab_key" field is a bincode-encode tuple of the first-level cookie, and the end-to-end MuxPublic key.
            // we assume we have at least one obfsudp key
            let e2e_key: MuxPublic = {
                let mut seen = None;
                for bridge in bridges.iter() {
                    if bridge.protocol == "sosistab2-obfsudp" {
                        if let Ok(val) =
                            bincode::deserialize::<(ObfsUdpPublic, MuxPublic)>(&bridge.sosistab_key)
                        {
                            seen = Some(val.1)
                        }
                    }
                }
                seen.context("cannot deduce the sosistab2 MuxPublic of this exit")?
            };
            let multiplex = Arc::new(sosistab2::Multiplex::new(
                MuxSecret::generate(),
                Some(e2e_key),
            ));
            // add *all* the bridges!
            let sess_id = format!("sess-{}", rand::thread_rng().gen::<u128>());
            add_bridges(&ctx, &sess_id, &multiplex, &bridges).await;

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
                    match connect_once(ctx.clone(), bridge.clone(), sess_id).await {
                        Ok(pipe) => {
                            log::debug!("add pipe {} / {}", pipe.protocol(), pipe.peer_addr());
                            mplex.add_pipe(pipe);
                        }
                        Err(err) => {
                            log::warn!(
                                "pipe creation failed for {} ({}): {:?}",
                                bridge.endpoint,
                                bridge.protocol,
                                err
                            )
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
    let keys: (ObfsUdpPublic, MuxPublic) =
        bincode::deserialize(&desc.sosistab_key).context("cannot decode keys")?;
    ObfsUdpPipe::connect(desc.endpoint, keys.0, &meta)
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
        desc.sosistab_key.clone(),
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
                Duration::from_millis(50),
            ))
        }
        other => {
            anyhow::bail!("unknown protocol {other}")
        }
    };
    if desc.is_direct {
        Ok(inner)
    } else {
        Ok(Box::new(DelayPipe::new(inner, Duration::from_millis(10))))
    }
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
        smol::Timer::after(Duration::from_secs(300)).await;
        loop {
            let fallible_part = async {
                let bridges = ccache.get_bridges_v2(&selected_exit.hostname, true).await?;
                let multiplex = weak_multiplex.upgrade().context("multiplex is dead")?;
                if let Some(previous_bridges) = previous_bridges.replace(bridges.clone()) {
                    let new_bridges = bridges
                        .into_iter()
                        .filter(|br| {
                            !previous_bridges
                                .iter()
                                .any(|pipe| pipe.endpoint == br.endpoint)
                        })
                        .collect_vec();
                    add_bridges(&ctx, &sess_id, &multiplex, &new_bridges).await;
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
