use bytes::Bytes;
use ed25519_dalek::ed25519::signature::Signature;
use ed25519_dalek::{PublicKey, Verifier};
use futures_intrusive::sync::ManualResetEvent;
use futures_util::{stream::FuturesUnordered, Future, StreamExt};
use geph4_protocol::binder::protocol::BridgeDescriptor;

use itertools::Itertools;
use native_tls::TlsConnector;
use rand::Rng;
use regex::Regex;
use smol::channel::Sender;
use smol_str::SmolStr;
use smol_timeout::TimeoutExt;
use sosistab2::{Multiplex, MuxPublic, MuxSecret, Pipe};
use sosistab2_obfstls::ObfsTlsPipe;
use sosistab2_obfsudp::{ObfsUdpPipe, ObfsUdpPublic};

use crate::{
    connect::{
        tunnel::{autoconnect::AutoconnectPipe, delay::DelayPipe, TunnelStatus},
        METRIC_SESSION_ID,
    },
    metrics::Metrics,
};
use crate::{conninfo_store::ConnInfoStore, metrics::BridgeMetrics};

use super::{EndpointSource, TunnelCtx};
use anyhow::Context;
use std::{
    collections::{BTreeSet, HashSet},
    net::SocketAddr,
    sync::Weak,
};
use std::{net::IpAddr, time::Instant};

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

pub(super) async fn get_session(ctx: &TunnelCtx) -> anyhow::Result<Arc<sosistab2::Multiplex>> {
    match ctx.endpoint.clone() {
        EndpointSource::Independent { endpoint } => {
            let (addr, raw_key) = parse_independent_endpoint(&endpoint)?;
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
        EndpointSource::Binder(conn_info, binder_tunnel_params) => {
            let start = Instant::now();
            let summary = conn_info.summary().await?;
            let exit_names = summary.exits.iter().map(|e| &e.hostname).collect_vec();
            let selected_exit = summary
                .exits
                .iter()
                .find(|s| Some(s.hostname.as_str()) == binder_tunnel_params.exit_server.as_deref())
                .context(format!(
                    "no such exit found in the list; list is {:?}",
                    exit_names
                ))?
                .clone();
            log::debug!("obtaining global conninfo store");
            let bridges = conn_info.bridges().await?;

            log::debug!("{} routes", bridges.len());

            let e2e_key = MuxPublic::from_bytes(*selected_exit.sosistab_e2e_pk.as_bytes());
            let multiplex = Arc::new(sosistab2::Multiplex::new(
                MuxSecret::generate(),
                Some(e2e_key),
            ));

            // *somehow* this doesn't work. IDK why.
            #[cfg(not(target_os = "ios"))]
            verify_exit_signatures(&bridges, selected_exit.signing_key)?;

            let (metrics_send, metrics_recv) = smol::channel::bounded(1000);

            // add *all* the bridges!
            let sess_id = format!("sess-{}", rand::thread_rng().gen::<u128>());
            {
                let ctx = ctx.clone();
                let multiplex = multiplex.clone();
                let sess_id = sess_id.clone();
                log::debug!("about to add bridges now!");
                add_bridges(&ctx, &sess_id, multiplex.clone(), &bridges, metrics_send)
                    .timeout(Duration::from_secs(30))
                    .await
                    .context("timed out")?;
            }

            // weak here to prevent a reference cycle!
            let weak_multiplex = Arc::downgrade(&multiplex);
            multiplex.add_drop_friend(smolscale::spawn(replace_dead(
                ctx.clone(),
                conn_info.clone(),
                sess_id,
                weak_multiplex,
            )));

            log::debug!("about to return the session");

            let total_latency = start.elapsed().as_secs_f64();
            log::debug!("get_session took: {}s", total_latency);

            // collect metrics in a background task
            smolscale::spawn(async move {
                let bridge_metrics = metrics_recv.collect::<Vec<BridgeMetrics>>().await;

                let metrics_json = serde_json::to_value(Metrics::ConnEstablished {
                    bridges: bridge_metrics,
                    total_latency,
                });
                match metrics_json {
                    Ok(json) => {
                        log::debug!(
                            "uploading connection metrics: {}",
                            serde_json::to_string(&json).unwrap()
                        );
                        let _ = conn_info.rpc().add_metric(*METRIC_SESSION_ID, json).await;
                    }
                    Err(e) => {
                        log::warn!("Failed to serialize metrics: {}", e);
                    }
                };
            })
            .detach();

            Ok(multiplex)
        }
    }
}

async fn add_bridges(
    ctx: &TunnelCtx,
    sess_id: &str,
    mplex: Arc<Multiplex>,
    bridges: &[BridgeDescriptor],
    metrics_send: Sender<BridgeMetrics>,
) {
    let force_bridge = match &ctx.endpoint {
        EndpointSource::Independent { endpoint: _ } => None,
        EndpointSource::Binder(_, b) => b.force_bridge,
    };
    if bridges.is_empty() {
        return;
    }
    let something_works = Arc::new(ManualResetEvent::new(false));
    let protocols: BTreeSet<SmolStr> = bridges.iter().map(|b| b.protocol.clone()).collect();
    for protocol in protocols {
        let protocol = protocol.clone();
        let bridges = bridges
            .iter()
            .filter(|s| s.protocol == protocol)
            .filter(|s| match force_bridge {
                None => true,
                Some(ip) => s.endpoint.ip() == IpAddr::from(ip),
            })
            .cloned()
            .collect_vec();

        let metrics_send = metrics_send.clone();
        let mplex = mplex.clone();
        let something_works = something_works.clone();
        let all_futures: Vec<_> = bridges
            .iter()
            .flat_map(|bridge| {
                let bridge = bridge.clone(); // Clone `bridge` here
                let ctx = ctx.clone();
                let sess_id = sess_id.to_string();
                let metrics_send = metrics_send.clone();
                if let EndpointSource::Binder(_, params) = &ctx.endpoint {
                    if params.use_bridges && bridge.is_direct {
                        return None;
                    }
                    if let Some(regex) = &params.force_protocol {
                        let compiled = Regex::new(regex).expect("invalid protocol force");
                        if !compiled.is_match(&bridge.protocol) {
                            return None;
                        }
                    }
                }
                let protocol = protocol.clone();
                Some(async move {
                    let mut bridge_metrics = BridgeMetrics {
                        address: bridge.endpoint,
                        protocol: protocol.clone().into(),
                        pipe_latency: None,
                    };
                    match connect_once(ctx.clone(), bridge.clone(), &sess_id).await {
                        Ok((pipe, latency)) => {
                            bridge_metrics.pipe_latency = Some(latency);
                            let _ = metrics_send.send(bridge_metrics).await;
                            Some(pipe)
                        }
                        Err(err) => {
                            log::warn!(
                                "pipe creation failed for {} ({}): {:?}",
                                bridge.endpoint,
                                bridge.protocol,
                                err
                            );

                            let _ = metrics_send.send(bridge_metrics).await;
                            None
                        }
                    }
                })
            })
            .collect();

        let mut unordered_futures = FuturesUnordered::from_iter(all_futures);

        // Drain the remaining futures in the background for metrics.
        smolscale::spawn({
            let mplex = mplex.clone();

            async move {
                while let Some(maybe_pipe) = unordered_futures.next().await {
                    if let Some(pipe) = maybe_pipe {
                        log::debug!("adding pipe {} @ {}", pipe.protocol(), pipe.peer_addr());
                        mplex.add_pipe(pipe);

                        something_works.set();
                    }
                }
            }
        })
        .detach();
    }
    // we wait until one pipe is added
    something_works.wait().await;
    log::debug!("finished add_bridges");
}

async fn connect_udp(desc: BridgeDescriptor, meta: String) -> anyhow::Result<ObfsUdpPipe> {
    let cookie: ObfsUdpPublic =
        bincode::deserialize(&desc.cookie).context("cannot decode pipe cookie")?;
    ObfsUdpPipe::connect(desc.endpoint, cookie, &meta)
        .timeout(Duration::from_secs(30))
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
    .timeout(Duration::from_secs(30))
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

type ConnectLatency = f64;

async fn connect_once(
    ctx: TunnelCtx,
    desc: BridgeDescriptor,
    meta: &str,
) -> anyhow::Result<(Box<dyn Pipe>, ConnectLatency)> {
    let start = Instant::now();
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
    let latency = start.elapsed().as_secs_f64();
    Ok((inner, latency))
}

async fn replace_dead(
    ctx: TunnelCtx,
    conn_info: Arc<ConnInfoStore>,
    sess_id: String,
    weak_multiplex: Weak<Multiplex>,
) {
    let mut previous_bridges: Option<Vec<BridgeDescriptor>> = None;
    loop {
        smol::Timer::after(Duration::from_secs(120)).await;
        loop {
            let fallible_part = async {
                let current_bridges = conn_info.bridges().await?;
                let multiplex = match weak_multiplex.upgrade() {
                    Some(mux) => mux,
                    None => {
                        log::error!("multiplex dropped");
                        return Ok(());
                    }
                };

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
                    let (dummy_send, _dummy_recv) = smol::channel::bounded(1);
                    add_bridges(&ctx, &sess_id, multiplex.clone(), &to_add, dummy_send)
                        .timeout(Duration::from_secs(30))
                        .await
                        .context("add_bridges timed out")?;
                }
                anyhow::Ok(())
            };
            if let Err(err) = fallible_part.await {
                log::warn!("error replacing dead bridges: {:?}", err);
                smol::Timer::after(Duration::from_secs(1)).await;
            } else {
                break;
            }
        }
    }
}
