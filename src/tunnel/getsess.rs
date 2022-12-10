use geph4_protocol::binder::protocol::BridgeDescriptor;
use rand::{seq::SliceRandom, Rng};
use smol_timeout::TimeoutExt;
use sosistab2::{MuxPublic, MuxSecret, ObfsUdpPipe, ObfsUdpPublic, Pipe};

use crate::tunnel::activity::wait_activity;

use super::{EndpointSource, TunnelCtx};
use anyhow::Context;
use async_net::SocketAddr;

use std::{convert::TryFrom, sync::Arc, time::Duration};

pub fn parse_independent_endpoint(
    endpoint: &str,
) -> anyhow::Result<(SocketAddr, x25519_dalek::PublicKey)> {
    // parse endpoint addr
    let pk_and_url = endpoint.split('@').collect::<Vec<_>>();
    let server_pk = x25519_dalek::PublicKey::from(
        <[u8; 32]>::try_from(
            hex::decode(pk_and_url.first().context("URL not in form PK@host:port")?)
                .context("PK is not hex")?,
        )
        .unwrap(),
    );
    let server_addr: SocketAddr = pk_and_url
        .get(1)
        .context("URL not in form PK@host:port")?
        .parse()
        .context("cannot parse host:port")?;
    Ok((server_addr, server_pk))
}

pub(crate) async fn get_session(ctx: TunnelCtx) -> anyhow::Result<Arc<sosistab2::Multiplex>> {
    match &ctx.endpoint {
        EndpointSource::Independent { endpoint: _ } => {
            todo!()
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
                    if let Ok(val) =
                        bincode::deserialize::<(ObfsUdpPublic, MuxPublic)>(&bridge.sosistab_key)
                    {
                        seen = Some(val.1)
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
            for bridge in bridges.into_iter() {
                if binder_tunnel_params.use_bridges && bridge.alloc_group == "direct" {
                    continue;
                }
                let sess_id = sess_id.clone();
                let multiplex = multiplex.clone();
                smolscale::spawn(async move {
                    match connect_once(bridge, &sess_id).await {
                        Ok(pipe) => {
                            log::debug!(
                                "add initial pipe {} / {}",
                                pipe.protocol(),
                                pipe.peer_addr()
                            );
                            multiplex.add_pipe(pipe);
                        }
                        Err(err) => {
                            log::warn!("pipe creation failed: {:?}", err)
                        }
                    }
                })
                .detach();
            }

            // weak here to prevent a reference cycle!
            let weak_multiplex = Arc::downgrade(&multiplex);
            let ccache = binder_tunnel_params.ccache.clone();
            let binder_tunnel_params = binder_tunnel_params.clone();
            multiplex.add_drop_friend(smolscale::spawn(async move {
                loop {
                    let interval = Duration::from_secs_f64(rand::thread_rng().gen_range(1.0, 3.0));
                    wait_activity(interval).await;
                    if let Some(multiplex) = weak_multiplex.upgrade() {
                        let dead_count = multiplex.clear_dead_pipes();
                        if dead_count > 0 {
                            let fallible = async {
                                let mut bridges = ccache
                                    .get_bridges_v2(&selected_exit.hostname, false)
                                    .await
                                    .context("cannot get bridges")?;
                                bridges.shuffle(&mut rand::thread_rng());
                                if let Some(first) = bridges.first() {
                                    if binder_tunnel_params.use_bridges
                                        && first.alloc_group == "direct"
                                    {
                                        return Ok(());
                                    }
                                    let pipe = connect_once(first.clone(), &sess_id).await?;
                                    log::debug!(
                                        "add later pipe {} / {}",
                                        pipe.protocol(),
                                        pipe.peer_addr()
                                    );
                                    multiplex.add_pipe(pipe);
                                }
                                anyhow::Ok(())
                            };
                            if let Err(err) = fallible.await {
                                log::warn!("{:?}", err)
                            }
                        }
                    }
                }
            }));

            Ok(multiplex)
        }
    }
}

async fn connect_once(desc: BridgeDescriptor, meta: &str) -> anyhow::Result<Box<dyn Pipe>> {
    match desc.protocol.as_str() {
        "sosistab2-obfsudp" => {
            log::debug!("trying to connect to {}", desc.endpoint);
            let keys: (ObfsUdpPublic, MuxPublic) =
                bincode::deserialize(&desc.sosistab_key).context("cannot decode keys")?;
            let connection = ObfsUdpPipe::connect(desc.endpoint, keys.0, meta)
                .timeout(Duration::from_secs(10))
                .await
                .context("pipe connection timeout")??;
            Ok(Box::new(connection))
        }
        other => {
            anyhow::bail!("unsupported protocol {other}")
        }
    }
}
