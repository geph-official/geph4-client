use super::{session, RootCtx};
use anyhow::Context;
use binder_transport::BinderRequestData;
use ed25519_dalek::Signer;
use rand::prelude::*;
use smol::{channel::Sender, prelude::*};
use smol_timeout::TimeoutExt;
use smolscale::OnError;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};

pub async fn handle_control(
    ctx: Arc<RootCtx>,
    mut client: smol::net::TcpStream,
) -> anyhow::Result<()> {
    let exit_hostname = ctx.exit_hostname.clone();
    let bridge_pkt_key = move |bridge_group: &str| {
        format!(
            "raw_flow.{}.{}",
            exit_hostname.replace(".", "-"),
            bridge_group.replace(".", "-")
        )
    };

    let bridge_secret = ctx.bridge_secret.as_bytes();
    // first, let's challenge the client to prove that they have the bridge secret
    let challenge_string: [u8; 32] = rand::thread_rng().gen();
    client
        .write_all(&challenge_string)
        .timeout(Duration::from_secs(10))
        .await
        .ok_or_else(|| anyhow::anyhow!("challenge send timeout"))
        .context("failed to write challenge")??;
    // then, we read back a challenge
    let mut challenge_response = [0u8; 32];
    client
        .read_exact(&mut challenge_response)
        .timeout(Duration::from_secs(10))
        .await
        .ok_or_else(|| anyhow::anyhow!("challenge recv timeout"))
        .context("failed to read challenge response")??;
    // verify the challenge
    let correct_response = blake3::keyed_hash(&challenge_string, &bridge_secret);
    if *correct_response.as_bytes() != challenge_response {
        anyhow::bail!("failed bridge secret authentication");
    }
    // now we read their info
    let mut info: Option<(u16, x25519_dalek::PublicKey, Sender<()>)> = None;
    loop {
        let (their_addr, their_group): (SocketAddr, String) = aioutils::read_pascalish(&mut client)
            .or(async {
                smol::Timer::after(Duration::from_secs(600)).await;
                anyhow::bail!("timeout read")
            })
            .await?;
        let flow_key = bridge_pkt_key(&their_group);
        log::debug!("bridge in group {} to forward {}", their_group, their_addr);
        // create or recall binding
        if info.is_none() {
            let ctx = ctx.clone();
            let stat = ctx.stat_client.clone();
            let stat2 = stat.clone();
            let fk2 = flow_key.clone();
            log::debug!("redoing binding because info is none");
            let sosis_secret = x25519_dalek::StaticSecret::new(&mut rand::thread_rng());
            let sosis_listener = sosistab::Listener::listen(
                "[::0]:0",
                sosis_secret.clone(),
                move |len, _| {
                    if fastrand::f32() < 0.05 {
                        stat.count(&flow_key, len as f64 * 20.0)
                    }
                },
                move |len, _| {
                    if fastrand::f32() < 0.05 {
                        stat2.count(&fk2, len as f64 * 20.0)
                    }
                },
            )
            .await;
            let (send, recv) = smol::channel::bounded(1);
            info = Some((
                sosis_listener.local_addr().port(),
                x25519_dalek::PublicKey::from(&sosis_secret),
                send,
            ));
            // spawn a task that dies when the binding is gone
            ctx.nursery.clone().spawn(OnError::Ignore, move |nursery| {
                async move {
                    loop {
                        let sess = sosis_listener
                            .accept_session()
                            .await
                            .ok_or_else(|| anyhow::anyhow!("could not accept sosis session"))?;
                        let ctx = ctx.clone();
                        nursery.spawn(OnError::Ignore, move |_| {
                            session::handle_session(ctx.new_sess(sess))
                        });
                    }
                }
                .or(async move { Ok(recv.recv().await?) })
            });
        }
        // send to the other side and then binder
        let (port, sosistab_pk, _) = info.as_ref().unwrap();
        aioutils::write_pascalish(&mut client, &(port, sosistab_pk))
            .or(async {
                smol::Timer::after(Duration::from_secs(600)).await;
                anyhow::bail!("timeout write")
            })
            .await?;
        let route_unixtime = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let to_sign =
            bincode::serialize(&(sosistab_pk, their_addr, their_group.clone(), route_unixtime))
                .unwrap();
        let exit_signature = ctx.signing_sk.sign(&to_sign);
        let binder_client = ctx.binder_client.clone();
        let exit_hostname = ctx.exit_hostname.to_string();
        while let Err(err) = binder_client
            .request(BinderRequestData::AddBridgeRoute {
                sosistab_pubkey: *sosistab_pk,
                bridge_address: their_addr,
                bridge_group: their_group.clone(),
                exit_hostname: exit_hostname.clone(),
                route_unixtime,
                exit_signature,
            })
            .await
            .context("failed to go to binder")
        {
            log::warn!("{:?}", err);
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    }
}
