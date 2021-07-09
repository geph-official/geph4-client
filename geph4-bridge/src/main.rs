mod forward;

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use binder_transport::{BinderClient, BinderRequestData, BinderResponse, ExitDescriptor};
use env_logger::Env;
use once_cell::sync::Lazy;
use smol::{
    net::{TcpListener, UdpSocket},
    prelude::*,
};
use std::time::Duration;
use structopt::StructOpt;

use crate::forward::Forwarder;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(long, default_value = "http://binder-v4.geph.io:8964")]
    /// HTTP(S) address of the binder
    binder_http: String,

    #[structopt(
        long,
        default_value = "124526f4e692b589511369687498cce57492bf4da20f8d26019c1cc0c80b6e4b"
    )]
    /// x25519 master key of the binder
    binder_master_pk: String,

    /// bridge secret. All bridges and exits know this secret, and it's used to prevent random people from spamming the bridge table.
    #[structopt(long)]
    bridge_secret: String,

    /// bridge group.
    #[structopt(long, default_value = "other")]
    bridge_group: String,
}

fn main() -> anyhow::Result<()> {
    smol::block_on(async move {
        let opt: Opt = Opt::from_args();
        env_logger::Builder::from_env(Env::default().default_filter_or("geph4_bridge=info")).init();
        run_command("iptables -t nat -F");
        // --random to not leak origin ports
        run_command("iptables -t nat -A POSTROUTING -j MASQUERADE --random");
        // set TTL to 200 to hide distance of clients
        // run_command("iptables -t mangle -I POSTROUTING -j TTL --ttl-set 200");
        let binder_client = Arc::new(binder_transport::HttpClient::new(
            bincode::deserialize(&hex::decode(opt.binder_master_pk)?)?,
            opt.binder_http,
            &[],
            None,
        ));
        bridge_loop(binder_client, &opt.bridge_secret, &opt.bridge_group).await;
        Ok(())
    })
}

/// Main loop of the bridge.
///
/// We poll the binder for a list of exits, and maintain a list of actor-like "exit manager" tasks that each manage a control-protocol connection.
async fn bridge_loop<'a>(
    binder_client: Arc<dyn BinderClient>,
    bridge_secret: &'a str,
    bridge_group: &'a str,
) {
    let mut current_exits = HashMap::new();
    loop {
        let binder_client = binder_client.clone();
        let exits = binder_client.request(BinderRequestData::GetExits).await;
        if let Ok(BinderResponse::GetExitsResp(exits)) = exits {
            log::info!("got {} exits!", exits.len());
            // insert all exits that aren't in current exit
            for exit in exits {
                if current_exits.get(&exit.hostname).is_none() {
                    log::info!("{} is a new exit, spawning 16 new managers!", exit.hostname);
                    let task = (0..16)
                        .map(|_| {
                            smolscale::spawn(manage_exit(
                                exit.clone(),
                                bridge_secret.to_string(),
                                bridge_group.to_string(),
                            ))
                        })
                        .collect::<Vec<_>>();
                    current_exits.insert(exit.hostname, task);
                }
            }
        }

        smol::Timer::after(Duration::from_secs(30)).await;
    }
}

async fn manage_exit(
    exit: ExitDescriptor,
    bridge_secret: String,
    bridge_group: String,
) -> anyhow::Result<()> {
    let (local_udp, local_tcp) = std::iter::from_fn(|| Some(fastrand::u32(1000..65536)))
        .find_map(|port| {
            Some((
                smol::future::block_on(UdpSocket::bind(format!("[::0]:{}", port))).ok()?,
                smol::future::block_on(TcpListener::bind(format!("[::0]:{}", port))).ok()?,
            ))
        })
        .unwrap();
    log::info!(
        "forward to {} from local address {}",
        exit.hostname,
        local_udp.local_addr().unwrap()
    );
    let (send_routes, recv_routes) = flume::bounded(0);
    let manage_fut = async {
        loop {
            if let Err(err) = manage_exit_once(
                &exit,
                &bridge_secret,
                &bridge_group,
                local_udp.local_addr().unwrap(),
                &send_routes,
            )
            .await
            {
                log::warn!("restarting manage_exit_once: {}", err);
            }
        }
    };
    let route_fut = async {
        // command for route delete
        let mut forwarder: Option<Forwarder> = None;
        let mut last_remote_port = 0;
        loop {
            let (remote_port, _) = recv_routes.recv_async().await?;
            let remote_addr =
                smol::net::resolve(&format!("{}:{}", exit.hostname, remote_port)).await?[0];
            if remote_port != last_remote_port {
                last_remote_port = remote_port;
                forwarder.replace(Forwarder::new(
                    local_udp.clone(),
                    local_tcp.clone(),
                    remote_addr,
                    true,
                ));
            }
        }
    };
    smol::future::race(manage_fut, route_fut).await
}

fn run_command(s: &str) {
    log::info!("running command {}", s);
    std::process::Command::new("sh")
        .arg("-c")
        .arg(s)
        .output()
        .unwrap();
}

static MY_IP: Lazy<IpAddr> = Lazy::new(|| {
    ureq::get("http://checkip.amazonaws.com/")
        .call()
        .into_string()
        .unwrap()
        .trim()
        .to_string()
        .parse()
        .unwrap()
});

async fn manage_exit_once(
    exit: &ExitDescriptor,
    bridge_secret: &str,
    bridge_group: &str,
    mut my_addr: SocketAddr,
    route_update: &flume::Sender<(u16, x25519_dalek::PublicKey)>,
) -> anyhow::Result<()> {
    // get my ip address
    my_addr.set_ip(*MY_IP);
    let mut conn = smol::net::TcpStream::connect(&format!("{}:28080", exit.hostname)).await?;
    // first read the challenge string
    let mut challenge_string = [0u8; 32];
    conn.read_exact(&mut challenge_string).await?;
    // compute the challenge response
    let challenge_response = blake3::keyed_hash(&challenge_string, bridge_secret.as_bytes());
    conn.write_all(challenge_response.as_bytes()).await?;
    // enter the main loop
    loop {
        // send address and group
        aioutils::write_pascalish(&mut conn, &(my_addr, bridge_group)).await?;
        // receive route
        let (port, sosistab_pk): (u16, x25519_dalek::PublicKey) =
            aioutils::read_pascalish(&mut conn).await?;
        log::info!(
            "route at {} is {}/{}",
            exit.hostname,
            port,
            hex::encode(sosistab_pk.as_bytes())
        );
        // update route
        route_update.send_async((port, sosistab_pk)).await?;
        smol::Timer::after(Duration::from_secs(30)).await;
    }
}
