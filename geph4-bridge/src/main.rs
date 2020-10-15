use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use binder_transport::{BinderClient, BinderRequestData, BinderResponse, ExitDescriptor};
use env_logger::Env;
use serde::{de::DeserializeOwned, Serialize};
use smol::prelude::*;
use std::time::Duration;
use structopt::StructOpt;

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
        env_logger::from_env(Env::default().default_filter_or("geph4_bridge=info")).init();
        run_command("iptables -t nat -F");
        run_command("iptables -t nat -A POSTROUTING -j MASQUERADE --random");
        let binder_client = Arc::new(binder_transport::HttpClient::new(
            bincode::deserialize(&hex::decode(opt.binder_master_pk)?)?,
            opt.binder_http,
            &[],
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
    let mut current_exits: HashMap<String, smol::Task<anyhow::Result<()>>> = HashMap::new();
    loop {
        let binder_client = binder_client.clone();
        let exits = smol::unblock(move || {
            binder_client.request(BinderRequestData::GetExits, Duration::from_secs(10))
        })
        .await;
        if let Ok(exits) = exits {
            if let BinderResponse::GetExitsResp(exits) = exits {
                log::info!("got {} exits!", exits.len());
                // insert all exits that aren't in current exit
                for exit in exits {
                    if current_exits.get(&exit.hostname).is_none() {
                        log::info!("{} is a new exit, spawning a manager!", exit.hostname);
                        let task = smol::spawn(manage_exit(
                            exit.clone(),
                            bridge_secret.to_string(),
                            bridge_group.to_string(),
                        ));
                        current_exits.insert(exit.hostname, task);
                    }
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
    let free_socket = std::net::UdpSocket::bind("[::0]:0").unwrap();
    let remote_addr = smol::net::resolve(&format!("{}:28080", exit.hostname)).await?[0];
    log::info!(
        "forward to {} from local address {}",
        exit.hostname,
        free_socket.local_addr().unwrap()
    );
    let (send_routes, recv_routes) = flume::bounded(0);
    let manage_fut = async {
        loop {
            if let Err(err) = manage_exit_once(
                &exit,
                &bridge_secret,
                &bridge_group,
                free_socket.local_addr().unwrap(),
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
        let mut route_delete: Option<String> = None;
        let mut last_remote_port = 0;
        loop {
            let (remote_port, _) = recv_routes.recv_async().await?;
            if remote_port != last_remote_port {
                if let Some(delete_command) = route_delete.take() {
                    run_command(&delete_command);
                }
                run_command(&format!(
                "iptables -t nat -A PREROUTING -p udp --dport {} -j DNAT --to-destination {}:{}",
                free_socket.local_addr().unwrap().port(),
                remote_addr.ip(), remote_port
            ));
                route_delete = Some(format!(
                "iptables -t nat -D PREROUTING -p udp --dport {} -j DNAT --to-destination {}:{}",
                free_socket.local_addr().unwrap().port(),
                remote_addr.ip(), remote_port
            ));
                last_remote_port = remote_port
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

async fn manage_exit_once(
    exit: &ExitDescriptor,
    bridge_secret: &str,
    bridge_group: &str,
    mut my_addr: SocketAddr,
    route_update: &flume::Sender<(u16, x25519_dalek::PublicKey)>,
) -> anyhow::Result<()> {
    // get my ip address
    log::info!("trying to get IP...");
    let my_ip = smol::unblock(|| {
        ureq::get("http://checkip.amazonaws.com/")
            .call()
            .into_string()
            .unwrap()
            .trim()
            .to_string()
    })
    .await;
    log::info!("my IP is {}", my_ip);
    my_addr.set_ip(my_ip.parse().unwrap());
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
        write_pascalish(&mut conn, &(my_addr, bridge_group)).await?;
        // receive route
        let (port, sosistab_pk): (u16, x25519_dalek::PublicKey) = read_pascalish(&mut conn).await?;
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

async fn read_pascalish<T: DeserializeOwned>(
    reader: &mut (impl AsyncRead + Unpin),
) -> anyhow::Result<T> {
    // first read 2 bytes as length
    let mut len_bts = [0u8; 2];
    reader.read_exact(&mut len_bts).await?;
    let len = u16::from_be_bytes(len_bts);
    // then read len
    let mut true_buf = vec![0u8; len as usize];
    reader.read_exact(&mut true_buf).await?;
    // then deserialize
    Ok(bincode::deserialize(&true_buf)?)
}

async fn write_pascalish<T: Serialize>(
    writer: &mut (impl AsyncWrite + Unpin),
    value: &T,
) -> anyhow::Result<()> {
    let serialized = bincode::serialize(value).unwrap();
    assert!(serialized.len() <= 65535);
    // write bytes
    writer
        .write_all(&(serialized.len() as u16).to_be_bytes())
        .await?;
    writer.write_all(&serialized).await?;
    Ok(())
}
