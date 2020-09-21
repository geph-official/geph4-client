use std::{convert::TryInto, sync::Arc, time::Instant};

use async_net::SocketAddr;
use async_rwlock::RwLock;
use etherparse::{SlicedPacket, TransportSlice};
use governor::{Quota, RateLimiter};
use nonzero_ext::nonzero;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "geph4-vpntest",
    about = "VPN testing tool for Geph protocol-suite things"
)]
enum Opt {
    Server {
        sk_seed: String,
    },
    Client {
        server_addr: SocketAddr,
        server_pk: String,
    },
}

fn main() {
    let opt = Opt::from_args();
    env_logger::init();
    match opt {
        Opt::Server { sk_seed } => main_server(sk_seed),
        Opt::Client {
            server_addr,
            server_pk,
        } => main_client(server_addr, server_pk),
    }
}

fn main_server(sk_seed: String) {
    let long_sk: [u8; 32] = *blake3::hash(sk_seed.as_bytes()).as_bytes();
    let long_sk = x25519_dalek::StaticSecret::from(long_sk);
    let mut tun_device = tundevice::TunDevice::new_from_os("tun-geph").unwrap();
    tun_device.assign_ip("100.64.89.10".parse().unwrap());
    let tun_device = Arc::new(tun_device);
    async_global_executor::block_on(async move {
        let listener = sosistab::Listener::listen("0.0.0.0:23456", long_sk.clone()).await;
        println!(
            "Listening on port 23456; PK = {}",
            hex::encode(x25519_dalek::PublicKey::from(&long_sk).to_bytes())
        );
        loop {
            let session = listener
                .accept_session()
                .await
                .expect("can't accept more sessions?!");
            handle_server_client(session, tun_device.clone()).await;
        }
    })
}

async fn handle_server_client(session: sosistab::Session, tun_device: Arc<tundevice::TunDevice>) {
    let lim = RateLimiter::keyed(Quota::per_second(nonzero!(100u32)));
    smol::future::race(
        async {
            loop {
                // read from tun
                let incoming_from_tun = tun_device.read_raw().await.unwrap();
                match SlicedPacket::from_ip(&incoming_from_tun[4..]) {
                    Ok(pkt) => {
                        if let Some(TransportSlice::Tcp(slice)) = pkt.transport {
                            if slice.ack()
                                && !slice.rst()
                                && !slice.syn()
                                && !slice.fin()
                                && pkt.payload.is_empty()
                                && lim.check_key(&slice.source_port()).is_err()
                            {
                                continue;
                            }
                        }
                    }
                    Err(err) => eprintln!("error: {} in {:?}", err, incoming_from_tun),
                }
                session.send_bytes(incoming_from_tun).await;
            }
        },
        async {
            loop {
                // incoming from session
                let incoming_from_session = session.recv_bytes().await;
                tun_device.write_raw(&incoming_from_session).await.unwrap();
            }
        },
    )
    .await;
}

fn main_client(server_addr: SocketAddr, server_pk: String) {
    let mut tun_device = tundevice::TunDevice::new_from_os("tun-geph").unwrap();
    tun_device.assign_ip("100.64.89.11".parse().unwrap());
    let tun_device = Arc::new(tun_device);

    async_global_executor::block_on(async move {
        let server_pk: [u8; 32] = hex::decode(server_pk)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let server_pk = x25519_dalek::PublicKey::from(server_pk);
        let session = sosistab::connect(server_addr, server_pk).await.unwrap();
        handle_server_client(session, tun_device).await;
    });
}
