use smol::prelude::*;
use std::convert::TryInto;
use std::io::prelude::*;
use std::net::{TcpListener, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() {
    // println!("YOH");
    env_logger::init();
    smol::block_on(async {
        // let guard = pprof::ProfilerGuard::new(1000).unwrap();
        let args: Vec<String> = std::env::args().collect();
        let pubkey_bts: [u8; 32] = hex::decode(&args.get(2).unwrap_or(
            &"52a3c5c5fdba402c46aa4d7088a7d9c742b16fede34f8f5beb788f59501b176b".to_string(),
        ))
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();
        let session = sosistab::connect(
            smol::unblock(move || {
                (&args.get(1).unwrap_or(&"172.105.240.170:23456".to_string()))
                    .to_socket_addrs()
                    .unwrap()
                    .next()
                    .unwrap()
            })
            .await,
            x25519_dalek::PublicKey::from(pubkey_bts),
        )
        .await
        .unwrap();
        eprintln!("session established to remote!");
        let mplex = Arc::new(sosistab::mux::Multiplex::new(session));
        {
            let mplex = mplex.clone();
            smol::spawn(async move {
                loop {
                    smol::Timer::after(Duration::from_secs(5)).await;
                    let stats = mplex.get_session().get_stats().await;
                    eprintln!(
                        "STATS: total down {} packets; raw loss {:.3}%; processed loss {:.3}%; overhead {:.3}%",
                        stats.down_total,
                        stats.down_loss * 100.0,
                        stats.down_recovered_loss * 100.0,
                        stats.down_redundant*100.0,
                    );
                }
            })
            .detach()
        }
        let client_listen = smol::Async::new(TcpListener::bind("localhost:3131").unwrap()).unwrap();
        loop {
            let (client, _) = client_listen.accept().await.unwrap();
            let client = async_dup::Arc::new(client);
            let mplex = mplex.clone();
            smol::spawn(async move {
                let start = Instant::now();
                let remote = mplex.open_conn().await.unwrap();
                let diff = Instant::now().saturating_duration_since(start);
                eprintln!("opened connection in {} ms", diff.as_millis());
                drop(
                    smol::future::race(
                        smol::io::copy(client.clone(), remote.clone()),
                        smol::io::copy(remote, client),
                    )
                    .await,
                );
            })
            .detach();
            // if let Ok(report) = guard.report().build() {
            //     let file = std::fs::File::create("flamegraph.svg").unwrap();
            //     report.flamegraph(file).unwrap();
            // };
        }
    })
}
