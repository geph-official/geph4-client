use std::{
    convert::TryInto,
    sync::Arc,
    time::{Duration, Instant},
};

use rand::prelude::*;
use smol::prelude::*;

const CONN_COUNT: usize = 1000;

fn main() {
    env_logger::init();
    smolscale::spawn(run_server()).detach();
    smolscale::block_on(run_client())
}

async fn run_server() {
    let mut badrng = rand::rngs::StdRng::seed_from_u64(0);
    let long_sk = x25519_dalek::StaticSecret::new(&mut badrng);
    let listener = sosistab::Listener::listen("127.0.0.1:23456", long_sk).await;
    loop {
        let socket = listener.accept_session().await.unwrap();
        smolscale::spawn(async move {
            let mplex = sosistab::mux::Multiplex::new(socket);
            loop {
                let conn = mplex.accept_conn().await.unwrap();
                smolscale::spawn(smol::io::copy(conn.clone(), conn.clone())).detach();
            }
        })
        .detach();
    }
}

async fn run_client() {
    let pubkey_bts: [u8; 32] =
        hex::decode("52a3c5c5fdba402c46aa4d7088a7d9c742b16fede34f8f5beb788f59501b176b")
            .unwrap()
            .try_into()
            .unwrap();
    smol::Timer::after(Duration::from_secs(1)).await;
    println!("spawning {} idle connections...", CONN_COUNT);
    let session = sosistab::connect("127.0.0.1:23456".parse().unwrap(), pubkey_bts.into())
        .await
        .unwrap();
    let mux = Arc::new(sosistab::mux::Multiplex::new(session));
    let mut conns = Vec::new();
    for _ in 0..CONN_COUNT {
        let mux = mux.clone();
        conns.push(smolscale::spawn(async move {
            let start = Instant::now();
            let conn = mux.open_conn(None).await.unwrap();
            println!("took {} ms", start.elapsed().as_millis());
            conn
        }));
    }
    println!("sleeping for 5 seconds...");
    smol::Timer::after(Duration::from_secs(10)).await;
    println!("sending 10 KB through each of the connections..");
    for task in conns
        .into_iter()
        .map(|conn| {
            smolscale::spawn(async move {
                let mut conn = conn.await;
                println!("ready");
                for _ in 0..10 {
                    let mut buf = [0u8; 1024];
                    conn.write_all(&buf).await.unwrap();
                    conn.read_exact(&mut buf).await.unwrap();
                }
            })
        })
        .collect::<Vec<_>>()
    {
        task.await
    }
}
