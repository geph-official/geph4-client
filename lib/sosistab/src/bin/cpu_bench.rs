use std::{convert::TryInto, time::Duration};

use governor::{Quota, RateLimiter};
use nonzero_ext::nonzero;
use rand::prelude::*;

static EXEC: smol::Executor<'static> = smol::Executor::new();

fn main() {
    sosistab::runtime::set_smol_executor(&EXEC);
    env_logger::init();
    EXEC.spawn(run_server()).detach();
    smol::block_on(EXEC.run(run_client()))
}

async fn run_server() {
    let mut badrng = rand::rngs::StdRng::seed_from_u64(0);
    let long_sk = x25519_dalek::StaticSecret::new(&mut badrng);
    let listener =
        sosistab::Listener::listen("127.0.0.1:23456", long_sk, |_, _| (), |_, _| ()).await;
    loop {
        let socket = listener.accept_session().await.unwrap();
        EXEC.spawn(async move {
            let mplex = sosistab::mux::Multiplex::new(socket);
            loop {
                let pkt = mplex.recv_urel().await.unwrap();
                mplex.send_urel(pkt).unwrap();
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
    let session = sosistab::connect("127.0.0.1:23456".parse().unwrap(), pubkey_bts.into())
        .await
        .unwrap();
    let mux = sosistab::mux::Multiplex::new(session);
    let up_loop = async {
        let lim = RateLimiter::direct(Quota::per_second(nonzero!(10000u32)));
        for count in 0u128.. {
            mux.send_urel(vec![0; 1024].into()).unwrap();
            if count % 1000 == 0 {
                eprintln!("{} packets sent", count);
            }
            lim.until_ready().await;
        }
    };
    let dn_loop = async {
        for count in 0u128.. {
            let _ = mux.recv_urel().await.unwrap();
            if count % 1000 == 0 {
                eprintln!("{} packets received", count)
            }
        }
    };
    smol::future::race(up_loop, dn_loop).await
}
