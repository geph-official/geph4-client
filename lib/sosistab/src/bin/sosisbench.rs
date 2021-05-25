use std::{
    convert::TryInto,
    net::SocketAddr,
    sync::{atomic::AtomicUsize, Arc},
    time::Instant,
};

use anyhow::Context;
use argh::FromArgs;
use once_cell::sync::Lazy;

use rand_chacha::rand_core::SeedableRng;
use smol::prelude::*;

#[derive(FromArgs, PartialEq, Debug)]
/// Top level
struct Args {
    #[argh(subcommand)]
    nested: Subcmds,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
/// Command-line arguments.
enum Subcmds {
    Client(ClientArgs),
    Server(ServerArgs),
    Flood(FloodArgs),
    SelfTest(SelfTestArgs),
}

/// Client
#[derive(FromArgs, PartialEq, Debug, Clone)]
#[argh(subcommand, name = "client")]
struct ClientArgs {
    #[argh(option)]
    /// host:port of the server
    connect: String,
}

/// Client
#[derive(FromArgs, PartialEq, Debug, Clone)]
#[argh(subcommand, name = "flood")]
struct FloodArgs {
    #[argh(option)]
    /// host:port of the server
    connect: String,
    #[argh(option)]
    /// public key of the server
    server_pk: String,
}

/// Client
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "server")]
struct ServerArgs {
    #[argh(option)]
    /// listening address
    listen: SocketAddr,
}

/// Self test
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "selftest")]
struct SelfTestArgs {}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args: Args = argh::from_env();
    match args.nested {
        Subcmds::Flood(flood) => smolscale::block_on(flood_main(flood)),
        Subcmds::Client(client) => smolscale::block_on(client_main(client)),
        Subcmds::Server(server) => smolscale::block_on(server_main(server)),
        Subcmds::SelfTest(_) => {
            let client_args = ClientArgs {
                connect: "127.0.0.1:19999".into(),
            };
            let server_args = ServerArgs {
                listen: "127.0.0.1:19999".parse().unwrap(),
            };
            smolscale::block_on(async move {
                // for _ in 0..100 {
                smolscale::spawn(client_main(client_args.clone())).detach();
                // }
                server_main(server_args).await
            })
        }
    }
}

static SNAKEOIL_SK: Lazy<x25519_dalek::StaticSecret> =
    Lazy::new(|| x25519_dalek::StaticSecret::new(&mut rand_chacha::ChaCha8Rng::seed_from_u64(0)));

async fn flood_main(args: FloodArgs) -> anyhow::Result<()> {
    let server_addr = smol::net::resolve(&args.connect)
        .await
        .context("cannot resolve")?[0];
    let server_pk: [u8; 32] = hex::decode(&args.server_pk).unwrap().try_into().unwrap();
    let server_pk = x25519_dalek::PublicKey::from(server_pk);
    let count = Arc::new(AtomicUsize::default());
    for _ in 0..128 {
        let count = count.clone();
        smolscale::spawn(async move {
            loop {
                let start = Instant::now();
                eprintln!("connecting to {}...", server_addr);
                let session = sosistab::connect_udp(server_addr, server_pk, Default::default())
                    .await
                    .context("cannot connect to sosistab")
                    .unwrap();
                count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                eprintln!(
                    "spammed {} sessions (last {:?})",
                    count.load(std::sync::atomic::Ordering::Relaxed),
                    start.elapsed()
                );
                session.send_bytes(vec![0u8; 10000].into()).await.unwrap();
            }
        })
        .detach();
    }
    smol::future::pending().await
}

async fn client_main(args: ClientArgs) -> anyhow::Result<()> {
    // smolscale::permanently_single_threaded();
    let start = Instant::now();
    let session = sosistab::connect_udp(
        smol::net::resolve(&args.connect)
            .await
            .context("cannot resolve")?[0],
        (&*SNAKEOIL_SK).into(),
        Default::default(),
    )
    .await
    .context("cannot connect to sosistab")?;
    eprintln!("Session established in {:?}", start.elapsed());
    let mux = sosistab::Multiplex::new(session);
    let start = Instant::now();
    let mut conn = mux.open_conn(None).await?;
    eprintln!("RelConn established in {:?}", start.elapsed());
    let mut buffer = [0u8; 16384];
    let start = Instant::now();
    for buffs in 1u128..=1000000 {
        conn.read_exact(&mut buffer).await?;
        let total_bytes = (buffs as f64) * 16384.0;
        let total_time = start.elapsed().as_secs_f64();
        let mega_per_secs = total_bytes / 1048576.0 / total_time;
        if buffs % 10 == 0 {
            eprintln!(
                "downloaded {:.2} MB in {:.2} secs ({:.2} Mbps, {:.3} MB/s)",
                total_bytes / 1048576.0,
                total_time,
                mega_per_secs * 8.0,
                mega_per_secs
            )
        }
    }
    eprintln!("got all 1000000 buffers right!");
    Ok(())
}

async fn server_main(args: ServerArgs) -> anyhow::Result<()> {
    let listener =
        sosistab::Listener::listen_udp(args.listen, SNAKEOIL_SK.clone(), |_, _| (), |_, _| ())
            .await?;
    for count in 1u128.. {
        let session = listener
            .accept_session()
            .await
            .ok_or_else(|| anyhow::anyhow!("failed to accept"))?;
        eprintln!("accepted session {}", count);
        let forked: smol::Task<anyhow::Result<()>> = smolscale::spawn(async move {
            let mux = sosistab::Multiplex::new(session);
            loop {
                let mut conn = mux.accept_conn().await?;
                eprintln!("accepted connection for session {}", count);
                let buff = [0u8; 16384];
                for _ in 0..1000000 {
                    conn.write_all(&buff).await?;
                }
            }
        });
        forked.detach();
    }
    unreachable!()
}
