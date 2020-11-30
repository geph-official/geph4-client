use std::process::Stdio;

use once_cell::sync::Lazy;
use smol::prelude::*;
use tundevice::TunDevice;
use vpn_structs::StdioMsg;

/// The raw TUN device.
static RAW_TUN: Lazy<TunDevice> = Lazy::new(|| {
    log::info!("initializing tun-geph");
    TunDevice::new_from_os("tun-geph").expect("could not initiate 'tun-geph' tun device!")
});

fn main() {
    smol::block_on(async move {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut child = smol::process::Command::new("/usr/bin/env")
            .arg("su")
            .arg("nobody")
            .arg("-s")
            .arg(&args[0])
            .arg("--")
            .args(&args[1..])
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut child_output = child.stdout.take().unwrap();
        let mut child_input = child.stdin.take().unwrap();
        // two loops
        let read_loop = async {
            loop {
                let bts = RAW_TUN.read_raw().await.unwrap();
                StdioMsg { verb: 0, body: bts }
                    .write(&mut child_input)
                    .await
                    .unwrap();
                child_input.flush().await.unwrap();
            }
        };
        let write_loop = async {
            loop {
                let msg = StdioMsg::read(&mut child_output).await.unwrap();
                match msg.verb {
                    0 => RAW_TUN.write_raw(msg.body).await.unwrap(),
                    1 => RAW_TUN.assign_ip(&String::from_utf8_lossy(&msg.body)),
                    _ => log::warn!("invalid verb kind: {}", msg.verb),
                }
            }
        };
        smol::future::race(read_loop, write_loop).await
    })
}
