use async_net::SocketAddr;
use smol::prelude::*;
use std::{
    process::{ExitStatus, Stdio},
    time::{Duration, Instant},
};

async fn system(line: &str) -> ExitStatus {
    let mut proc = smol::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(line)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .spawn()
        .unwrap();
    proc.status().await.unwrap()
}

pub async fn nettest(nettest_name: String, nettest_server: SocketAddr) {
    let stat_client = statsd::Client::new(nettest_server, &nettest_name).unwrap();
    loop {
        log::info!("Measuring 1MB cachefly speed:");
        let cachefly_time = measure_time(async {
            system("curl -v --proxy socks5h://localhost:9909 https://cachefly.cachefly.net/1mb.test > /dev/null").await;
        }).await;
        stat_client.timer("cachefly.duration", cachefly_time.as_millis() as _);
        smol::Timer::after(Duration::from_secs(30)).await;
    }
}

async fn measure_time(fut: impl Future<Output = ()>) -> Duration {
    let start = Instant::now();
    fut.await;
    start.elapsed()
}
