use crate::{ios::LOG_BUFFER, plots::stat_derive};
use anyhow::Context;
use chrono::{Datelike, Timelike, Utc};
use geph4_protocol::tunnel::{activity::wait_activity, ClientTunnel};
use http_types::headers::{HeaderValue, ToHeaderValues};
use std::{collections::BTreeMap, net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

/// Prints stats in a loop.
pub async fn print_stats_loop(tun: Arc<ClientTunnel>) {
    loop {
        wait_activity(Duration::from_secs(200)).await;
        let stats = tun.get_stats().await;
        log::info!("** recv_loss = {:.2}% **", stats.last_loss * 100.0);
        smol::Timer::after(Duration::from_secs(30)).await;
    }
}

/// Serves stats at stats_listen addr via http
pub async fn serve_stats(tun: Arc<ClientTunnel>, stats_listen: SocketAddr) -> anyhow::Result<()> {
    let stat_listener = smol::net::TcpListener::bind(stats_listen)
        .await
        .context("cannot bind stats")?;
    loop {
        let (stat_client, _) = stat_listener.accept().await?;
        let tun = tun.clone();
        smolscale::spawn(async move {
            drop(
                async_h1::accept(stat_client, move |req| {
                    let tun = tun.clone();
                    async move { handle_stats(tun, req).await }
                })
                .await,
            );
        })
        .detach();
    }
}

/// Handles requests for the debug pack, proxy information, program termination, and general statistics
async fn handle_stats(
    tun: Arc<ClientTunnel>,
    req: http_types::Request,
) -> http_types::Result<http_types::Response> {
    let stats = tun.get_stats().await;
    // If the GEPH_SECURE_STATS environment variable is set, we must have X-Geph-Stats-Token set to that environment variable.
    if let Ok(s) = std::env::var("GEPH_SECURE_STATS") {
        if req
            .header("X-Geph-Stats-Token")
            .map(|f| f.as_str().to_string())
            .unwrap_or_default()
            != s
        {
            return Err(http_types::Error::new(403, anyhow::anyhow!("denied")));
        }
    }
    let mut res = http_types::Response::new(http_types::StatusCode::Ok);
    res.insert_header("Access-Control-Allow-Origin", "*");
    match req.url().path() {
        "/proxy.pac" => {
            // Serves a Proxy Auto-Configuration file
            res.set_body("function FindProxyForURL(url, host){return 'PROXY 127.0.0.1:9910';}");
            Ok(res)
        }
        "/rawstats" => Ok(res),
        "/deltastats" => {
            // Serves all the delta stats as json
            let body_str = smol::unblock(move || {
                let detail = stat_derive(stats);
                serde_json::to_string(&detail)
            })
            .await?;
            res.set_body(body_str);
            res.set_content_type(http_types::mime::JSON);
            Ok(res)
        }
        "/logs" => {
            let now = Utc::now();
            let filename = format!(
                "filename=\"{}-{:02}-{:02}-{:02}:{:02}.txt\"",
                now.year(),
                now.month(),
                now.day(),
                now.hour(),
                now.minute()
            );
            res.insert_header(
                "Content-Disposition",
                "attachment", // &vec![
                              //     HeaderValue::from_str("attachment").unwrap(),
                              //     HeaderValue::from_str(&filename).unwrap(),
                              // // ]
                              // .iter(),
            );
            res.set_body(LOG_BUFFER.lock().get_logs());
            Ok(res)
        }
        "/kill" => std::process::exit(0),
        _ => {
            // Serves all the stats as json
            if tun.is_connected() {
                let mut stats_map: BTreeMap<String, f32> = BTreeMap::new();
                stats_map.insert("total_tx".into(), stats.total_sent_bytes);
                stats_map.insert("total_rx".into(), stats.total_recv_bytes);
                stats_map.insert("latency".into(), stats.last_ping);
                stats_map.insert("loss".into(), stats.last_loss);

                res.set_body(serde_json::to_string(&stats_map)?);
                res.set_content_type(http_types::mime::JSON);
            }
            Ok(res)
        }
    }
}
