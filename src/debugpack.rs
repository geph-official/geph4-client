use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rusqlite::{backup, params, Connection};
use serde::{Deserialize, Serialize};
use smol::channel::Sender;
use structopt::StructOpt;

use crate::config::CommonOpt;

#[derive(Debug, StructOpt, Deserialize, Serialize, Clone)]
pub struct DebugPackOpt {
    #[structopt(flatten)]
    pub common: CommonOpt,

    #[structopt(long)]
    pub export_to: String, // path of file to backup DB to
}

pub struct DebugPack {
    conn: Arc<Mutex<Connection>>,
    send_log: Sender<String>,
    #[allow(dead_code)]
    send_timeseries: Sender<(String, f64)>,
}

#[allow(dead_code)]
pub static START_TIME: Lazy<Instant> = Lazy::new(Instant::now);

impl DebugPack {
    pub fn new(db_path: &str) -> anyhow::Result<Self> {
        // open database & create tables if not exist
        let conn = Connection::open(db_path)?;
        conn.execute(
            "create table if not exists timeseries (
                timestamp timestamp,
                key text,
                value real)",
            [],
        )?;
        conn.execute(
            "create table if not exists loglines (
                timestamp timestamp,
                line text)",
            [],
        )?;

        conn.execute(
            "create index if not exists loglines_idx on loglines (timestamp)",
            [],
        )?;
        conn.execute(
            "create index if not exists timeseries_idx on loglines (timestamp)",
            [],
        )?;

        conn.execute(
            "delete from loglines where datetime(timestamp, '+1 day') < datetime()",
            params![],
        )?;
        conn.execute(
            "delete from timeseries where datetime(timestamp, '+1 day') < datetime()",
            params![],
        )?;

        let (send_log, recv_log) = smol::channel::bounded(10);
        let db_path2 = db_path.to_string();
        std::thread::spawn(move || {
            let conn = Connection::open(db_path2).unwrap();
            while let Ok(next) = recv_log.recv_blocking() {
                if let Err(err) = conn.execute(
                    "insert into loglines (timestamp, line) values (datetime(), ?1)",
                    params![next],
                ) {
                    log::error!("cannot write logline: {}", err)
                }
            }
        });
        let (send_timeseries, recv_timeseries) = smol::channel::bounded(10);
        let db_path2 = db_path.to_string();
        std::thread::spawn(move || {
            let conn = Connection::open(db_path2).unwrap();
            while let Ok((key, value)) = recv_timeseries.recv_blocking() {
                if let Err(err) = conn.execute(
                    "insert into timeseries (timestamp, key, value) values (datetime(), ?1, ?2)",
                    params![key, value],
                ) {
                    log::error!("cannot write logline: {}", err)
                }
            }
        });

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            send_log,
            send_timeseries,
        })
    }

    pub fn add_logline(&self, logline: &str) {
        let _ = self.send_log.try_send(logline.into());
    }

    #[allow(dead_code)]
    pub fn add_timeseries(&self, key: &str, value: f64) {
        let _ = self.send_timeseries.try_send((key.to_string(), value));
    }

    pub fn backup(&self, dest: &str) -> anyhow::Result<()> {
        let mut dst = Connection::open(dest)?;
        let src = self.conn.lock();
        let backup = backup::Backup::new(&src, &mut dst)?;
        backup.run_to_completion(100, Duration::from_millis(1), None)?;
        Ok(())
    }

    pub async fn get_loglines(
        &self,
        after: SystemTime,
    ) -> anyhow::Result<Vec<(SystemTime, String)>> {
        let conn = self.conn.clone();
        smol::unblock(move || {
            let conn = conn.lock();
            let mut stmt = conn.prepare("select cast(strftime('%s', timestamp) as integer), line from loglines where timestamp > datetime(?1, 'unixepoch') limit 2000")?;
            let after_timestamp = after.duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
            let rows = stmt.query_map(params![after_timestamp], |row| {
                let timestamp: i64 = row.get(0)?;
                let line: String = row.get(1)?;
                let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp as u64);
                Ok((timestamp, line))
            })?;

            let mut results = Vec::new();
            for row_result in rows {
                results.push(row_result?);
            }

            Ok(results)
        })
        .await
    }
}
