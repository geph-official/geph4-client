use std::{
    ops::Deref,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rusqlite::{backup, params, Connection};
use serde::{Deserialize, Serialize};
use smol::{channel::Sender, Task};
use structopt::StructOpt;

use crate::{
    config::{CommonOpt, CONFIG},
    ALLOCATOR,
};

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
    send_timeseries: Sender<(String, f64)>,
}

pub static DEBUGPACK: Lazy<Arc<DebugPack>> = Lazy::new(|| {
    let dp = match CONFIG.deref() {
        crate::config::Opt::Connect(connect_opt) => {
            DebugPack::new(&connect_opt.common.debugpack_path).unwrap()
        }
        crate::config::Opt::BridgeTest(bt_pot) => {
            DebugPack::new(&bt_pot.common.debugpack_path).unwrap()
        }
        crate::config::Opt::Sync(sync_opt) => {
            DebugPack::new(&sync_opt.common.debugpack_path).unwrap()
        }
        crate::config::Opt::BinderProxy(bp_opt) => {
            DebugPack::new(&bp_opt.common.debugpack_path).unwrap()
        }
        crate::config::Opt::Debugpack(dp_opt) => {
            DebugPack::new(&dp_opt.common.debugpack_path).unwrap()
        }
    };

    Arc::new(dp)
});

pub static START_TIME: Lazy<Instant> = Lazy::new(Instant::now);

pub static TIMESERIES_LOOP: Lazy<Task<()>> = Lazy::new(|| {
    smolscale::spawn(async {
        loop {
            DEBUGPACK.add_timeseries("memory", ALLOCATOR.allocated() as f64);
            DEBUGPACK.add_timeseries("uptime", START_TIME.elapsed().as_secs_f64());

            smol::Timer::after(Duration::from_secs(10)).await;
        }
    })
});

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
            let mut stmt = conn.prepare("select cast(strftime('%s', timestamp) as integer), line from loglines where timestamp > datetime(?1, 'unixepoch')")?;
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

pub(crate) fn export_debugpak(dest: &str) -> anyhow::Result<()> {
    DEBUGPACK.backup(dest)
}
