use std::{
    ops::Deref,
    sync::Arc,
    time::{Duration, Instant},
};

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rusqlite::{backup, params, Connection};
use serde::{Deserialize, Serialize};
use smol::Task;
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
            let allocated = ALLOCATOR.allocated();
            let _ = DEBUGPACK.add_timeseries("memory", allocated as f64);
            let _ = DEBUGPACK.add_timeseries("uptime", START_TIME.elapsed().as_secs_f64());

            smol::Timer::after(Duration::from_secs(1)).await;
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

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn add_logline(&self, logline: &str) -> anyhow::Result<()> {
        self.conn.lock().execute(
            "insert into loglines (timestamp, line) values (datetime(), ?)",
            params![logline],
        )?;
        Ok(())
    }

    pub fn add_timeseries(&self, key: &str, value: f64) -> anyhow::Result<()> {
        self.conn.lock().execute(
            "insert into timeseries (timestamp, key, value) values (datetime(), ?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn backup(&self, dest: &str) -> anyhow::Result<()> {
        let mut dst = Connection::open(dest)?;
        let src = self.conn.lock();
        let backup = backup::Backup::new(&src, &mut dst)?;
        backup.run_to_completion(5, Duration::from_millis(100), None)?;
        Ok(())
    }
}

pub(crate) fn export_debugpak(dest: &str) -> anyhow::Result<()> {
    DEBUGPACK.backup(dest)
}
