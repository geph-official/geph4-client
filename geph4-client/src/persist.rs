use anyhow::Context;
use rusqlite::{Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Serialize};
use std::path::{Path, PathBuf};

/// A key-value database, backed by SQLite.
#[derive(Debug)]
pub struct KVDatabase {
    path: PathBuf,
    conn: Connection,
}

impl KVDatabase {
    /// Opens a database, given a path.
    pub fn open(folder_path: &Path) -> anyhow::Result<KVDatabase> {
        let conn = Connection::open(folder_path)?;
        conn.execute::<&[u8]>(
            "create table if not exists kvv (key blob primary key not null, value blob not null)",
            &[],
        )
        .context("can't create table")?;
        Ok(KVDatabase {
            path: folder_path.to_owned(),
            conn: Connection::open(folder_path)?,
        })
    }

    /// Opens a transaction.
    pub fn transaction(&mut self) -> KVTransaction<'_> {
        let txn = self.conn.transaction().unwrap();
        KVTransaction { txn }
    }
}
/// A writing transaction.
pub struct KVTransaction<'a> {
    txn: rusqlite::Transaction<'a>,
}

impl<'a> KVTransaction<'a> {
    /// Read something
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        let val: Option<Vec<u8>> = self
            .txn
            .query_row(
                "select value from kvv where key = $1",
                &[&key.as_bytes()],
                |row| row.get(0),
            )
            .optional()
            .unwrap();

        match val {
            Some(val) => Some(bincode::deserialize(&val).expect("deserialization failed?!")),
            None => None,
        }
    }

    /// Write something
    pub fn insert<T: Serialize>(&mut self, key: &str, value: T) {
        self.txn
            .execute(
                "insert or replace into kvv values ($1, $2)",
                &[key.as_bytes(), &bincode::serialize(&value).unwrap()],
            )
            .expect("sqlite write failed");
    }

    /// Commit to disk
    pub fn commit(self) {
        self.txn.commit().expect("sqlite commit failed")
    }
}
