use lmdb::Transaction;
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;

/// A key-value database, backed by LMDB.
#[derive(Debug)]
pub struct KVDatabase {
    lm_env: lmdb::Environment,
    lm_db: lmdb::Database,
}

impl KVDatabase {
    /// Opens a database, given a path.
    pub fn open(folder_path: &Path) -> anyhow::Result<KVDatabase> {
        let lm_env = lmdb::Environment::new().open(folder_path)?;
        let lm_db = lm_env.open_db(None)?;
        Ok(KVDatabase { lm_env, lm_db })
    }

    /// Opens a reading transaction.
    pub fn read(&self) -> KVRead<'_> {
        let txn = self.lm_env.begin_ro_txn().unwrap();
        KVRead {
            txn,
            lm_db: self.lm_db,
        }
    }

    /// Opens a writing transaction.
    pub fn write(&self) -> KVWrite<'_> {
        let txn = self.lm_env.begin_rw_txn().unwrap();
        KVWrite {
            txn,
            lm_db: self.lm_db,
        }
    }
}

/// A reading transaction.
pub struct KVRead<'a> {
    txn: lmdb::RoTransaction<'a>,
    lm_db: lmdb::Database,
}

impl<'a> KVRead<'a> {
    /// Read something
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        match self.txn.get(self.lm_db, &key.as_bytes()) {
            Ok(val) => Some(bincode::deserialize(val).expect("deserialization failed?!")),
            Err(lmdb::Error::NotFound) => None,
            Err(e) => panic!("unexpected lmdb error: {}", e),
        }
    }
}

/// A writing transaction.
pub struct KVWrite<'a> {
    txn: lmdb::RwTransaction<'a>,
    lm_db: lmdb::Database,
}

impl<'a> KVWrite<'a> {
    /// Read something
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        match self.txn.get(self.lm_db, &key.as_bytes()) {
            Ok(val) => Some(bincode::deserialize(val).expect("deserialization failed?!")),
            Err(lmdb::Error::NotFound) => None,
            Err(e) => panic!("unexpected lmdb error: {}", e),
        }
    }

    /// Write something
    pub fn insert<T: Serialize>(&mut self, key: &str, value: T) {
        self.txn
            .put(
                self.lm_db,
                &key.as_bytes(),
                &bincode::serialize(&value).unwrap(),
                lmdb::WriteFlags::default(),
            )
            .expect("lmdb write failed");
    }

    /// Commit to disk
    pub fn commit(self) {
        self.txn.commit().expect("lmdb commit failed")
    }
}
