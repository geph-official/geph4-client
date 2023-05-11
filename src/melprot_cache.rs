use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;

use tap::Tap;

/// A flat-file based state cache for melprot
pub struct FlatFileStateCache {
    root: PathBuf,
}

impl FlatFileStateCache {
    /// Creates a new flat-file based state cache.
    pub fn open(root: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(root)?;
        Ok(Self {
            root: root.to_owned(),
        })
    }
}

#[async_trait]
impl melprot::StateCache for FlatFileStateCache {
    async fn get_blob(&self, key: &[u8]) -> Option<Bytes> {
        let key_hex = hex::encode(key);
        let path = self.root.clone().tap_mut(|p| p.push(&key_hex));
        let val = smol::fs::read(&path).await.ok();
        log::debug!(
            "read {:?}; hit? {}",
            String::from_utf8_lossy(key),
            val.is_some()
        );
        Some(val?.into())
    }

    async fn insert_blob(&self, key: &[u8], value: &[u8]) {
        let key = hex::encode(key);
        log::debug!("write {key}");
        let mut path = self.root.clone();
        path.push(&key);
        let _ = smol::fs::write(&path, value).await;
    }
}
