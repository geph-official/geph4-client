use std::{convert::TryInto, path::PathBuf};

use serde::Serialize;
use smol::prelude::*;

pub fn str_to_path(src: &str) -> PathBuf {
    // if it's auto then generate
    if src == "auto" {
        let mut config_dir = dirs::config_dir().unwrap();
        config_dir.push("geph4-credentials");
        config_dir
    } else {
        PathBuf::from(src)
    }
}

pub fn str_to_x25519_pk(src: &str) -> x25519_dalek::PublicKey {
    let raw_bts = hex::decode(src).unwrap();
    let raw_bts: [u8; 32] = raw_bts.as_slice().try_into().unwrap();
    x25519_dalek::PublicKey::from(raw_bts)
}

pub fn str_to_mizaru_pk(src: &str) -> mizaru::PublicKey {
    let raw_bts = hex::decode(src).unwrap();
    let raw_bts: [u8; 32] = raw_bts.as_slice().try_into().unwrap();
    mizaru::PublicKey(raw_bts)
}

pub async fn write_pascalish<T: Serialize>(
    writer: &mut (impl AsyncWrite + Unpin),
    value: &T,
) -> anyhow::Result<()> {
    let serialized = bincode::serialize(value).unwrap();
    assert!(serialized.len() <= 65535);
    // write bytes
    writer
        .write_all(&(serialized.len() as u16).to_be_bytes())
        .await?;
    writer.write_all(&serialized).await?;
    Ok(())
}
