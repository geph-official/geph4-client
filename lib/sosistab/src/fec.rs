use bytes::{Bytes, BytesMut};

mod decoder;
mod encoder;
mod wrapped;
pub use decoder::*;
pub use encoder::*;

pub fn pre_encode(pkt: &[u8], len: usize) -> BytesMut {
    assert!(pkt.len() <= 65535);
    assert!(pkt.len() + 2 <= len);
    // tracing::trace!("pre-encoding pkt with len {} => {}", pkt.len(), len);
    let hdr = (pkt.len() as u16).to_le_bytes();
    let mut bts = BytesMut::with_capacity(len);
    bts.extend_from_slice(&hdr);
    bts.extend_from_slice(&pkt);
    bts.extend_from_slice(&vec![0u8; len - pkt.len() - 2]);
    bts
}

fn post_decode(raw: Bytes) -> Option<Bytes> {
    if raw.len() < 2 {
        return None;
    }
    let body_len = u16::from_le_bytes([raw[0], raw[1]]);
    Some(raw.slice(2..2 + body_len as usize))
}
