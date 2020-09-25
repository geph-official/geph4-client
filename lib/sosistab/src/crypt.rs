use bytes::{Bytes, BytesMut};
use c2_chacha::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use c2_chacha::ChaCha12;
use rand::prelude::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::time::SystemTime;

pub const UP_KEY: &[u8; 32] = b"upload--------------------------";
pub const DN_KEY: &[u8; 32] = b"download------------------------";
/// A structure for encrypting or decrypting Chacha12/Blake3-64.
pub struct StdAEAD {
    chacha_key: [u8; 32],
    blake3_key: [u8; 32],
}

impl StdAEAD {
    /// New std aead given a key.
    pub fn new(key: &[u8]) -> Self {
        let blake3_key = blake3::keyed_hash(b"mac-----------------------------", key);
        let chacha_key = blake3::keyed_hash(b"enc-----------------------------", key);
        StdAEAD {
            chacha_key: chacha_key.as_bytes().to_owned(),
            blake3_key: blake3_key.as_bytes().to_owned(),
        }
    }

    /// Encrypts a message, given a nonce.
    pub fn encrypt(&self, msg: &[u8], nonce: u128) -> Bytes {
        // overwrite first 128 bits of key
        let mut chacha_key = self.chacha_key;
        let mut blake3_key = self.blake3_key;
        let nonce = nonce.to_le_bytes();
        (&mut chacha_key[0..16]).copy_from_slice(&nonce);
        (&mut blake3_key[0..16]).copy_from_slice(&nonce);
        // chacha8 encryption
        let mut out_space = BytesMut::with_capacity(msg.len() + 24);
        out_space.extend_from_slice(msg);
        let mut chacha = ChaCha12::new_var(&chacha_key, &[0; 8]).expect("can't make chacha8");
        chacha.apply_keystream(&mut out_space[..msg.len()]);
        let mac = blake3::keyed_hash(&blake3_key, &out_space[..msg.len()]);
        // nonce
        out_space.extend_from_slice(&nonce);
        // mac
        out_space.extend_from_slice(&mac.as_bytes()[..8]);
        out_space.freeze()
    }

    /// Decrypts a message. Returns None if there's an error. Intentionally does not discriminate between different errors to limit possible side channels.
    pub fn decrypt(&self, msg: &[u8]) -> Option<Bytes> {
        if msg.len() < 24 {
            return None;
        }
        let ciphertext = &msg[..msg.len() - 24];
        let nonce = &msg[msg.len() - 24..][..16];
        let mac = &msg[msg.len() - 24..][16..];
        // overwrite first 128 bits of key with the nonce
        let mut chacha_key = self.chacha_key;
        let mut blake3_key = self.blake3_key;
        (&mut chacha_key[0..16]).copy_from_slice(&nonce);
        (&mut blake3_key[0..16]).copy_from_slice(&nonce);
        // decrypt
        let mut out_space = BytesMut::with_capacity(msg.len());
        out_space.extend_from_slice(ciphertext);
        let mut chacha = ChaCha12::new_var(&chacha_key, &[0; 8]).expect("can't make chacha8");
        // check mac
        let calc_mac = blake3::keyed_hash(&blake3_key, &out_space);
        if !constant_time_eq::constant_time_eq(&calc_mac.as_bytes()[..8], mac) {
            return None;
        }
        // decrypt
        chacha.apply_keystream(&mut out_space);
        Some(out_space.freeze())
    }

    /// Pad and encrypt.
    pub fn pad_encrypt(&self, msg: impl Serialize, target_len: usize) -> Bytes {
        let target_len = rand::thread_rng().gen_range(0, target_len + 1);
        let mut plain = Vec::with_capacity(1500);
        bincode::serialize_into(&mut plain, &msg).unwrap();
        let plainlen = plain.len();
        if plain.len() < target_len {
            plain.extend_from_slice(&vec![0; target_len - plain.len()]);
        }
        let encrypted = self.encrypt(&plain, rand::thread_rng().gen());
        log::trace!("PAD and ENCRYPT {} => {}", plainlen, encrypted.len());
        encrypted
    }

    /// Decrypt and depad.
    pub fn pad_decrypt<T: DeserializeOwned>(&self, ctext: &[u8]) -> Option<T> {
        let plain = self.decrypt(ctext)?;
        bincode::deserialize_from(plain.as_ref()).ok()
    }
}

// #[cfg(test)]
// mod tests {
//     extern crate test;
//     use super::*;
//     use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
//     use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
//                             // use chacha20poly1305::aead::{Aead, NewAead};
//     use chacha20poly1305::{ChaCha20Poly1305, ChaCha8Poly1305, Key, Nonce}; // Or `XChaCha20Poly1305`
//     use rand::prelude::*;

//     #[bench]
//     fn bench_stdaead_encrypt(b: &mut test::Bencher) {
//         let mut aead = StdAEAD::new(b"helloworld");
//         let mut rng = rand::thread_rng();
//         b.iter(|| {
//             std::hint::black_box(aead.encrypt(&[0; 1400], rng.gen()));
//         })
//     }

//     #[test]
//     fn stdaead_dencrypt() {
//         let mut aead = StdAEAD::new(b"helloworld");
//         let mut rng = rand::thread_rng();
//         let ciph = aead.encrypt(&[0; 1400], rng.gen());
//         aead.decrypt(&ciph).unwrap();
//     }

//     #[bench]
//     fn bench_chacha8poly1305_encrypt(b: &mut test::Bencher) {
//         let mut aead = ChaCha8Poly1305::new(Key::from_slice(b"an example very very secret key."));
//         let nonce = Nonce::from_slice(b"unique nonce");
//         b.iter(|| {
//             let ptext: &[u8] = &[0u8; 1400];
//             std::hint::black_box(aead.encrypt(nonce, ptext));
//         })
//     }

//     #[bench]
//     fn bench_chacha20poly1305_encrypt(b: &mut test::Bencher) {
//         let mut aead = ChaCha20Poly1305::new(Key::from_slice(b"an example very very secret key."));
//         let nonce = Nonce::from_slice(b"unique nonce");
//         b.iter(|| {
//             let ptext: &[u8] = &[0u8; 1400];
//             std::hint::black_box(aead.encrypt(nonce, ptext));
//         })
//     }

//     #[bench]
//     fn bench_aesgcm_encrypt(b: &mut test::Bencher) {
//         let mut aead = Aes256Gcm::new(Key::from_slice(b"an example very very secret key."));
//         let nonce = Nonce::from_slice(b"unique nonce");
//         b.iter(|| {
//             let ptext: &[u8] = &[0u8; 1400];
//             std::hint::black_box(aead.encrypt(nonce, ptext));
//         })
//     }
// }

#[derive(Debug, Clone)]
/// Cookie is a generator of temporary symmetric keys.
pub struct Cookie(x25519_dalek::PublicKey);

impl Cookie {
    /// Create a new cookie based on a public key.
    pub fn new(pk: x25519_dalek::PublicKey) -> Cookie {
        Cookie(pk)
    }

    fn generate_temp_keys(&self, ctx: &str, start_epoch: u64) -> Vec<[u8; 32]> {
        let mut vec = Vec::new();
        for epoch in &[start_epoch, start_epoch - 1, start_epoch + 1] {
            let mut key = [0u8; 32];
            blake3::derive_key(&format!("{}-{}", ctx, epoch), self.0.as_bytes(), &mut key);
            vec.push(key)
        }
        vec
    }

    /// Generate a bunch of symmetric keys given the current time, for client to server.
    pub fn generate_c2s(&self) -> impl Iterator<Item = [u8; 32]> {
        self.generate_temp_keys("sosistab-1-c2s", curr_epoch())
            .into_iter()
    }

    /// Generate a bunch of symmetric keys given the current time, for server to client.
    pub fn generate_s2c(&self) -> impl Iterator<Item = [u8; 32]> {
        self.generate_temp_keys("sosistab-1-s2c", curr_epoch())
            .into_iter()
    }
}

fn curr_epoch() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("must be after Unix epoch")
        .as_secs()
        / 60
}

pub fn triple_ecdh(
    my_long_sk: &x25519_dalek::StaticSecret,
    my_eph_sk: &x25519_dalek::StaticSecret,
    their_long_pk: &x25519_dalek::PublicKey,
    their_eph_pk: &x25519_dalek::PublicKey,
) -> blake3::Hash {
    let g_e_a = my_eph_sk.diffie_hellman(&their_long_pk);
    let g_a_e = my_long_sk.diffie_hellman(&their_eph_pk);
    let g_e_e = my_eph_sk.diffie_hellman(&their_eph_pk);
    let to_hash = {
        let mut to_hash = Vec::new();
        if g_e_a.as_bytes() < g_a_e.as_bytes() {
            to_hash.extend_from_slice(g_e_a.as_bytes());
            to_hash.extend_from_slice(g_a_e.as_bytes());
        } else {
            to_hash.extend_from_slice(g_a_e.as_bytes());
            to_hash.extend_from_slice(g_e_a.as_bytes());
        }
        to_hash.extend_from_slice(g_e_e.as_bytes());
        to_hash
    };
    blake3::hash(&to_hash)
}
