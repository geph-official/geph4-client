use bincode::{DefaultOptions, Options};
use bytes::{Bytes, BytesMut};
use c2_chacha::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use c2_chacha::ChaCha12;
use rand::prelude::*;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::{sync::Arc, time::SystemTime};

pub const UP_KEY: &[u8; 32] = b"upload--------------------------";
pub const DN_KEY: &[u8; 32] = b"download------------------------";
/// A structure for encrypting or decrypting Chacha12/Blake3-64.
#[derive(Debug, Copy, Clone)]
pub struct LegacyAEAD {
    chacha_key: [u8; 32],
    blake3_key: [u8; 32],
}

impl LegacyAEAD {
    /// New std aead given a key.
    pub fn new(key: &[u8]) -> Self {
        let blake3_key = blake3::keyed_hash(b"mac-----------------------------", key);
        let chacha_key = blake3::keyed_hash(b"enc-----------------------------", key);
        LegacyAEAD {
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
        let mut chacha = ChaCha12::new_var(&chacha_key, &[0; 8]).expect("can't make chacha12");
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
        let mut chacha = ChaCha12::new_var(&chacha_key, &[0; 8]).expect("can't make chacha12");
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
    pub fn pad_encrypt_v1(&self, msgs: &[impl Serialize], target_len: usize) -> Bytes {
        let mut target_len = rand::thread_rng().gen_range(0, target_len);
        let mut plain = Vec::with_capacity(1500);
        for msg in msgs {
            bincode::serialize_into(&mut plain, &msg).unwrap();
        }
        let plainlen = plain.len();
        if plain.len() > target_len {
            target_len = plain.len() + rand::thread_rng().gen_range(0, 4);
        }
        plain.extend_from_slice(&vec![0xff; target_len - plain.len()]);
        let encrypted = self.encrypt(&plain, rand::thread_rng().gen());
        tracing::trace!("PAD and ENCRYPT {} => {}", plainlen, encrypted.len());
        encrypted
    }

    /// Decrypt and depad.
    pub fn pad_decrypt_v1<T: DeserializeOwned>(&self, ctext: &[u8]) -> Option<Vec<T>> {
        let plain = self.decrypt(ctext)?;
        // Some(vec![bincode::deserialize(&plain).ok()?])
        // eprintln!("plain gotten");
        let mut reader = plain.as_ref();
        let mut output = Vec::with_capacity(1);
        while !reader.is_empty() {
            let cfg = DefaultOptions::new()
                .with_fixint_encoding()
                .with_limit(10000)
                .allow_trailing_bytes();
            let boolayah: Option<T> = cfg.deserialize_from(&mut reader).ok();
            if let Some(boolayah) = boolayah {
                output.push(boolayah);
            } else {
                break;
            }
        }
        if output.is_empty() {
            return None;
        }
        Some(output)
    }
}

/// Next generation AEAD, based on `ring`'s ChaCha20/Poly1305, used in versions 3 and above
#[derive(Debug, Clone)]
pub struct NgAEAD {
    key: Arc<LessSafeKey>,
}

impl NgAEAD {
    pub fn new(key: &[u8]) -> Self {
        let ubk = UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap();
        Self {
            key: Arc::new(LessSafeKey::new(ubk)),
        }
    }

    /// Returns the overhead.
    pub fn overhead() -> usize {
        CHACHA20_POLY1305.nonce_len() + CHACHA20_POLY1305.tag_len()
    }

    /// Encrypts a message with a random nonce.
    pub fn encrypt(&self, msg: &[u8]) -> Bytes {
        let mut nonce = [0; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        // make an output. it starts out containing the plaintext.
        let mut output = Vec::with_capacity(
            msg.len() + CHACHA20_POLY1305.nonce_len() + CHACHA20_POLY1305.tag_len(),
        );
        output.extend_from_slice(&msg);
        // now we overwrite it
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut output,
            )
            .unwrap();
        output.extend_from_slice(&nonce);
        output.into()
    }

    /// Decrypts a message.
    pub fn decrypt(&self, ctext: &[u8]) -> Option<Bytes> {
        if ctext.len() < CHACHA20_POLY1305.nonce_len() + CHACHA20_POLY1305.tag_len() {
            return None;
        }
        // nonce is last 12 bytes
        let (ctext, nonce) = ctext.split_at(ctext.len() - CHACHA20_POLY1305.nonce_len());
        // we now open
        let mut ctext = ctext.to_vec();
        self.key
            .open_in_place(
                Nonce::try_assume_unique_for_key(nonce).unwrap(),
                Aad::empty(),
                &mut ctext,
            )
            .ok()?;
        ctext.truncate(ctext.len() - CHACHA20_POLY1305.tag_len());
        Some(ctext.into())
    }
}

#[derive(Debug, Clone)]
/// Cookie is a generator of temporary symmetric keys.
pub struct Cookie(x25519_dalek::PublicKey);

impl Cookie {
    /// Create a new cookie based on a public key.
    pub fn new(pk: x25519_dalek::PublicKey) -> Cookie {
        Cookie(pk)
    }

    fn generate_temp_keys(&self, ctx: &str, start_epoch: u64) -> Vec<[u8; 32]> {
        let mut vec = Vec::with_capacity(5);
        for epoch in &[
            start_epoch,
            start_epoch - 1,
            start_epoch + 1,
            start_epoch - 2,
            start_epoch + 2,
        ] {
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

#[tracing::instrument(skip(my_long_sk, my_eph_sk), level = "trace")]
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
