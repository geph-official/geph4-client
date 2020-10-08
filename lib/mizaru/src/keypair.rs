use rayon::prelude::*;
use rsa::{RSAPrivateKey, RSAPublicKey};
use rsa_fdh::blind;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::{atomic::AtomicU64, atomic::Ordering, Arc},
    time::SystemTime,
};

const KEY_COUNT: usize = 65536;
const KEY_BITS: usize = 2048;

/// Obtains the epoch from a SystemTime
pub fn time_to_epoch(time: SystemTime) -> usize {
    let unix = time.duration_since(std::time::UNIX_EPOCH).unwrap();
    (unix.as_secs() / 86400) as usize
}

/// A Mizaru private key. Consists of a vast number of RSA private keys, one for every day, for the 65536 days after the Unix epoch. This supports serde so that you can save this to disk.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretKey {
    rsa_keys: Arc<Vec<RSAPrivateKey>>,
    // all the intermediate layers of the merkle tree
    merkle_tree: Arc<Vec<Vec<[u8; 32]>>>,
}

impl SecretKey {
    /// Generates a Mizaru private key. May take **quite** a while!
    pub fn generate() -> Self {
        let count = AtomicU64::new(0);
        // first we generate the massive number of rsa keys
        let rsa_keys: Vec<RSAPrivateKey> = (0..KEY_COUNT)
            .into_par_iter()
            .map(|_| {
                let mut rng = rand::rngs::OsRng {};
                let count = count.fetch_add(1, Ordering::SeqCst);
                eprintln!("generated {}/{} keys", count, KEY_COUNT);
                RSAPrivateKey::new(&mut rng, KEY_BITS).expect("can't generate RSA key")
            })
            .collect();
        // then, we populate the merkle tree level by level
        let merkle_tree_first: Vec<[u8; 32]> = rsa_keys
            .iter()
            .map(|v| Sha256::digest(&bincode::serialize(&v.to_public_key()).unwrap()).into())
            .collect();
        let mut merkle_tree = vec![merkle_tree_first];
        while merkle_tree.last().unwrap().len() > 1 {
            // "decimate" the merkle tree level to make the next
            let last = merkle_tree.last().unwrap();
            let new = (0..last.len() / 2)
                .map(|i| {
                    let mut v = last[i * 2].to_vec();
                    v.extend_from_slice(&last[i * 2 + 1]);
                    Sha256::digest(&v).into()
                })
                .collect();
            merkle_tree.push(new)
        }
        // return the value
        SecretKey {
            rsa_keys: Arc::new(rsa_keys),
            merkle_tree: Arc::new(merkle_tree),
        }
    }

    fn merkle_branch(&self, idx: usize) -> Vec<[u8; 32]> {
        fn other(i: usize) -> usize {
            i / 2 * 2 + ((i + 1) % 2)
        }
        let mut idx = idx;
        // HACK mutation within map
        self.merkle_tree
            .iter()
            .take(self.merkle_tree.len() - 1)
            .map(|level| {
                let toret = level[other(idx)];
                idx >>= 1;
                toret
            })
            .collect()
    }

    /// Blind-signs a message with a given epoch key. The returned struct contains all information required to verify a specific key within the merkle root and an RSA-FDH blind signature using that specific key.
    pub fn blind_sign(&self, epoch: usize, blinded_digest: &[u8]) -> BlindedSignature {
        assert!(epoch <= self.rsa_keys.len());
        let mut rng = rand::rngs::OsRng {};
        let key_to_use = &self.rsa_keys[epoch];
        let bare_sig =
            blind::sign(&mut rng, key_to_use, blinded_digest).expect("blind signature failed");
        BlindedSignature {
            epoch,
            used_key: key_to_use.to_public_key(),
            merkle_branch: self.merkle_branch(epoch),
            blinded_sig: bare_sig,
        }
    }

    /// Returns the "public key", i.e. the merkle tree root.
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey(self.merkle_tree.last().unwrap()[0])
    }

    /// Gets an epoch key.
    pub fn get_subkey(&self, epoch: usize) -> &RSAPrivateKey {
        &self.rsa_keys[epoch]
    }
}

/// A blind signature.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct BlindedSignature {
    pub epoch: usize,
    pub used_key: RSAPublicKey,
    pub merkle_branch: Vec<[u8; 32]>,
    pub blinded_sig: Vec<u8>,
}

impl BlindedSignature {
    /// Unblinds the signature, given the unblinding factor.
    pub fn unblind(self, unblinder: &[u8]) -> UnblindedSignature {
        let unblinded_sig = blind::unblind(&self.used_key, &self.blinded_sig, unblinder);
        UnblindedSignature {
            epoch: self.epoch,
            used_key: self.used_key,
            merkle_branch: self.merkle_branch,
            unblinded_sig,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct UnblindedSignature {
    pub epoch: usize,
    pub used_key: RSAPublicKey,
    pub merkle_branch: Vec<[u8; 32]>,
    pub unblinded_sig: Vec<u8>,
}

/// A Mizaru public key. This is actually just the merkle-tree-root of a huge bunch of bincoded RSA public keys!
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    /// Verifies an unblinded signature.
    pub fn blind_verify(&self, unblinded_digest: &[u8], sig: &UnblindedSignature) -> bool {
        self.verify_member(sig.epoch, &sig.used_key, &sig.merkle_branch)
            && blind::verify(&sig.used_key, unblinded_digest, &sig.unblinded_sig).is_ok()
    }

    /// Verifies that a certain subkey is the correct one for the epoch
    pub fn verify_member(
        &self,
        epoch: usize,
        subkey: &RSAPublicKey,
        merkle_branch: &[[u8; 32]],
    ) -> bool {
        merkle_branch.len();
        let mut accumulator: [u8; 32] =
            Sha256::digest(&bincode::serialize(&subkey).unwrap()).into();
        for (i, hash) in merkle_branch.iter().enumerate() {
            if epoch >> i & 1 == 0 {
                // the hash is on the "odd" position
                accumulator = hash_together(&accumulator, hash)
            } else {
                accumulator = hash_together(hash, &accumulator)
            }
        }
        accumulator == self.0
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(val: [u8; 32]) -> Self {
        Self(val)
    }
}

fn hash_together(x: &[u8], y: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(x.len() + y.len());
    buf.extend_from_slice(x);
    buf.extend_from_slice(y);
    Sha256::digest(&buf).into()
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use std::time::Instant;
//     #[test]
//     fn generate_key() {
//         let before = Instant::now();
//         let privkey = SecretKey::generate();
//         eprintln!("elapsed {} secs", before.elapsed().as_secs_f64());
//         eprintln!(
//             "signature is {} bytes",
//             privkey.blind_sign(1, b"hello world").len()
//         )
//     }
// }
