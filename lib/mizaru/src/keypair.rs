use rayon::prelude::*;
use rsa::{RSAPrivateKey, RSAPublicKey};
use rsa_fdh::blind;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{atomic::AtomicU64, atomic::Ordering, Arc};

const KEY_COUNT: usize = 65536;
const KEY_BITS: usize = 1024;

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
            .map(|i| {
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
}

/// A blind signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnblindedSignature {
    pub epoch: usize,
    pub used_key: RSAPublicKey,
    pub merkle_branch: Vec<[u8; 32]>,
    pub unblinded_sig: Vec<u8>,
}

/// A Mizaru public key. This is actually just the merkle-tree-root of a huge bunch of bincoded RSA public keys!
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Verifies an unblinded signature.
    pub fn blind_verify(&self, unblinded_digest: &[u8], sig: &UnblindedSignature) -> bool {
        // TODO!!! FIRST VERIFY MERKLE STUFF
        // then verify the actual blind sig
        blind::verify(&sig.used_key, unblinded_digest, &sig.unblinded_sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    #[test]
    fn generate_key() {
        let before = Instant::now();
        let privkey = SecretKey::generate();
        eprintln!("elapsed {} secs", before.elapsed().as_secs_f64());
        eprintln!(
            "signature is {} bytes",
            privkey.blind_sign(1, b"hello world").len()
        )
    }
}
