use chacha20poly1305::{
    aead::{Aead, NewAead},
    Nonce,
};
use chacha20poly1305::{ChaCha20Poly1305, Key};
use serde::{Deserialize, Serialize};

/// Either a response or a binder error
pub type BinderResult<T> = Result<T, BinderError>;

/// Data for a binder request
#[derive(Debug, Clone, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
pub enum BinderRequestData {
    Authenticate {
        username: String,
        password: String,
        blinded_digest: String,
    },
    Dummy,
}

impl BinderRequestData {
    /// Encrypts binder request data to a particular recipient, returning the request and also the reply key.
    pub fn encrypt(
        &self,
        my_esk: x25519_dalek::EphemeralSecret,
        recipient: x25519_dalek::PublicKey,
    ) -> (EncryptedBinderRequestData, [u8; 32]) {
        let plain = bincode::serialize(self).unwrap();
        let sender_epk = x25519_dalek::PublicKey::from(&my_esk);
        let shared_sec = my_esk.diffie_hellman(&recipient);
        let up_key = blake3::keyed_hash(blake3::hash(b"request").as_bytes(), shared_sec.as_bytes());
        let up_key = Key::from_slice(up_key.as_bytes());
        let ciphertext = ChaCha20Poly1305::new(up_key)
            .encrypt(Nonce::from_slice(&[0u8; 12]), plain.as_slice())
            .unwrap();
        (
            EncryptedBinderRequestData {
                sender_epk,
                ciphertext,
            },
            *blake3::keyed_hash(blake3::hash(b"response").as_bytes(), shared_sec.as_bytes())
                .as_bytes(),
        )
    }
}

/// Encrypted binder request data. Uses a crypto-box-like construction.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct EncryptedBinderRequestData {
    sender_epk: x25519_dalek::PublicKey,
    ciphertext: Vec<u8>,
}

impl EncryptedBinderRequestData {
    /// Decrypts the binder request data. Returns the binder request and also the reply key.
    pub fn decrypt(
        &self,
        my_lsk: &x25519_dalek::StaticSecret,
    ) -> Option<(BinderRequestData, [u8; 32])> {
        let shared_sec = my_lsk.diffie_hellman(&self.sender_epk);
        let up_key = blake3::keyed_hash(blake3::hash(b"request").as_bytes(), shared_sec.as_bytes());
        let plaintext = ChaCha20Poly1305::new(Key::from_slice(up_key.as_bytes()))
            .decrypt(Nonce::from_slice(&[0u8; 12]), self.ciphertext.as_slice())
            .ok()?;
        Some((
            bincode::deserialize(&plaintext).ok()?,
            *blake3::keyed_hash(blake3::hash(b"response").as_bytes(), shared_sec.as_bytes())
                .as_bytes(),
        ))
    }
}

/// Binder response
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum BinderResponse {
    AuthenticateResp {
        user_info: UserInfo,
        blind_signature: Vec<u8>,
    },
    DummyResp,
}

/// Information for a particular user
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct UserInfo {
    pub userid: i32,
    pub username: String,
    pub pwdhash: String,
    pub subscription: Option<SubscriptionInfo>,
}

/// Information about a user's subscription
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct SubscriptionInfo {
    pub level: String,
    pub expires_unix: i64,
}

/// Encrypts it to the reply key
pub fn encrypt_binder_response(
    this: &BinderResult<BinderResponse>,
    reply_key: [u8; 32],
) -> EncryptedBinderResponse {
    let plain = bincode::serialize(this).unwrap();
    EncryptedBinderResponse(
        ChaCha20Poly1305::new(Key::from_slice(&reply_key))
            .encrypt(Nonce::from_slice(&[0u8; 12]), plain.as_slice())
            .unwrap(),
    )
}

/// Encrypted binder response (encrypted Result)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBinderResponse(Vec<u8>);

impl EncryptedBinderResponse {
    /// Decrypts it
    pub fn decrypt(&self, reply_key: [u8; 32]) -> Option<BinderResult<BinderResponse>> {
        Some(
            bincode::deserialize(
                &ChaCha20Poly1305::new(Key::from_slice(&reply_key))
                    .decrypt(Nonce::from_slice(&[0u8; 12]), self.0.as_slice())
                    .ok()?,
            )
            .ok()?,
        )
    }
}

/// Error type enumerating all that could go wrong needed: e.g. user does not exist, wrong password, etc.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BinderError {
    // user-related errors
    NoUserFound,
    UserAlreadyExists,
    WrongPassword,
    WrongCaptcha,
    // database error
    DatabaseFailed,
    // other failure
    Other(String),
}

impl<E: std::error::Error> From<E> for BinderError {
    fn from(value: E) -> Self {
        BinderError::Other(value.to_string())
    }
}
