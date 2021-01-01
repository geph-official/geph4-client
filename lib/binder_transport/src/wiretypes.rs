use std::net::SocketAddr;

use chacha20poly1305::{
    aead::{Aead, NewAead},
    Nonce,
};
use chacha20poly1305::{ChaCha20Poly1305, Key};
use serde::{Deserialize, Serialize};
/// Either a response or a binder error
pub type BinderResult<T> = Result<T, BinderError>;

/// Data for a binder request
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum BinderRequestData {
    /// Get mizaru epoch key
    GetEpochKey { level: String, epoch: u16 },
    /// Authenticate a user, obtaining the user info and blinded signature.
    Authenticate {
        username: String,
        password: String,
        level: String,
        epoch: u16,
        blinded_digest: Vec<u8>,
    },
    /// Validates a blind signature token, applying rate-limiting as appropriate.
    Validate {
        level: String,
        unblinded_digest: Vec<u8>,
        unblinded_signature: mizaru::UnblindedSignature,
    },
    /// Obtain a CAPTCHA for registration
    GetCaptcha,
    /// Register a user
    RegisterUser {
        username: String,
        password: String,
        captcha_id: String,
        captcha_soln: String,
    },
    /// Changes password
    ChangePassword {
        username: String,
        old_password: String,
        new_password: String,
    },
    /// Delete a user
    DeleteUser { username: String, password: String },

    /// Get all exits
    GetExits,

    /// Add a bridge route
    AddBridgeRoute {
        /// Sosistab public key
        sosistab_pubkey: x25519_dalek::PublicKey,
        /// Address of the intermediate bridge
        bridge_address: SocketAddr,
        /// Bridge group
        bridge_group: String,
        /// Exit hostname
        exit_hostname: String,
        /// Time
        route_unixtime: u64,
        /// Authorization from the exit. Signature over a tuple of the rest of the fields except the exit hostname.
        exit_signature: ed25519_dalek::Signature,
    },

    /// Get bridges
    GetBridges {
        level: String,
        unblinded_digest: Vec<u8>,
        unblinded_signature: mizaru::UnblindedSignature,
        exit_hostname: String,
    },

    /// Get all free exits
    GetFreeExits,
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

    /// Returns a boolean determining whether or not this request is idempotent.
    pub fn is_idempotent(&self) -> bool {
        match self {
            BinderRequestData::GetEpochKey { .. } => true,
            BinderRequestData::GetCaptcha { .. } => true,
            BinderRequestData::GetExits { .. } => true,
            BinderRequestData::GetFreeExits { .. } => true,
            BinderRequestData::GetBridges { .. } => true,
            // BinderRequestData::Authenticate { .. } => true,
            // BinderRequestData::Validate { .. } => true,
            _ => false,
        }
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
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum BinderResponse {
    /// Okay to something that does not need response data.
    Okay,
    /// Carrying an epoch key
    GetEpochKeyResp(rsa::RSAPublicKey),
    /// Response to authentication
    AuthenticateResp {
        user_info: UserInfo,
        blind_signature: mizaru::BlindedSignature,
    },
    /// Response to ticket validation
    ValidateResp(bool),
    /// Response to CAPTCHA request
    GetCaptchaResp {
        captcha_id: String,
        png_data: Vec<u8>,
    },
    /// Response to request for all exits
    GetExitsResp(Vec<ExitDescriptor>),
    /// Response to request for bridges
    GetBridgesResp(Vec<BridgeDescriptor>),
}

/// Exit descriptor
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ExitDescriptor {
    pub hostname: String,
    pub signing_key: ed25519_dalek::PublicKey,
    pub country_code: String,
    pub city_code: String,
    pub sosistab_key: x25519_dalek::PublicKey,
}

/// Bridge descriptor
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct BridgeDescriptor {
    pub endpoint: SocketAddr,
    pub sosistab_key: x25519_dalek::PublicKey,
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
#[derive(Clone, Debug, Serialize, Deserialize, thiserror::Error)]
pub enum BinderError {
    // user-related errors
    #[error("no user found")]
    NoUserFound,
    #[error("user already exists")]
    UserAlreadyExists,
    #[error("wrong password")]
    WrongPassword,
    #[error("incorrect captcha")]
    WrongCaptcha,
    #[error("incorrect account level")]
    WrongLevel,
    // database error
    #[error("database failed")]
    DatabaseFailed,
    // other failure
    #[error("other failure `{0}`")]
    Other(String),
}

impl From<std::io::Error> for BinderError {
    fn from(value: std::io::Error) -> Self {
        BinderError::Other(value.to_string())
    }
}
