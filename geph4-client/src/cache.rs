use crate::persist::KVDatabase;
use binder_transport::{
    BinderClient, BinderError, BinderRequestData, BinderResponse, BridgeDescriptor, ExitDescriptor,
};
use rand::prelude::*;
use rsa_fdh::blind;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use smol::prelude::*;
use std::{sync::Arc, time::Duration, time::SystemTime};

/// An cached client
pub struct ClientCache {
    username: String,
    password: String,
    binder_client: Arc<dyn BinderClient>,
    free_pk: mizaru::PublicKey,
    plus_pk: mizaru::PublicKey,
    database: Arc<KVDatabase>,
}

impl ClientCache {
    /// Create a new ClientCache that saves to the given database.
    pub fn new(
        username: &str,
        password: &str,
        free_pk: mizaru::PublicKey,
        plus_pk: mizaru::PublicKey,
        binder_client: Arc<dyn BinderClient>,
        database: Arc<KVDatabase>,
    ) -> Self {
        ClientCache {
            username: username.to_string(),
            password: password.to_string(),
            binder_client,
            free_pk,
            plus_pk,
            database,
        }
    }

    async fn get_cached<T: Serialize + DeserializeOwned + Clone>(
        &self,
        key: &str,
        fallback: impl Future<Output = anyhow::Result<T>>,
        ttl: Duration,
    ) -> anyhow::Result<T> {
        let existing: Option<(T, u64)> = self.database.read().get(key);
        if let Some((existing, timeout)) = existing {
            if SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                < timeout + ttl.as_secs()
            {
                return Ok(existing);
            }
        }
        let deadline: SystemTime = SystemTime::now() + ttl;
        let deadline = deadline
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let fresh = fallback.await?;
        let mut db = self.database.write();
        // save to disk
        db.insert(key, (fresh.clone(), deadline));
        db.commit();
        Ok(fresh)
    }

    /// Obtains a new token.
    pub async fn get_auth_token(&self) -> anyhow::Result<Token> {
        self.get_cached(
            "cache.auth_token",
            self.get_token_fresh(),
            Duration::from_secs(86400),
        )
        .await
    }

    /// Gets a list of exits.
    pub async fn get_exits(&self) -> anyhow::Result<Vec<ExitDescriptor>> {
        self.get_cached(
            "cache.exits",
            self.get_exits_fresh(),
            Duration::from_secs(3600),
        )
        .await
    }

    /// Gets a list of bridges.
    pub async fn get_bridges(&self, exit_hostname: &str) -> anyhow::Result<Vec<BridgeDescriptor>> {
        let tok = self.get_auth_token().await?;
        let binder_client = self.binder_client.clone();
        let exit_hostname = exit_hostname.to_string();
        self.get_cached(
            "cache.bridges",
            async {
                let res = smol::unblock(move || {
                    binder_client.request(
                        BinderRequestData::GetBridges {
                            level: tok.level,
                            unblinded_digest: tok.unblinded_digest,
                            unblinded_signature: tok.unblinded_signature,
                            exit_hostname,
                        },
                        Duration::from_secs(1),
                    )
                })
                .await?;
                if let BinderResponse::GetBridgesResp(bridges) = res {
                    Ok(bridges)
                } else {
                    anyhow::bail!("invalid response")
                }
            },
            Duration::from_secs(3600),
        )
        .await
    }

    async fn get_token_fresh(&self) -> anyhow::Result<Token> {
        let digest: [u8; 32] = rand::thread_rng().gen();
        for level in &["plus", "free"] {
            let mizaru_pk = if level == &"plus" {
                &self.plus_pk
            } else {
                &self.free_pk
            };
            let epoch = mizaru::time_to_epoch(SystemTime::now()) as u16;
            let binder_client = self.binder_client.clone();
            let subkey = smol::unblock(move || {
                binder_client.request(
                    BinderRequestData::GetEpochKey {
                        level: level.to_string(),
                        epoch,
                    },
                    Duration::from_secs(10),
                )
            })
            .await?;
            if let BinderResponse::GetEpochKeyResp(subkey) = subkey {
                // create FDH
                let digest = blind::hash_message::<Sha256, _>(&subkey, &digest).unwrap();
                // blinding
                let (blinded_digest, unblinder) =
                    blind::blind(&mut rand::thread_rng(), &subkey, &digest);
                let binder_client = self.binder_client.clone();
                let username = self.username.clone();
                let password = self.password.clone();
                let resp = smol::unblock(move || {
                    binder_client.request(
                        BinderRequestData::Authenticate {
                            username,
                            password,
                            level: level.to_string(),
                            epoch,
                            blinded_digest,
                        },
                        Duration::from_secs(10),
                    )
                })
                .await;
                match resp {
                    Ok(BinderResponse::AuthenticateResp {
                        user_info,
                        blind_signature,
                    }) => {
                        let unblinded_signature = blind_signature.unblind(&unblinder);
                        if !mizaru_pk.blind_verify(&digest, &unblinded_signature) {
                            anyhow::bail!("an invalid signature was given by the binder")
                        }
                        return Ok(Token {
                            user_info,
                            level: level.to_string(),
                            epoch,
                            unblinded_digest: digest.to_vec(),
                            unblinded_signature,
                        });
                    }
                    Err(BinderError::WrongLevel) => continue,
                    Err(e) => return Err(e.into()),
                    _ => continue,
                }
            }
        }
        anyhow::bail!("neither plus nor free worked");
    }

    async fn get_exits_fresh(&self) -> anyhow::Result<Vec<ExitDescriptor>> {
        let binder_client = self.binder_client.clone();
        let res = smol::unblock(move || {
            binder_client.request(BinderRequestData::GetExits, Duration::from_secs(1))
        })
        .await?;
        match res {
            binder_transport::BinderResponse::GetExitsResp(exits) => Ok(exits),
            other => anyhow::bail!("unexpected response {:?}", other),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub user_info: binder_transport::UserInfo,
    pub level: String,
    pub epoch: u16,
    pub unblinded_digest: Vec<u8>,
    pub unblinded_signature: mizaru::UnblindedSignature,
}
