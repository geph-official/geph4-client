use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;

use event_listener::Event;
use futures_util::join;
use geph4_protocol::binder::protocol::{
    AuthError, AuthRequestV2, AuthResponseV2, BinderClient, BlindToken, BridgeDescriptor,
    Credentials, Level, MasterSummary, UserInfoV2,
};

use rand::Rng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use smol_timeout::TimeoutExt;
use sqlx::SqlitePool;

const TOKEN_STALE_SECS: u64 = 86400;
const SUMMARY_STALE_SECS: u64 = 3600;
const BRIDGE_STALE_SECS: u64 = 600;

/// Persistent storage for connection info, asynchronously refreshed.
pub struct ConnInfoStore {
    storage: SqlitePool,
    rpc: Arc<BinderClient>,

    mizaru_free: mizaru::PublicKey,
    mizaru_plus: mizaru::PublicKey,
    selected_exit: String,

    get_creds: Box<dyn Fn() -> Credentials + Send + Sync + 'static>,

    notify: Event,
}

impl ConnInfoStore {
    /// Creates a storage unit given the parameters. Ensures that the stored is not stale.
    pub async fn connect(
        storage: SqlitePool,
        rpc: BinderClient,
        mizaru_free: mizaru::PublicKey,
        mizaru_plus: mizaru::PublicKey,
        exit_host: &str,
        get_creds: impl Fn() -> Credentials + Send + Sync + 'static,
    ) -> anyhow::Result<Self> {
        log::debug!("attempting to construct a conninfo store!");

        sqlx::query(
            "create table if not exists conninfo_store (k primary key not null, v not null)",
        )
        .execute(&storage)
        .await?;

        let toret = Self {
            storage,
            rpc: rpc.into(),
            mizaru_free,
            mizaru_plus,
            selected_exit: exit_host.to_owned(),
            get_creds: Box::new(get_creds),
            notify: Event::new(),
        };

        toret.refresh(true).await?;

        Ok(toret)
    }

    async fn kv_read<T: DeserializeOwned>(&self, k: &str) -> anyhow::Result<Option<T>> {
        let bts: Option<(Vec<u8>,)> = sqlx::query_as("select v from conninfo_store where k == ?")
            .bind(k)
            .fetch_optional(&self.storage)
            .await?;
        if let Some((bts,)) = bts {
            Ok(Some(stdcode::deserialize(&bts)?))
        } else {
            Ok(None)
        }
    }

    async fn kv_read_or_wait<T: DeserializeOwned>(&self, k: &str) -> anyhow::Result<T> {
        loop {
            let notify = self.notify.listen();
            if let Some(v) = self.kv_read(k).await? {
                return Ok(v);
            } else {
                log::warn!("waiting for key {:?}", k);

                notify.await;
            }
        }
    }

    async fn kv_write<T: Serialize>(&self, k: &str, v: &T) -> anyhow::Result<()> {
        let serialized_v = stdcode::serialize(v)?;
        sqlx::query("INSERT INTO conninfo_store (k, v) VALUES ($1, $2) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v")
            .bind(k)
            .bind(&serialized_v)
            .execute(&self.storage)
            .await?;
        self.notify.notify(usize::MAX);
        Ok(())
    }

    /// Refreshes the whole store. This should generally be called in a background task.
    pub async fn refresh(&self, express: bool) -> anyhow::Result<()> {
        log::info!("calling refresh now!");
        let current_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        const TIMEOUT: Duration = Duration::from_secs(60);
        // refresh master summary
        let summary_refresh_unix: u64 = self
            .kv_read("summary_refresh_unix")
            .await?
            .unwrap_or_default();
        let summary_fut = async {
            if current_unix > summary_refresh_unix + SUMMARY_STALE_SECS && !express {
                log::debug!("summary stale so refreshing summary");
                let summary = self
                    .get_verified_summary()
                    .timeout(TIMEOUT)
                    .await
                    .context("getting summary timed out")??;
                self.kv_write("summary", &summary).await?;
                self.kv_write("summary_refresh_unix", &current_unix).await?;
            }
            anyhow::Ok(())
        };

        // refresh token
        let token_refresh_unix: u64 = self
            .kv_read("token_refresh_unix")
            .await?
            .unwrap_or_default();
        let token_fut = async {
            let current_user_info: Option<UserInfoV2> = self.kv_read("user_info").await?;
            let remote_user_info = self
                .rpc()
                .get_user_info((self.get_creds)())
                .timeout(TIMEOUT)
                .await
                .context("getting remote user info timed out")???;
            log::debug!(
                "current user info == remote user info?: {}",
                current_user_info == Some(remote_user_info.clone())
            );
            if current_unix > token_refresh_unix + TOKEN_STALE_SECS * 2 / 3
                || current_user_info != Some(remote_user_info)
                || express
            {
                log::debug!("token stale so refreshing token");
                // refresh 2/3 through the period
                let (user_info, blind_token) = self
                    .get_auth_token()
                    .timeout(TIMEOUT)
                    .await
                    .context("getting blind token timed out")??;

                self.kv_write("blind_token", &blind_token).await?;
                self.kv_write("user_info", &user_info).await?;
                self.kv_write("token_refresh_unix", &current_unix).await?;
            }
            anyhow::Ok(())
        };
        // refresh bridge list
        let bridge_refresh_unix: u64 = self
            .kv_read("bridge_refresh_unix")
            .await?
            .unwrap_or_default();
        let cached_exit: Option<String> = self.kv_read("cached_exit").await?;
        let bridge_fut = async {
            // if we have selected no exit, then we synchronize the cached exit
            let effective_exit_host = if self.selected_exit.is_empty() {
                cached_exit.clone()
            } else {
                Some(self.selected_exit.clone())
            };
            // but if we have no cached exit either, we just skip bridge synchronization
            match effective_exit_host {
                None => return Ok(()),
                Some(effective_exit_host) => {
                    // we refresh in two cases: if the bridges are stale, OR if the exit we want bridges for is NOT the exit that the bridges are in the cache for.
                    if (current_unix > bridge_refresh_unix + BRIDGE_STALE_SECS && !express)
                        || cached_exit != Some(effective_exit_host.clone())
                    {
                        log::debug!("bridges stale so refreshing bridges");
                        // refresh if the bridges are old, OR if the exit that's actually selected isn't the one in the persistent store
                        let token: BlindToken = self.kv_read_or_wait("blind_token").await?;
                        let bridges = self
                            .rpc
                            .get_bridges_v2(token, effective_exit_host.as_str().into())
                            .timeout(TIMEOUT)
                            .await
                            .context("getting bridges timed out")??;
                        if bridges.is_empty() && !self.selected_exit.is_empty() {
                            anyhow::bail!("empty list of bridges received");
                        }

                        self.kv_write("bridges", &bridges).await?;
                        self.kv_write("bridge_refresh_unix", &current_unix).await?;
                        self.kv_write("cached_exit", &self.selected_exit).await?;
                    }
                }
            }

            anyhow::Ok(())
        };

        let (a, b, c) = join!(summary_fut, token_fut, bridge_fut);
        a?;
        b?;
        c?;
        Ok(())
    }

    /// Gets the current list of bridges
    pub async fn bridges(&self) -> anyhow::Result<Vec<BridgeDescriptor>> {
        self.kv_read_or_wait("bridges").await
    }

    /// Gets the current master summary
    pub async fn summary(&self) -> anyhow::Result<MasterSummary> {
        self.kv_read_or_wait("summary").await
    }

    /// Gets the current user info
    pub async fn user_info(&self) -> anyhow::Result<UserInfoV2> {
        self.kv_read_or_wait("user_info").await
    }

    /// Gets the current authentication token
    pub async fn blind_token(&self) -> anyhow::Result<BlindToken> {
        self.kv_read_or_wait("blind_token").await
    }

    /// Gets the underlying RPC.
    pub fn rpc(&self) -> &BinderClient {
        &self.rpc
    }

    /// Obtains an authentication token.
    async fn get_auth_token(&self) -> anyhow::Result<(UserInfoV2, BlindToken)> {
        let digest: [u8; 32] = rand::thread_rng().gen();
        for level in [Level::Free, Level::Plus] {
            let mizaru_pk = self.get_mizaru_pk(level)?;
            let epoch = mizaru::time_to_epoch(SystemTime::now()) as u16;
            let subkey = self.rpc.get_mizaru_epoch_key(level, epoch).await?;

            let digest = rsa_fdh::blind::hash_message::<sha2::Sha256, _>(&subkey, &digest).unwrap();
            let (blinded_digest, unblinder) =
                rsa_fdh::blind::blind(&mut rand::thread_rng(), &subkey, &digest);
            let resp: AuthResponseV2 = match self
                .rpc
                .authenticate_v2(AuthRequestV2 {
                    credentials: (self.get_creds)(),
                    level,
                    epoch,
                    blinded_digest: blinded_digest.into(),
                })
                .await?
            {
                Err(AuthError::WrongLevel) => continue,
                x => x?,
            };
            let blind_signature: mizaru::BlindedSignature =
                bincode::deserialize(&resp.blind_signature_bincode)?;
            let unblinded_signature = blind_signature.unblind(&unblinder);
            // This checks that the 1. epoch is correct and 2. the Merkle proof is correct, so if the binder lied to us about the subkey, we will fail now and avoid being deanonymized
            if unblinded_signature.epoch != epoch as usize
                || !mizaru_pk.blind_verify(&digest, &unblinded_signature)
            {
                anyhow::bail!("an invalid signature was given by the binder")
            }
            let tok = BlindToken {
                level,
                unblinded_digest: digest.into(),
                unblinded_signature_bincode: bincode::serialize(&unblinded_signature)?.into(),
                version: std::env::var("GEPH_VERSION").ok().map(|s| s.into()),
            };
            // intentionally sleep between 3 and 8 seconds to increase the anonymity set
            let duration = Duration::from_secs_f64(rand::thread_rng().gen_range(3.0, 8.0));
            smol::Timer::after(duration).await;
            return Ok((resp.user_info, tok));
        }
        unreachable!()
    }

    /// Obtains the overall network summary.
    async fn get_verified_summary(&self) -> anyhow::Result<MasterSummary> {
        // load from the network
        let summary = self.rpc.get_summary().await?;

        Ok(summary)
    }

    fn get_mizaru_pk(&self, level: Level) -> anyhow::Result<mizaru::PublicKey> {
        match level {
            Level::Free => Ok(self.mizaru_free.clone()),
            Level::Plus => Ok(self.mizaru_plus.clone()),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ConnInfoInner {
    user_info: UserInfoV2,
    blind_token: BlindToken,
    token_refresh_unix: u64,

    cached_exit: String,
    bridges: Vec<BridgeDescriptor>,
    bridges_refresh_unix: u64,

    summary: MasterSummary,
    summary_refresh_unix: u64,
}
