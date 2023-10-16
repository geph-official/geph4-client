use std::{
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use acidjson::AcidJson;
use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::join;
use geph4_protocol::binder::protocol::{
    AuthError, AuthRequestV2, AuthResponseV2, BinderClient, BlindToken, BridgeDescriptor,
    Credentials, Level, MasterSummary, UserInfoV2,
};
use melprot::NodeRpcClient;
use moka::sync::{Cache, CacheBuilder};
use nanorpc::{JrpcRequest, JrpcResponse, RpcTransport};
use rand::Rng;
use serde::{Deserialize, Serialize};

use stdcode::StdcodeSerializeExt;
use tmelcrypt::{HashVal, Hashable};

const TOKEN_STALE_SECS: u64 = 86400;
const SUMMARY_STALE_SECS: u64 = 3600;
const BRIDGE_STALE_SECS: u64 = 600;

/// Persistent storage for connection info, asynchronously refreshed.
pub struct ConnInfoStore {
    inner: AcidJson<ConnInfoInner>,
    rpc: Arc<BinderClient>,

    mizaru_free: mizaru::PublicKey,
    mizaru_plus: mizaru::PublicKey,
    selected_exit: String,

    get_creds: Box<dyn Fn() -> Credentials + Send + Sync + 'static>,
}

impl ConnInfoStore {
    /// Creates a storage unit given the parameters. Ensures that the stored is not stale.
    pub async fn connect(
        cache_path: &Path,
        rpc: BinderClient,
        mizaru_free: mizaru::PublicKey,
        mizaru_plus: mizaru::PublicKey,
        exit_host: &str,
        get_creds: impl Fn() -> Credentials + Send + Sync + 'static,
    ) -> anyhow::Result<Self> {
        log::debug!("attempting to construct a conninfo store!");
        let inner = AcidJson::open_or_else(cache_path, || ConnInfoInner {
            user_info: UserInfoV2 {
                userid: 0,
                subscription: None,
            },
            blind_token: BlindToken {
                level: Level::Free,
                unblinded_digest: Bytes::new(),
                unblinded_signature_bincode: Bytes::new(),
                version: None,
            },
            token_refresh_unix: 0,
            cached_exit: "".into(),
            bridges: vec![],
            bridges_refresh_unix: 0,
            summary: MasterSummary {
                exits: vec![],
                bad_countries: vec![],
            },
            summary_refresh_unix: 0,
        })?;

        let toret = Self {
            inner,
            rpc: rpc.into(),
            mizaru_free,
            mizaru_plus,
            selected_exit: exit_host.to_owned(),
            get_creds: Box::new(get_creds),
        };

        // only force a refresh here if the *token* is stale, because that is a hard error. other things being stale are totally fine.
        let current_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let must_refresh = (current_unix
            > toret.inner.read().token_refresh_unix + TOKEN_STALE_SECS)
            || toret.inner.read().cached_exit.as_str() != exit_host;

        if must_refresh {
            log::debug!("blocking on construct because token is stale, or exit host changed");
            toret.refresh().await?;
        }
        Ok(toret)
    }

    /// Refreshes the whole store. This should generally be called in a background task.
    pub async fn refresh(&self) -> anyhow::Result<()> {
        log::info!("calling refresh now!");
        let current_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // refresh master summary
        let summary_refresh_unix = self.inner.read().summary_refresh_unix;
        let summary_fut = async {
            if current_unix > summary_refresh_unix + SUMMARY_STALE_SECS {
                log::debug!("summary stale so refreshing summary");
                let summary = self.get_verified_summary().await?;
                let mut inner = self.inner.write();
                inner.summary = summary;
                inner.summary_refresh_unix = current_unix;
            }
            anyhow::Ok(())
        };

        // refresh token
        let token_refresh_unix = self.inner.read().token_refresh_unix;
        let token_fut = async {
            let current_user_info = self.inner.read().user_info.clone();
            let remote_user_info = self.rpc().get_user_info((self.get_creds)()).await??;
            log::debug!(
                "current user info == remote user info?: {}",
                current_user_info == remote_user_info
            );
            if current_unix > token_refresh_unix + TOKEN_STALE_SECS * 2 / 3
                || current_user_info != remote_user_info
            {
                log::debug!("token stale so refreshing token");
                // refresh 2/3 through the period
                let (user_info, blind_token) = self.get_auth_token().await?;
                let mut inner = self.inner.write();
                inner.blind_token = blind_token;
                inner.user_info = user_info;
                inner.token_refresh_unix = current_unix;
            }
            anyhow::Ok(())
        };
        // refresh bridge list
        let bridge_refresh_unix = self.inner.read().bridges_refresh_unix;
        let cached_exit = self.inner.read().cached_exit.clone();
        let bridge_fut = async {
            // if we have selected no exit, then we synchronize the cached exit
            let effective_exit_host = if self.selected_exit.is_empty() {
                cached_exit
            } else {
                self.selected_exit.clone()
            };
            // but if we have no cached exit either, we just skip bridge synchronization
            if effective_exit_host.is_empty() {
                return Ok(());
            }

            if current_unix > bridge_refresh_unix + BRIDGE_STALE_SECS
                || effective_exit_host != self.selected_exit
            {
                log::debug!("bridges stale so refreshing bridges");
                // refresh if the bridges are old, OR if the exit that's actually selected isn't the one in the persistent store
                let token = self.inner.read().blind_token.clone();
                let bridges = self
                    .rpc
                    .get_bridges_v2(token, effective_exit_host.as_str().into())
                    .await?;
                if bridges.is_empty() && !self.selected_exit.is_empty() {
                    anyhow::bail!("empty list of bridges received");
                }
                let mut inner = self.inner.write();
                inner.bridges = bridges;
                inner.bridges_refresh_unix = current_unix;
                inner.cached_exit = self.selected_exit.clone();
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
    pub fn bridges(&self) -> Vec<BridgeDescriptor> {
        self.inner.read().bridges.clone()
    }

    /// Gets the current master summary
    pub fn summary(&self) -> MasterSummary {
        self.inner.read().summary.clone()
    }

    /// Gets the current user info
    pub fn user_info(&self) -> UserInfoV2 {
        self.inner.read().user_info.clone()
    }

    /// Gets the current authentication token
    pub fn blind_token(&self) -> BlindToken {
        self.inner.read().blind_token.clone()
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

        // if !self.verify_summary(&summary).await? {
        //     anyhow::bail!(
        //         "summary hash from binder: {:?} does not match gibbername summary history",
        //         summary.clean_hash()
        //     );
        // }
        // log::info!("successfully verified master summary against gibbername summary history!");
        Ok(summary)
    }

    /// Verifies the given [`MasterSummary`] against what is stored in a gibbername chain on Mel.
    /// NOTE: There may be an interval where newly updated exit lists in the binder database are't consistent with
    /// what is stored on the corresponding gibbername chain.
    ///
    /// We check from newest to oldest until we find a match, or we run out of bindings.
    /// Old domain names being used by other people is not a threat because
    /// we also hash the sosistab2 public key of the servers, which other people can't get.
    async fn verify_summary(&self, summary: &MasterSummary) -> anyhow::Result<bool> {
        struct CustomRpcTransport {
            binder_client: Arc<BinderClient>,
            cache: Cache<HashVal, JrpcResponse>,
        }

        #[async_trait]
        impl RpcTransport for CustomRpcTransport {
            type Error = anyhow::Error;

            async fn call_raw(&self, req: JrpcRequest) -> Result<JrpcResponse, Self::Error> {
                let cache_key = (&req.method, &req.params).stdcode().hash();
                if let Some(mut val) = self.cache.get(&cache_key) {
                    val.id = req.id;
                    return Ok(val);
                }
                log::debug!("calling method = {}, args = {:?}", req.method, req.params);
                let resp = self.binder_client.reverse_proxy_melnode(req).await??;
                self.cache.insert(cache_key, resp.clone());
                Ok(resp)
            }
        }
        let my_summary_hash = summary.clean_hash();
        log::info!("about to verify summary hash from binder: {my_summary_hash}");

        // Connect to a melnode that is reverse-proxied through the binder.
        let client = melprot::Client::new(
            melstructs::NetID::Mainnet,
            NodeRpcClient::from(CustomRpcTransport {
                binder_client: self.rpc.clone(),
                cache: CacheBuilder::new(100)
                    .time_to_live(Duration::from_secs(5))
                    .build(),
            }),
        );
        // you must load the client with a hardcoded known height + block hash before it can verify anything
        let trusted_height = melbootstrap::checkpoint_height(melstructs::NetID::Mainnet)
            .context("Unable to get checkpoint height")?;
        client.trust(trusted_height);
        log::info!("^__^ !! created reverse-proxied mel client !! ^__^");

        let history = gibbername::lookup_whole_history(&client, "jermeb-beg").await?;
        log::info!("history from gibbername: {:?}", history);
        Ok(history
            .iter()
            .rev()
            .any(|summary_hash| summary_hash == &my_summary_hash.to_string()))
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
