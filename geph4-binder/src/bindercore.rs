use binder_transport::{BinderError, BridgeDescriptor, ExitDescriptor, SubscriptionInfo, UserInfo};

use native_tls::{Certificate, TlsConnector};

use parking_lot::Mutex;
use postgres_native_tls::MakeTlsConnector;
use r2d2_postgres::PostgresConnectionManager;

use std::{
    collections::HashMap,
    convert::TryFrom,
    convert::TryInto,
    ffi::{CStr, CString},
    net::SocketAddr,
    ops::DerefMut,
    time::Duration,
    time::SystemTime,
};

pub struct BinderCore {
    captcha_service: String,
    mizaru_sk: Mutex<HashMap<String, mizaru::SecretKey>>,
    conn_pool: r2d2::Pool<PostgresConnectionManager<postgres_native_tls::MakeTlsConnector>>,
}

impl BinderCore {
    /// Creates a BinderCore.
    pub fn create(database_url: &str, captcha_service_url: &str, cert: &[u8]) -> BinderCore {
        let connector = TlsConnector::builder()
            .add_root_certificate(Certificate::from_pem(cert).unwrap())
            .build()
            .unwrap();
        let connector = MakeTlsConnector::new(connector);
        let manager = PostgresConnectionManager::new(database_url.parse().unwrap(), connector);
        BinderCore {
            captcha_service: captcha_service_url.to_string(),
            mizaru_sk: Mutex::new(HashMap::new()),
            conn_pool: r2d2::Builder::new()
                .min_idle(Some(2))
                .max_size(8)
                .build(manager)
                .unwrap(),
        }
    }

    /// Obtains the master x25519 key.
    pub fn get_master_sk(&self) -> Result<x25519_dalek::StaticSecret, BinderError> {
        let mut client = self.get_pg_conn()?;
        let mut txn = client
            .transaction()
            .map_err(|err| BinderError::DatabaseFailed(err.to_string()))?;
        let row = txn
            .query_opt("select value from secrets where key='MASTER'", &[])
            .map_err(|err| BinderError::DatabaseFailed(err.to_string()))?;
        if let Some(row) = row {
            Ok(bincode::deserialize(row.get(0)).unwrap())
        } else {
            let sk = x25519_dalek::StaticSecret::new(rand::rngs::OsRng {});
            txn.execute(
                "insert into secrets values ($1, $2)",
                &[&"MASTER", &bincode::serialize(&sk).unwrap()],
            )
            .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
            txn.commit()
                .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
            Ok(sk)
        }
    }

    /// Obtains the Mizaru signing key.
    pub fn get_mizaru_sk(&self, acct_level: &str) -> Result<mizaru::SecretKey, BinderError> {
        if acct_level != "plus" && acct_level != "free" {
            return Err(BinderError::Other("whatever".into()));
        }
        let mut mizaru_sk = self.mizaru_sk.lock();
        if let Some(sk) = mizaru_sk.get(acct_level) {
            return Ok(sk.clone());
        }
        let key_name = format!("mizaru-master-sk-{}", acct_level);
        let mut client = self.get_pg_conn()?;
        let mut txn = client
            .transaction()
            .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
        let row = txn
            .query_opt("select value from secrets where key=$1", &[&key_name])
            .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
        match row {
            Some(row) => {
                let res: mizaru::SecretKey =
                    bincode::deserialize(row.get(0)).expect("must deserialize mizaru-master-sk");
                mizaru_sk.insert(acct_level.into(), res.clone());
                Ok(res)
            }
            None => {
                let secret_key = mizaru::SecretKey::generate();
                txn.execute(
                    "insert into secrets values ($1, $2)",
                    &[&key_name, &bincode::serialize(&secret_key).unwrap()],
                )
                .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
                txn.commit().unwrap();
                Ok(secret_key)
            }
        }
    }

    /// Obtain a connection.
    fn get_pg_conn(&self) -> Result<impl DerefMut<Target = postgres::Client>, BinderError> {
        let client = self.conn_pool.get();
        client.map_err(|e| BinderError::DatabaseFailed(e.to_string()))
    }

    /// Obtain the user info given the username.
    fn get_user_info(&self, username: &str) -> Result<UserInfo, BinderError> {
        let mut client = self.get_pg_conn()?;
        let mut txn = client
            .transaction()
            .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
        let rows = txn
            .query(
                "select id,username,pwdhash from users where username = $1",
                &[&username],
            )
            .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
        if rows.is_empty() {
            return Err(BinderError::NoUserFound);
        }
        let row = &rows[0];
        let userid: i32 = row.get(0);
        let username = row.get(1);
        let pwdhash = row.get(2);
        let subscription = txn
            .query_opt(
                "select plan, extract(epoch from expires) from subscriptions where id=$1",
                &[&userid],
            )
            .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?
            .map(|v| SubscriptionInfo {
                level: v.get(0),
                expires_unix: v.get::<_, f64>(1) as i64,
            });
        Ok(UserInfo {
            userid,
            username,
            pwdhash,
            subscription,
        })
    }

    /// Checks whether or not user exists.
    fn user_exists(&self, username: &str) -> Result<bool, BinderError> {
        match self.get_user_info(username) {
            Ok(_) => Ok(true),
            Err(BinderError::NoUserFound) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Checks whether or not a password is correct.
    fn verify_password(&self, username: &str, password: &str) -> Result<(), BinderError> {
        let pwdhash = self.get_user_info(username)?.pwdhash;
        if verify_libsodium_password(password, &pwdhash) {
            Ok(())
        } else {
            Err(BinderError::WrongPassword)
        }
    }

    /// Creates a new user, consuming a captcha answer.
    pub fn create_user(
        &self,
        username: &str,
        password: &str,
        captcha_id: &str,
        captcha_soln: &str,
    ) -> Result<(), BinderError> {
        if !verify_captcha(&self.captcha_service, captcha_id, captcha_soln)? {
            log::warn!("{} is not soln to {}", captcha_soln, captcha_id);
            return Err(BinderError::WrongCaptcha);
        }
        if self.user_exists(username)? {
            Err(BinderError::UserAlreadyExists)
        } else {
            let mut client = self.get_pg_conn()?;
            client.execute("insert into users (username, pwdhash, freebalance, createtime) values ($1, $2, $3, $4)",
            &[&username,
            &hash_libsodium_password(password),
            &1000,
            &std::time::SystemTime::now()]).map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
            Ok(())
        }
    }

    /// Obtains a captcha.
    pub fn get_captcha(&self) -> Result<(String, Vec<u8>), BinderError> {
        let captcha_id = generate_captcha(&self.captcha_service)?;
        let png_data = render_captcha_png(&self.captcha_service, &captcha_id)?;
        Ok((captcha_id, png_data))
    }

    /// Deletes a user, given a username and password.
    pub fn delete_user(&self, username: &str, password: &str) -> Result<(), BinderError> {
        if let Err(BinderError::WrongPassword) = self.verify_password(username, password) {
            Err(BinderError::WrongPassword)
        } else {
            let mut client = self.get_pg_conn()?;
            client
                .execute("delete from users where username=$1", &[&username])
                .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
            Ok(())
        }
    }

    /// Changes the password of the users.
    pub fn change_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), BinderError> {
        if let Err(BinderError::WrongPassword) = self.verify_password(username, old_password) {
            Err(BinderError::WrongPassword)
        } else {
            let new_pwdhash = hash_libsodium_password(new_password);
            let mut client = self.get_pg_conn()?;
            client
                .execute(
                    "update users set pwdhash=$1 where username =$2",
                    &[&new_pwdhash, &username],
                )
                .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
            Ok(())
        }
    }

    /// Gets epoch key
    pub fn get_epoch_key(
        &self,
        level: &str,
        epoch: usize,
    ) -> Result<rsa::RSAPublicKey, BinderError> {
        let lala = self.get_mizaru_sk(level)?;
        let sk = lala.get_subkey(epoch);
        Ok(sk.to_public_key())
    }

    /// Validates the username and password, and if it is valid, blind-sign the given digest and return the signature.
    pub fn authenticate(
        &self,
        username: &str,
        password: &str,
        level: &str,
        epoch: usize,
        blinded_digest: &[u8],
    ) -> Result<(UserInfo, mizaru::BlindedSignature), BinderError> {
        if level != "free" && level != "plus" {
            return Err(BinderError::Other("mizaru failed".into()));
        }
        let user_info = self.get_user_info(&username)?;
        self.check_login_ratelimit(user_info.userid)?;
        self.verify_password(&username, &password)?;

        let actual_level = user_info
            .clone()
            .subscription
            .map(|s| s.level)
            .unwrap_or_else(|| "free".to_string());
        if actual_level != level {
            return Err(BinderError::WrongLevel);
        }
        let key = self.get_mizaru_sk(level)?;
        let real_epoch = mizaru::time_to_epoch(SystemTime::now());
        if (real_epoch as i32 - epoch as i32).abs() <= 1 {
            let sig = key.blind_sign(epoch, blinded_digest);
            Ok((user_info, sig))
        } else {
            Err(BinderError::Other("mizaru failed".into()))
        }
    }

    /// checks whether the login violated the rate limit.
    fn check_login_ratelimit(&self, uid: i32) -> Result<(), BinderError> {
        const MAX_INTENSITY: f32 = 20.0;
        let mut conn = self.get_pg_conn()?;
        let mut txn = conn
            .transaction()
            .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
        let row = txn
            .query_one(
                "select coalesce(max(intensity), 0.0), coalesce(MAX(last_login), NOW()) from login_intensity where id = $1",
                &[&uid],
            )
            .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
        let existing_intensity: f32 = row.get(0);
        let existing_time: SystemTime = row.get(1);
        let days_past = existing_time.elapsed().unwrap_or_default().as_secs_f32() / 86400.0;
        let new_intensity = existing_intensity * (0.5f32.powf(days_past)) + 1.0;
        if new_intensity > MAX_INTENSITY {
            return Err(BinderError::Other(format!(
                "too many logins recently (intensity {})",
                existing_intensity
            )));
        }
        txn.execute("insert into login_intensity (id, intensity, last_login) values ($1, $2, $3) on conflict (id) do update set intensity = excluded.intensity", 
        &[&uid, &new_intensity, &SystemTime::now()]).map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
        txn.commit()
            .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
        Ok(())
    }

    /// Validates an token
    pub fn validate(
        &self,
        level: &str,
        unblinded_digest: &[u8],
        unblinded_signature: &mizaru::UnblindedSignature,
    ) -> Result<bool, BinderError> {
        // TODO rate-limit
        let key = self.get_mizaru_sk(level)?.to_public_key();
        Ok(key.blind_verify(unblinded_digest, unblinded_signature))
    }

    /// Adds a bridge route. We save this into the routes table, and every now and then we clear the table of really old values.
    pub fn add_bridge_route(
        &self,
        sosistab_pubkey: x25519_dalek::PublicKey,
        bridge_address: SocketAddr,
        bridge_group: &str,
        exit_hostname: &str,
        update_time: u64,
        exit_signature: ed25519_dalek::Signature,
    ) -> Result<(), BinderError> {
        let mut client = self.get_pg_conn()?;
        let mut txn: postgres::Transaction = client
            .transaction()
            .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
        // first check the exit signature
        let signing_key = {
            let bts: Vec<u8> = txn
                .query_one(
                    "select signing_key from exits where hostname=$1",
                    &[&exit_hostname],
                )
                .map_err(|e| BinderError::Other(e.to_string()))?
                .get(0);
            ed25519_dalek::PublicKey::from_bytes(&bts).unwrap()
        };
        let message =
            bincode::serialize(&(sosistab_pubkey, bridge_address, bridge_group, update_time))
                .unwrap();
        if signing_key
            .verify_strict(&message, &exit_signature)
            .is_err()
        {
            log::warn!(
                "invalid signature on bridge route for {}! silently ignoring!",
                exit_hostname
            );
            return Ok(());
        }
        let update_time: std::time::SystemTime =
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(update_time);
        let query = "insert into routes (hostname, sosistab_pubkey, bridge_address, bridge_group, update_time) values ($1, $2, $3, $4, $5)";
        txn.execute(
            query,
            &[
                &exit_hostname,
                &sosistab_pubkey.to_bytes().to_vec(),
                &bridge_address.to_string(),
                &bridge_group,
                &update_time,
            ],
        )
        .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
        txn.execute(
            "delete from routes where update_time < NOW() - interval '2 minute'",
            &[],
        )
        .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
        txn.commit()
            .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
        Ok(())
    }

    /// Get all exits
    pub fn get_exits(&self, only_free: bool) -> Result<Vec<ExitDescriptor>, BinderError> {
        let mut client = self.get_pg_conn()?;
        let mut txn: postgres::Transaction = client
            .transaction()
            .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
        let rows = txn
            .query(
                if only_free {
                    "select hostname,signing_key,country,city,sosistab_key from exits where plus = 'f'"
                } else {
                    "select hostname,signing_key,country,city,sosistab_key from exits"
                },
                &[],
            )
            .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
        let mut toret = rows
            .into_iter()
            .map(|row| ExitDescriptor {
                hostname: row.get(0),
                signing_key: ed25519_dalek::PublicKey::from_bytes(&row.get::<_, Vec<u8>>(1))
                    .unwrap(),
                country_code: row.get(2),
                city_code: row.get(3),
                sosistab_key: x25519_dalek::PublicKey::from(
                    <[u8; 32]>::try_from(row.get::<_, Vec<u8>>(4).as_slice()).unwrap(),
                ),
            })
            .collect::<Vec<_>>();
        toret.sort_by_key(|d| d.country_code.clone());
        Ok(toret)
    }

    /// Get all bridges.
    pub fn get_bridges(
        &self,
        level: &str,
        unblinded_digest: &[u8],
        unblinded_signature: &mizaru::UnblindedSignature,
        exit_hostname: &str,
    ) -> Result<Vec<BridgeDescriptor>, BinderError> {
        if !self.validate(level, unblinded_digest, unblinded_signature)? {
            return Err(BinderError::NoUserFound);
        }

        let mut client = self.get_pg_conn()?;
        let mut txn: postgres::Transaction<'_> = client
            .transaction()
            .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
        let query = "select bridge_address,sosistab_pubkey,bridge_group from routes where update_time > NOW() - interval '2 minute' and hostname=$1 and bridge_group not in (select bridge_group from route_blacklist where hostname=$1)";
        let mut rows = txn
            .query(query, &[&exit_hostname])
            .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
        // we sort by the keyed hash of the bridge address with the given unblinded digest. This ensures reasonable stability.
        rows.sort_by_key(|row| {
            let addr: String = row.get(0);
            *blake3::keyed_hash(blake3::hash(unblinded_digest).as_bytes(), addr.as_bytes())
                .as_bytes()
        });
        let mut res: Vec<_> = rows
            .into_iter()
            .map(|row| {
                let bridge_address: String = row.get(0);
                let bridge_address: SocketAddr = bridge_address.parse().unwrap();
                let sosistab_key: Vec<u8> = row.get(1);
                let sosistab_key: [u8; 32] = sosistab_key.as_slice().try_into().unwrap();
                let sosistab_key = x25519_dalek::PublicKey::from(sosistab_key);
                let group: String = row.get(2);
                (
                    BridgeDescriptor {
                        endpoint: bridge_address,
                        sosistab_key,
                    },
                    group,
                )
            })
            .collect();
        res.sort_by(|a, b| a.1.cmp(&b.1));
        res.dedup_by(|a, b| a.1 == b.1);
        log::debug!("serving out {} bridges", res.len());
        Ok(res.into_iter().map(|v| v.0).collect())
    }
}

/// Generate a captcha, returning its ID.
fn generate_captcha(captcha_service: &str) -> Result<String, BinderError> {
    // call out to the microservice
    let resp = ureq::get(&format!("{}/new", captcha_service))
        .timeout(Duration::from_secs(1))
        .call();
    if resp.ok() {
        Ok(resp
            .into_string()
            .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?)
    } else {
        Err(BinderError::DatabaseFailed("captcha failed".into()))
    }
}

/// Verify a captcha.
#[allow(clippy::unnecessary_wraps)]
fn verify_captcha(
    captcha_service: &str,
    captcha_id: &str,
    solution: &str,
) -> Result<bool, BinderError> {
    log::warn!(
        "verify_captcha({}, {}, {})",
        captcha_service,
        captcha_id,
        solution
    );
    // call out to the microservice
    let resp = ureq::get(&format!(
        "{}/solve?id={}&soln={}",
        captcha_service, captcha_id, solution
    ))
    .timeout(Duration::from_secs(1))
    .call();
    // TODO handle network errors
    Ok(resp.ok())
}

/// Render a captcha as PNG given a captcha service string.
fn render_captcha_png(captcha_service: &str, captcha_id: &str) -> Result<Vec<u8>, BinderError> {
    // download the captcha from the service
    let resp = ureq::get(&format!("{}/img/{}", captcha_service, captcha_id))
        .timeout(Duration::from_secs(1))
        .call();
    if resp.ok() {
        let mut v = vec![];
        use std::io::Read;
        resp.into_reader()
            .read_to_end(&mut v)
            .map_err(|e| BinderError::DatabaseFailed(e.to_string()))?;
        Ok(v)
    } else {
        Err(BinderError::DatabaseFailed("captcha failed".into()))
    }
}

fn verify_libsodium_password(password: &str, hash: &str) -> bool {
    let password = password.as_bytes();
    let hash = CString::new(hash).unwrap();
    let res = unsafe {
        libsodium_sys::crypto_pwhash_str_verify(
            hash.as_ptr(),
            password.as_ptr() as *const u8,
            password.len() as u64,
        )
    };
    res == 0
}

fn hash_libsodium_password(password: &str) -> String {
    let password = password.as_bytes();
    let mut output = vec![0u8; 1024];
    let res = unsafe {
        libsodium_sys::crypto_pwhash_str(
            output.as_mut_ptr() as *mut u8,
            password.as_ptr() as *const u8,
            password.len() as u64,
            libsodium_sys::crypto_pwhash_OPSLIMIT_INTERACTIVE as u64,
            libsodium_sys::crypto_pwhash_MEMLIMIT_INTERACTIVE as usize,
        )
    };
    assert_eq!(res, 0);
    let cstr = unsafe { CStr::from_ptr(output.as_ptr() as *const u8) };
    cstr.to_str().unwrap().to_owned()
}
