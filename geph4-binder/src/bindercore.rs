use binder_transport::{BinderError, SubscriptionInfo, UserInfo};
use postgres::{Client, NoTls};
use std::{
    ffi::{CStr, CString},
    time::Duration,
};

pub struct BinderCore {
    database: String,
    captcha_service: String,
}

impl BinderCore {
    pub fn new_default() -> BinderCore {
        BinderCore {
            database: "host=localhost user=postgres password=postgres".to_string(),
            captcha_service: "https://single-verve-156821.ew.r.appspot.com".to_string(),
        }
    }

    /// Obtain the user info given the username.
    fn get_user_info(&self, username: &str) -> Result<UserInfo, BinderError> {
        let mut client =
            Client::connect(&self.database, NoTls).map_err(|_| BinderError::DatabaseFailed)?;
        let mut txn = client.transaction()?;
        let rows = txn
            .query(
                "select id,username,pwdhash from users where username = $1",
                &[&username],
            )
            .map_err(|_| BinderError::DatabaseFailed)?;
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
            .map_err(|_| BinderError::DatabaseFailed)?
            .map(|v| SubscriptionInfo {
                level: v.get(0),
                expires_unix: v.get(1),
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
            return Err(BinderError::WrongCaptcha);
        }
        if self.user_exists(username)? {
            Err(BinderError::UserAlreadyExists)
        } else {
            let mut client =
                Client::connect(&self.database, NoTls).map_err(|_| BinderError::DatabaseFailed)?;
            client.execute("insert into users (username, pwdhash, freebalance, createtime) values ($1, $2, $3, $4)",
            &[&username,
            &hash_libsodium_password(password),
            &1000,
            &std::time::SystemTime::now()]).map_err(|_| BinderError::DatabaseFailed)?;
            Ok(())
        }
    }

    /// Obtains a captcha ID and image.
    pub fn get_captcha_png(&self) -> Result<(String, Vec<u8>), BinderError> {
        let id = generate_captcha(&self.captcha_service)?;
        let captcha = render_captcha_png(&self.captcha_service, &id)?;
        Ok((id, captcha))
    }

    /// Solves a captcha, returning whether or not it worked.
    pub fn solve_captcha(&self, captcha_id: &str, captcha_soln: &str) -> Result<bool, BinderError> {
        Ok(verify_captcha(
            &self.captcha_service,
            captcha_id,
            &captcha_soln,
        )?)
    }

    /// Deletes a user, given a username and password.
    pub fn delete_user(&self, username: &str, password: &str) -> Result<(), BinderError> {
        if let Err(BinderError::WrongPassword) = self.verify_password(username, password) {
            Err(BinderError::WrongPassword)
        } else {
            let mut client =
                Client::connect(&self.database, NoTls).map_err(|_| BinderError::DatabaseFailed)?;
            client
                .execute("delete from users where username=$1", &[&username])
                .map_err(|_| BinderError::DatabaseFailed)?;
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
            let mut client =
                Client::connect(&self.database, NoTls).map_err(|_| BinderError::DatabaseFailed)?;
            client
                .execute(
                    "update users set pwdhash=$1 where username =$2",
                    &[&new_pwdhash, &username],
                )
                .map_err(|_| BinderError::DatabaseFailed)?;
            Ok(())
        }
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
            .map_err(|_| BinderError::DatabaseFailed)?)
    } else {
        Err(BinderError::DatabaseFailed)
    }
}

/// Verify a captcha.
fn verify_captcha(
    captcha_service: &str,
    captcha_id: &str,
    solution: &str,
) -> Result<bool, BinderError> {
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
            .map_err(|_| BinderError::DatabaseFailed)?;
        Ok(v)
    } else {
        Err(BinderError::DatabaseFailed)
    }
}

fn verify_libsodium_password(password: &str, hash: &str) -> bool {
    let password = password.as_bytes();
    let hash = CString::new(hash).unwrap();
    let res = unsafe {
        libsodium_sys::crypto_pwhash_str_verify(
            hash.as_ptr(),
            password.as_ptr() as *const i8,
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
            output.as_mut_ptr() as *mut i8,
            password.as_ptr() as *const i8,
            password.len() as u64,
            libsodium_sys::crypto_pwhash_OPSLIMIT_INTERACTIVE as u64,
            libsodium_sys::crypto_pwhash_MEMLIMIT_INTERACTIVE as usize,
        )
    };
    assert_eq!(res, 0);
    let cstr = unsafe { CStr::from_ptr(output.as_ptr() as *const i8) };
    cstr.to_str().unwrap().to_owned()
}
