use postgres::{Client, NoTls};
use std::ffi::{CStr, CString};

pub struct BinderCore {
    database: String,
}

impl BinderCore {
    pub fn new_default() -> BinderCore {
        BinderCore {
            database: "host=localhost user=postgres password=postgres".to_string(),
        }
    }

    pub fn get_user_info(&self, username: &str) -> Result<UserInfo, BinderError> {
        let mut client =
            Client::connect(&self.database, NoTls).map_err(|_| BinderError::DatabaseFailed)?;
        let rows = client
            .query(
                "select id,username,pwdhash from users where username = $1",
                &[&username],
            )
            .map_err(|_| BinderError::DatabaseFailed)?;
        if rows.len() == 0 {
            return Err(BinderError::NoUserFound);
        }
        let row = &rows[0];
        let userid = row.get(0);
        let username = row.get(1);
        let pwdhash = row.get(2);
        Ok(UserInfo {
            userid,
            username,
            pwdhash,
        })
    }

    pub fn user_exists(&self, username: &str) -> Result<bool, BinderError> {
        match self.get_user_info(username) {
            Ok(_) => Ok(true),
            Err(BinderError::NoUserFound) => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub fn verify_password(&self, username: &str, password: &str) -> Result<(), BinderError> {
        let pwdhash = self.get_user_info(username)?.pwdhash;
        if verify_libsodium_password(password, &pwdhash) {
            Ok(())
        } else {
            Err(BinderError::WrongPassword)
        }
    }

    pub fn create_user(&mut self, username: &str, password: &str) -> Result<(), BinderError> {
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

    pub fn delete_user(&mut self, username: &str, password: &str) -> Result<(), BinderError> {
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

    pub fn change_password(
        &mut self,
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
            libsodium_sys::crypto_pwhash_OPSLIMIT_MODERATE as u64,
            libsodium_sys::crypto_pwhash_MEMLIMIT_MODERATE as usize,
        )
    };
    assert_eq!(res, 0);
    let cstr = unsafe { CStr::from_ptr(output.as_ptr() as *const i8) };
    cstr.to_str().unwrap().to_owned()
}

/// Error type enumerating all that could go wrong needed: e.g. user does not exist, wrong password, etc.
#[derive(Clone, Debug, Copy)]
pub enum BinderError {
    // user-related errors
    NoUserFound,
    UserAlreadyExists,
    WrongPassword,
    // database error
    DatabaseFailed,
}

#[derive(Clone, Debug)]
pub struct UserInfo {
    userid: i32,
    username: String,
    pwdhash: String,
}
