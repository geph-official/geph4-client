use anyhow::{anyhow, Result};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::ptr::{null_mut, NonNull};
use winapi::ctypes::c_ushort;

use winapi::um::wincred::{
    CredDeleteW, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
};

use winapi::um::winnt::LPWSTR;

use crate::AuthKind;

fn to_wide_chars(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn from_wide_ptr(ptr: *const u16) -> String {
    unsafe {
        let len = (0..).take_while(|&i| *ptr.offset(i) != 0).count();
        let slice = std::slice::from_raw_parts(ptr, len);
        OsString::from_wide(slice).to_string_lossy().into_owned()
    }
}

pub fn read_credentials(target_name: &str) -> Result<AuthKind> {
    let mut pcred: *mut CREDENTIALW = null_mut();
    let target_name = to_wide_chars(target_name);
    let result = unsafe { CredReadW(target_name.as_ptr(), CRED_TYPE_GENERIC, 0, &mut pcred) };

    if result == 0 {
        return Err(anyhow!("Failed to read credential"));
    }

    let credential: NonNull<CREDENTIALW> =
        NonNull::new(pcred).ok_or_else(|| anyhow!("Failed to read credential"))?;

    let credential = unsafe { &*credential.as_ptr() };

    // Decode the username and password
    let username_password = unsafe {
        let slice = std::slice::from_raw_parts(
            credential.CredentialBlob as *const _,
            credential.CredentialBlobSize as usize,
        );
        String::from_utf16(slice)?
    };

    // Free the credential memory
    unsafe { CredFree(pcred as *mut _) };

    let mut parts = username_password.splitn(2, ":");
    let username = parts
        .next()
        .ok_or_else(|| anyhow!("Failed to parse username"))?
        .to_string();
    let password = parts
        .next()
        .ok_or_else(|| anyhow!("Failed to parse password"))?
        .to_string();

    Ok(AuthKind::AuthPassword { username, password })
}
