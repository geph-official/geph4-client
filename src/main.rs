use std::{ffi::CString, time::Duration};

use geph4client::{
    dispatch,
    ios::{call_geph, check_bridges, get_logs},
    Opt,
};
// use rand::AsByteSliceMut;
// use std::{ffi::CString, time::Duration};
use structopt::StructOpt;

// ios simulation going on here
fn main() -> anyhow::Result<()> {
    // logs loop
    std::thread::spawn(|| loop {
        let buflen = 1000;
        let mut buf = vec![0; buflen];
        let ret = get_logs(buf.as_mut_ptr(), buflen as i32);
        std::thread::sleep(Duration::from_secs(1));
    });

    let args_arr = vec![
        "geph4-client",
        "connect",
        "--username",
        "LisaWei",
        "--password",
        "doremi",
        "--exit-server",
        "us-hio-01.exits.geph.io",
        "--sticky-bridges",
        "--stdio-vpn",
    ];
    let json = serde_json::to_string(&args_arr)?;
    let ret = call_geph(json.as_ptr() as *const i8);

    unsafe {
        log::debug!("{}", CString::from_raw(ret).into_string()?);
    }

    Ok(())
}

// fn main() -> anyhow::Result<()> {
//     std::env::set_var("GEPH_RECURSIVE", "1"); // no forking in iOS
//     let args = Opt::from_args();
//     dispatch(args)
// }
