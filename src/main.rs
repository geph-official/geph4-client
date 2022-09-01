use geph4client::{
    dispatch,
    ios::{call_geph, LOG_LINES},
    Opt,
};
use std::{ffi::CString, io::BufRead};
use structopt::StructOpt;

// ios simulation going on here
// fn main() -> anyhow::Result<()> {
//     // logs loop
//     std::thread::spawn(|| loop {
//         let mut line = String::new();
//         if LOG_LINES.lock().read_line(&mut line).is_err() {
//             return -1;
//         }
//         eprint!("{}", line);
//     });

//     let args_arr = vec![
//         "geph4-client",
//         "connect",
//         "--username",
//         "LisaWei",
//         "--password",
//         "doremi",
//         "--exit-server",
//         "us-hio-01.exits.geph.io",
//         // "--use-tcp",
//         // "--http-listen",
//         // "0.0.0.0:9910",
//         // "--socks5-listen",
//         // "0.0.0.0:9909",
//         "--sticky-bridges",
//     ];
//     let json = serde_json::to_string(&args_arr)?;
//     let ret = call_geph(json.as_ptr() as *const i8);

//     unsafe {
//         log::debug!("{}", CString::from_raw(ret).into_string()?);
//     }

//     Ok(())
// }

fn main() -> anyhow::Result<()> {
    std::env::set_var("GEPH_RECURSIVE", "1"); // no forking in iOS
    let args = Opt::from_args();
    dispatch(args)
}
