use geph4client::{dispatch, Opt};
// use rand::AsByteSliceMut;
// use std::time::Duration;
use structopt::StructOpt;

fn main() -> anyhow::Result<()> {
    let opt: Opt = Opt::from_args();
    // std::thread::spawn(|| loop {
    //     eprintln!("yo checking bridges");
    //     let buflen = 1000;
    //     let mut buf = vec![0; buflen];
    //     let ret = check_bridges(buf.as_mut_ptr(), buflen as i32);
    //     // eprintln!("bridges = {:?}", buf);
    //     // eprintln!("ret = {}", ret);
    //     std::thread::sleep(Duration::from_secs(1));
    // });

    dispatch(opt)
}
