use geph4client::{dispatch, ios::check_bridges, Opt};
// use rand::AsByteSliceMut;
use std::time::Duration;
use structopt::StructOpt;

fn main() -> anyhow::Result<()> {
    let opt: Opt = Opt::from_args();
    // std::thread::spawn(|| loop {
    //     eprintln!("yo checking bridges");
    //     let buflen = 2000;
    //     let mut buf = vec![0; buflen];
    //     let ret = check_bridges(buf.as_mut_ptr(), buflen as i32);
    //     // eprintln!("bridges = {:?}", buf);
    //     eprintln!("ret = {}", ret);
    //     std::thread::sleep(Duration::from_secs(10));
    // });

    dispatch(opt)
}
