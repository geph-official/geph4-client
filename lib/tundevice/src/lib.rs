use bytes::Bytes;
use fs::OpenOptions;
use smol::prelude::*;
use std::os::raw::c_char;
use std::os::unix::io::AsRawFd;
use std::{ffi::CStr, process::Command};
use std::{fs, io, os::raw::c_int};
extern "C" {
    fn tun_setup(fd: c_int, name: *mut u8) -> c_int;
}

/// A virtual TUN interface.
///
/// This is the main interface of this crate, representing a TUN device or something similar on non-Unix platforms.
#[derive(Debug)]
pub struct TunDevice {
    fd: async_dup::Mutex<smol::Async<fs::File>>,
    name: String,
}

impl TunDevice {
    /// Creates a new TUN interface by calling into the operating system.
    pub fn new_from_os(name: &str) -> io::Result<Self> {
        assert!(std::env::consts::OS == "linux");
        // open FD
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        // The buffer is larger than needed, but who cares… it is large enough.
        let mut name_buffer = Vec::new();
        name_buffer.extend_from_slice(name.as_bytes());
        name_buffer.extend_from_slice(&[0; 1024]);
        let name_ptr: *mut u8 = name_buffer.as_mut_ptr();
        let result = unsafe { tun_setup(fd.as_raw_fd(), name_ptr) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let name = unsafe {
            CStr::from_ptr(name_ptr as *const c_char)
                .to_string_lossy()
                .into_owned()
        };
        log::warn!("TUN DEVICE INITIALIZED {:#?}", fd);
        // return the device
        Ok(TunDevice {
            fd: async_dup::Mutex::new(smol::Async::new(fd)?),
            name,
        })
    }

    /// Assigns an IP address to the device.
    pub fn assign_ip(&self, cidr_str: &str) {
        assert!(std::env::consts::OS == "linux");
        // spawn ip tool
        Command::new("/usr/bin/env")
            .args(&["ip", "link", "set", &self.name, "up"])
            .output()
            .expect("cannot bring up interface!");
        Command::new("/usr/bin/env")
            .args(&["ip", "addr", "flush", "dev", &self.name])
            .output()
            .expect("cannot assign IP to interface!");
        Command::new("/usr/bin/env")
            .args(&["ip", "addr", "add", cidr_str, "dev", &self.name])
            .output()
            .expect("cannot assign IP to interface!");
        Command::new("/usr/bin/env")
            .args(&["ip", "link", "set", "dev", &self.name, "mtu", "1280"])
            .output()
            .expect("cannot set MTU to 1280!");
    }

    /// Reads raw packet.
    pub async fn read_raw(&self, buf: &mut [u8]) -> Option<usize> {
        Some((&self.fd).read(buf).await.ok()?)
    }

    /// Writes a packet.
    pub async fn write_raw(&self, to_write: &[u8]) -> Option<()> {
        (&self.fd).write(&to_write).await.ok();
        Some(())
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use std::{thread, time::Duration};

//     #[test]
//     fn test_tun() {
//         smol::block_on(async move {
//             let mut device = TunDevice::new_from_os("tun-test").unwrap();
//             device.assign_ip("10.89.64.2".parse().unwrap());
//             device.route_traffic("10.89.64.1".parse().unwrap());
//             loop {
//                 println!("{:?}", device.read_raw().await);
//             }
//         });
//     }
//     // commented out because this whole crate requires rootish perms
// }
