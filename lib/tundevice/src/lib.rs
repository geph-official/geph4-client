use bytes::Bytes;
use flume::{Receiver, Sender};
use std::io::prelude::*;
use std::os::raw::c_char;
use std::os::unix::io::AsRawFd;
use std::{ffi::CStr, process::Command};
use std::{fs, io, os::raw::c_int};

use fs::OpenOptions;
extern "C" {
    fn tun_setup(fd: c_int, name: *mut u8) -> c_int;
}

/// A virtual TUN interface.
///
/// This is the main interface of this crate, representing a TUN device or something similar on non-Unix platforms.
#[derive(Debug)]
pub struct TunDevice {
    fd: fs::File,
    name: String,
    send_write: Sender<Bytes>,
    recv_read: Receiver<Bytes>,
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
        // spawn two threads
        let mut fd1 = fd.try_clone().unwrap();
        let (send_write, recv_write) = flume::bounded::<Bytes>(1000);
        let (send_read, recv_read) = flume::bounded::<Bytes>(1000);
        let mut fd2 = fd.try_clone().unwrap();
        std::thread::Builder::new()
            .name("tun-read".into())
            .spawn(move || {
                let mut buf = [0u8; 2048];
                for _ in 0.. {
                    let n = fd1.read(&mut buf).ok().unwrap();
                    // send_read.try_send(Bytes::copy_from_slice(&buf[..n]))
                    if send_read
                        .try_send(Bytes::copy_from_slice(&buf[..n]))
                        .is_err()
                    {
                        log::warn!("overflowing tundevice ({:?})", &buf[..n])
                    }
                }
                Some(())
            })
            .unwrap();
        std::thread::Builder::new()
            .name("tun-write".into())
            .spawn(move || {
                for _ in 0.. {
                    let bts = recv_write.recv().ok()?;
                    let _ = fd2.write_all(&bts);
                    let _ = fd2.flush();
                }
                Some(())
            })
            .unwrap();
        log::warn!("TUN DEVICE INITIALIZED {:#?}", fd);
        // return the device
        Ok(TunDevice {
            fd,
            name,
            send_write,
            recv_read,
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
            .args(&["ip", "addr", "add", cidr_str, "dev", &self.name])
            .output()
            .expect("cannot assign IP to interface!");
        Command::new("/usr/bin/env")
            .args(&["ip", "link", "set", "dev", &self.name, "mtu", "1280"])
            .output()
            .expect("cannot set MTU to 1280!");
    }

    /// Reads raw packet.
    pub async fn read_raw(&self) -> Option<Bytes> {
        self.recv_read.recv_async().await.ok()
    }

    /// Writes a packet.
    pub async fn write_raw(&self, to_write: Bytes) -> Option<()> {
        self.send_write.send_async(to_write).await.ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};

    #[test]
    fn test_tun() {
        smol::block_on(async move {
            let mut device = TunDevice::new_from_os("tun-test").unwrap();
            device.assign_ip("10.89.64.2".parse().unwrap());
            device.route_traffic("10.89.64.1".parse().unwrap());
            loop {
                println!("{:?}", device.read_raw().await);
            }
        });
    }
    // commented out because this whole crate requires rootish perms
}
