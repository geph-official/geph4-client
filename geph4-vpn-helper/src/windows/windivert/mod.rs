//! A low-level, safe wrapper around WinDivert.
use anyhow::Result;
use bindings::WINDIVERT_ADDRESS;
use std::{ffi::CString, mem::MaybeUninit};
use thiserror::Error;

#[allow(dead_code, non_camel_case_types, non_snake_case)]
pub mod bindings;
mod packet;
pub use packet::*;
mod socket;
pub use socket::*;

#[derive(Debug, Error)]
#[error("internal WinDivert error: {0}")]
pub struct InternalError(bindings::DWORD);

fn check_c_error<T>(retcode: T, is_success: impl FnOnce(&T) -> bool) -> Result<T, InternalError> {
    if is_success(&retcode) {
        Ok(retcode)
    } else {
        // TODO we do this only because using GetLastError somehow causes a linker failure on the MSVC toolchain.
        let err = 100;
        Err(InternalError(err))
    }
}

/// A RAII-guarded WinDivert handle
pub struct Handle {
    handle: bindings::HANDLE,
}

unsafe impl Send for Handle {}

impl Handle {
    /// Open a new handle
    pub fn open(
        filter: &str,
        layer: Layer,
        priority: i16,
        flags: u64,
    ) -> Result<Self, InternalError> {
        let possibly_handle = unsafe {
            bindings::WinDivertOpen(
                CString::new(filter).unwrap().as_ptr() as *const i8,
                layer.to_windivert(),
                priority,
                flags,
            )
        };
        let handle = check_c_error(possibly_handle, |h| *h != std::ptr::null_mut())?;
        Ok(Self { handle })
    }

    /// Receives a single captured packet/event guaranteed to match the filter passed to open()
    pub fn receive(
        &self,
        packet_buf: Option<&mut [u8]>,
        addr_buf: Option<&mut MaybeUninit<bindings::WINDIVERT_ADDRESS>>,
    ) -> Result<usize, InternalError> {
        let mut recv_len = 0;
        let packet_len = packet_buf.as_ref().map(|v| v.len()).unwrap_or_default();

        let maybe_received = unsafe {
            bindings::WinDivertRecv(
                self.handle,
                packet_buf
                    .map(|v| v.as_mut_ptr())
                    .unwrap_or(std::ptr::null_mut()) as _,
                packet_len as _,
                &mut recv_len,
                addr_buf
                    .map(|v| v as *mut _)
                    .unwrap_or(std::ptr::null_mut()) as _,
            )
        };

        check_c_error(maybe_received, |n| *n > 0)?;
        Ok(recv_len as _)
    }

    pub fn send(&self, packet: &[u8], addr: WINDIVERT_ADDRESS) -> Result<(), InternalError> {
        let packet_len = packet.len() as u32;
        let maybe_injected = unsafe {
            bindings::WinDivertSend(
                self.handle,
                packet.as_ptr() as _,
                packet_len,
                std::ptr::null_mut(),
                &addr,
            )
        };

        check_c_error(maybe_injected, |b| *b > 0)?;
        Ok(())
    }
}

/// This prevents us from ever forgetting to close a handle.
impl Drop for Handle {
    fn drop(&mut self) {
        let retcode = unsafe { bindings::WinDivertClose(self.handle) };
        check_c_error(retcode, |v| *v > 0).expect("dropping a handle must succeed!");
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Layer {
    Network,
    NetworkForward,
    Flow,
    Socket,
    Reflect,
}

impl Layer {
    pub fn to_windivert(&self) -> i32 {
        match self {
            Layer::Network => bindings::WINDIVERT_LAYER_WINDIVERT_LAYER_NETWORK,
            Layer::NetworkForward => bindings::WINDIVERT_LAYER_WINDIVERT_LAYER_NETWORK_FORWARD,
            Layer::Flow => bindings::WINDIVERT_LAYER_WINDIVERT_LAYER_FLOW,
            Layer::Socket => bindings::WINDIVERT_LAYER_WINDIVERT_LAYER_SOCKET,
            Layer::Reflect => bindings::WINDIVERT_LAYER_WINDIVERT_LAYER_REFLECT,
        }
    }
}
