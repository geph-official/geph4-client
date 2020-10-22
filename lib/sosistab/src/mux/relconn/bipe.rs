use bytes::BytesMut;
use parking_lot::Mutex;
use smol::future::Future;
use smol::prelude::*;
use std::{pin::Pin, sync::Arc, task::Context, task::Poll};

/// Create a "bipe". Use async_dup's methods if you want something cloneable/shareable
pub fn bipe(capacity: usize) -> (BipeWriter, BipeReader) {
    let info = Arc::new(Mutex::new((false, BytesMut::new())));
    let event = Arc::new(event_listener::Event::new());
    (
        BipeWriter {
            queue: info.clone(),
            capacity,
            signal: event.clone(),
            listener: event.listen(),
        },
        BipeReader {
            queue: info,
            signal: event.clone(),
            listener: event.listen(),
        },
    )
}

/// Writing end of a byte pipe.
pub struct BipeWriter {
    queue: Arc<Mutex<(bool, BytesMut)>>,
    capacity: usize,
    signal: Arc<event_listener::Event>,
    listener: event_listener::EventListener,
}

impl Drop for BipeWriter {
    fn drop(&mut self) {
        self.queue.lock().0 = true;
        self.signal.notify(usize::MAX);
    }
}

fn broken_pipe() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionReset, "broken pipe")
}

impl AsyncWrite for BipeWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            // if there's room in the buffer then it's fine
            {
                let boo = &self.queue;
                let mut boo = boo.lock();
                if boo.0 {
                    return Poll::Ready(Err(broken_pipe()));
                }
                let queue = &mut boo.1;
                if queue.len() < self.capacity + buf.len() {
                    queue.extend_from_slice(buf);
                    self.signal.notify(usize::MAX);
                    return Poll::Ready(Ok(buf.len()));
                }
            }
            let listen_capacity = &mut self.listener;
            smol::pin!(listen_capacity);
            // there's no room, so we try again later
            smol::ready!(listen_capacity.poll(cx));
            self.listener = self.signal.listen()
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.queue.lock().0 = true;
        self.signal.notify(usize::MAX);
        Poll::Ready(Ok(()))
    }
}

/// Read end of a byte pipe.
pub struct BipeReader {
    queue: Arc<Mutex<(bool, BytesMut)>>,
    signal: Arc<event_listener::Event>,
    listener: event_listener::EventListener,
}

impl AsyncRead for BipeReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            {
                let boo = &self.queue;
                let mut boo = boo.lock();
                let queue = &mut boo.1;
                if !queue.is_empty() {
                    let to_copy_len = queue.len().min(buf.len());
                    (&mut buf[..to_copy_len]).copy_from_slice(&queue[..to_copy_len]);
                    *queue = queue.split_off(to_copy_len);
                    if queue.is_empty() {
                        *queue = BytesMut::new();
                    }
                    self.signal.notify(usize::MAX);
                    return Poll::Ready(Ok(to_copy_len));
                }
                if boo.0 {
                    return Poll::Ready(Err(broken_pipe()));
                }
            }
            let listen_new_data = &mut self.listener;
            smol::pin!(listen_new_data);
            smol::ready!(listen_new_data.poll(cx));
            self.listener = self.signal.listen();
        }
    }
}
