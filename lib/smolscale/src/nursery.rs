use std::{
    ops::Deref,
    sync::{Arc, Mutex},
};

use async_channel::{Receiver, Sender};
use futures_lite::prelude::*;
use slab::Slab;

/// A nursery represents a dynamic scope in which tasks can be spawned. It is used for *structured concurrency*, and it ensures that tasks spawned within the nursery terminate before the nursery falls out of scope.
///
/// We intentionally force all futures spawned in the nursery to return `anyhow::Result<()>`, and we do not expose join handles. This encourages a CSP-style anonymous-process way of thinking, and integration with `anyhow` allows for powerful error-propagation techniques.
///
/// Spawning is done through a NurseryHandle, which is clonable, rather than the Nursery itself. Nursery `Deref`'s into a `NurseryHandle` so that you can spawn from Nursery as well.
pub struct Nursery {
    nhandle: NurseryHandle,
    recv_error: Receiver<anyhow::Error>,
    recv_term: Receiver<()>,
}

impl Deref for Nursery {
    type Target = NurseryHandle;
    fn deref(&self) -> &Self::Target {
        &self.nhandle
    }
}

impl Default for Nursery {
    fn default() -> Self {
        Self::new()
    }
}

impl Nursery {
    /// Creates a new nursery
    pub fn new() -> Self {
        let (send_error, recv_error) = async_channel::unbounded();
        let (send_term, recv_term) = async_channel::unbounded();
        Self {
            nhandle: NurseryHandle {
                task_holder: Arc::new(Mutex::new(Slab::default())),
                send_error,
                send_term,
            },
            recv_error,
            recv_term,
        }
    }

    /// To handle
    pub fn handle(&self) -> NurseryHandle {
        self.nhandle.clone()
    }

    /// Waits for the tasks in the nursery to terminate. If any errors are propagated, immediately returns the error, terminating the whole nursery.
    ///
    /// This function asynchronously blocks until all NurseryHandles are dropped.
    pub async fn wait(self) -> anyhow::Result<()> {
        // simultaneously poll tasks and errors
        let a = async {
            if self.recv_error.sender_count() > 1 {
                let next_error = self
                    .recv_error
                    .recv()
                    .await
                    .expect("recv_error should never fail");
                Err(next_error)
            } else {
                Ok(())
            }
        };
        let b = async {
            while self.recv_error.sender_count() > 1 {
                self.recv_term.recv().await?;
            }
            Ok(())
        };
        a.or(b).await
    }

    /// Helper function that waits for nursery tasks synchronously.
    pub fn wait_sync(self) -> anyhow::Result<()> {
        futures_lite::future::block_on(self.wait())
    }
}

#[derive(Clone)]
pub struct NurseryHandle {
    task_holder: Arc<Mutex<Slab<async_executor::Task<()>>>>,
    send_error: Sender<anyhow::Error>,
    send_term: Sender<()>,
}

impl NurseryHandle {
    /// Spawns a task in the nursery, using the given recovery strategy. Takes a closure that returns a future because the task may be restarted on failure.
    pub fn spawn<F: Future<Output = anyhow::Result<()>> + Send + 'static>(
        &self,
        mut on_error: OnError,
        task_gen: impl FnOnce(NurseryHandle) -> F + Send + 'static,
    ) {
        let send_error = self.send_error.clone();
        let this = self.clone();
        let (send_tid, recv_tid) = async_oneshot::oneshot();
        let task_holder = self.task_holder.clone();
        let task = crate::spawn(async move {
            scopeguard::defer!({
                let _ = this.send_term.try_send(());
            });
            let send_error = send_error.clone();
            let result = task_gen(this.clone()).await;
            match result {
                Ok(()) => (),
                Err(err) => {
                    while let OnError::Custom(f) = on_error {
                        on_error = f(&err)
                    }
                    match on_error {
                        OnError::Ignore => (),
                        OnError::Propagate => {
                            let _ = send_error.send(err).await;
                        }
                        _ => unreachable!(),
                    }
                    if let Ok(tid) = recv_tid.await {
                        drop(task_holder.lock().unwrap().remove(tid));
                    };
                }
            }
        });
        let task_id = self.task_holder.lock().unwrap().insert(task);
        if send_tid.send(task_id).is_err() {
            drop(self.task_holder.lock().unwrap().remove(task_id));
        }
    }
}

/// The strategy used to recover from errors that a task returns.
pub enum OnError {
    Ignore,
    Propagate,
    Custom(Box<dyn FnOnce(&anyhow::Error) -> OnError + Send + Sync>),
}

impl OnError {
    /// Creates an error strategy based on the given closure. Convenience wrapper over `OnError::Custom` that boxes the closure for you.
    pub fn custom(f: impl FnOnce(&anyhow::Error) -> OnError + 'static + Send + Sync) -> Self {
        Self::Custom(Box::new(f))
    }
    /// Creates an error strategy that runs the given closure and ignores the error.
    pub fn ignore_with(f: impl FnOnce(&anyhow::Error) + 'static + Send + Sync) -> Self {
        Self::Custom(Box::new(move |e| {
            f(e);
            Self::Ignore
        }))
    }
    /// Creates an error strategy that runs the given closure and propagates it to the nursery.
    pub fn propagate_with(f: impl FnOnce(&anyhow::Error) + 'static + Send + Sync) -> Self {
        Self::Custom(Box::new(move |e| {
            f(e);
            Self::Propagate
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    #[test]
    fn nursery_simple() {
        let nursery = Nursery::new();
        let counter = Arc::new(AtomicUsize::new(0));
        nursery.spawn(OnError::Ignore, {
            let counter = counter.clone();
            move |nursery| async move {
                eprintln!("hello world");
                nursery.spawn(
                    OnError::propagate_with(|e| eprintln!("error: {}", e)),
                    |_| async {
                        eprintln!("attempt");
                        anyhow::bail!("oh no");
                    },
                );
                drop(nursery);
                drop(counter);
                Ok(())
            }
        });
        assert!(nursery.wait_sync().is_err())
    }
}
