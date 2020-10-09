use smol::prelude::*;
use std::{ops::Deref, sync::Arc, time::Duration, time::Instant};

pub struct ExecutorPool {
    exec: Arc<smol::Executor<'static>>,
}

impl Deref for ExecutorPool {
    type Target = smol::Executor<'static>;

    fn deref(&self) -> &smol::Executor<'static> {
        &self.exec
    }
}

impl Default for ExecutorPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutorPool {
    /// Creates a new ExecutorPool.
    pub fn new() -> Self {
        ExecutorPool {
            exec: Arc::new(smol::Executor::new()),
        }
    }

    /// Drives the given future to completion, spawning appropriate threads.
    pub fn block_on<F: Future<Output = T> + 'static + Send, T: Send + 'static>(&self, fut: F) -> T {
        let main_task = self.exec.spawn(fut);
        smol::block_on(main_task.or(async {
            loop {
                run_forever(self.exec.clone(), true).await;
            }
        }))
    }
}

/// Run forever.
///
/// The basic idea is that if try_tick repeatedly works, then it means we have an overloaded thread, and we spawn another.
async fn run_forever(exec: Arc<smol::Executor<'static>>, is_main: bool) {
    let mut load = 0.25;
    loop {
        if exec.try_tick() {
            load = 0.001 + load * 0.999
        } else {
            load *= 0.999
        }
        if load > 0.9 {
            let exec = exec.clone();
            load = 0.25;
            std::thread::Builder::new()
                .name("smolscale".into())
                .stack_size(512 * 1024)
                .spawn(move || smol::block_on(run_forever(exec, false)))
                .unwrap();
        }
        if is_main {
            exec.tick().await;
        } else {
            let fut = async {
                exec.tick().await;
                true
            }
            .or(async {
                smol::Timer::after(Duration::from_secs(1)).await;
                false
            });
            if !fut.await || load < 0.05 {
                return;
            }
        }
    }
}
