use async_task::Runnable;
use crossbeam_channel::{Receiver, Sender};
use smol::prelude::*;
use std::time::Duration;

const IDLE_THREAD_MS: u64 = 1000;
// const GROW_POOL_MS: u64 = 3;

pub struct ExecutorPool {
    send: Sender<Runnable>,
}

impl Default for ExecutorPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutorPool {
    /// Creates a new ExecutorPool. This implicitly starts an autoscaling thread pool in the background.
    pub fn new() -> Self {
        let (send, recv) = crossbeam_channel::unbounded();
        std::thread::Builder::new()
            .name("ss-manager".into())
            .spawn(move || execute_thread_pool(recv))
            .unwrap();
        ExecutorPool { send }
    }

    /// Runs the given future.
    pub fn spawn<F: Future<Output = T> + 'static + Send, T: Send + 'static>(
        &self,
        fut: F,
    ) -> smol::Task<T> {
        let send = self.send.clone();
        let schedule = move |runnable| send.send(runnable).unwrap();
        let (runnable, task) = async_task::spawn(fut, schedule);
        runnable.schedule();
        task
    }
}

fn execute_thread_pool(recv_tasks: Receiver<Runnable>) -> Option<()> {
    let (send_runnable, recv_runnable) = crossbeam_channel::bounded(0);
    loop {
        let to_run = recv_tasks.recv().ok()?;
        let returned = match send_runnable.try_send(to_run) {
            Err(crossbeam_channel::TrySendError::Full(to_run)) => Some(to_run),
            Err(crossbeam_channel::TrySendError::Disconnected(to_run)) => Some(to_run),
            Ok(()) => None,
        };
        if let Some(to_run) = returned {
            let recv_runnable = recv_runnable.clone();
            std::thread::Builder::new()
                .name("ss-worker".into())
                .spawn(move || execute_worker(to_run, recv_runnable))
                .unwrap();
        }
    }
}

fn execute_worker(first_runnable: Runnable, more_runnables: Receiver<Runnable>) {
    first_runnable.run();
    loop {
        let runnable = more_runnables.recv_timeout(Duration::from_millis(IDLE_THREAD_MS));
        if let Ok(runnable) = runnable {
            runnable.run();
        } else {
            return;
        }
    }
}
