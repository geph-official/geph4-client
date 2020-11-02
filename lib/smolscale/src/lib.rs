//! A global, auto-scaling, preemptive scheduler based on `async-executor`.
//!
//! `smolscale` is a fairly thin wrapper around a global [`async-executor`]. Unlike `async-global-executor` and friends, however, it has a **preemptive** thread pool that ensures that tasks cannot block other tasks no matter what. This means that you can do things like run expensive computations or even do blocking I/O within a task without worrying about causing deadlocks. Even with "traditional" tasks that do not block, this approach can reduce worst-case latency.
//!
//! Furthermore, the thread pool is **adaptive**, using the least amount of threads required to "get the job done". This minimizes OS-level context switching, increasing performance in I/O bound tasks compared to the usual approach of spawning OS threads matching the number of CPUs.
//!
//! Finally, this crate has seriously minimal dependencies, and will not add significantly to your compilation times.
//!
//! This crate is heavily inspired by Stjepan Glavina's [previous work on async-std](https://async.rs/blog/stop-worrying-about-blocking-the-new-async-std-runtime/).

use futures_lite::prelude::*;
use once_cell::sync::OnceCell;
use pin_project_lite::pin_project;
use std::{
    pin::Pin,
    sync::atomic::AtomicUsize,
    sync::atomic::Ordering,
    task::{Context, Poll},
    time::Duration,
};

//const CHANGE_THRESH: u32 = 10;
const MONITOR_MS: u64 = 50;

static EXEC: async_executor::Executor<'static> = async_executor::Executor::new();

static FUTURES_BEING_POLLED: AtomicUsize = AtomicUsize::new(0);
static FBP_NONZERO: event_listener::Event = event_listener::Event::new();
static POLL_COUNT: AtomicUsize = AtomicUsize::new(0);

static MONITOR: OnceCell<std::thread::JoinHandle<()>> = OnceCell::new();

fn start_monitor() {
    MONITOR.get_or_init(|| {
        std::thread::Builder::new()
            .name("sscale-mon".into())
            .spawn(monitor_loop)
            .unwrap()
    });
}

fn monitor_loop() {
    fn start_thread() {
        std::thread::Builder::new()
            .name("sscale-wkr".into())
            .spawn(|| async_io::block_on(EXEC.run(futures_lite::future::pending::<()>())))
            .unwrap();
    }
    start_thread();

    let mut running_threads: usize = 1;
    loop {
        std::thread::sleep(Duration::from_millis(MONITOR_MS));
        let fbp = loop {
            let fbp = FUTURES_BEING_POLLED.load(Ordering::SeqCst);
            if fbp > 0 {
                break fbp;
            }
            let listener = FBP_NONZERO.listen();
            let fbp = FUTURES_BEING_POLLED.load(Ordering::SeqCst);
            if fbp > 0 {
                break fbp;
            }
            listener.wait();
        };
        // let new_count = POLL_COUNT.load(Ordering::Relaxed);
        if fbp == running_threads {
            start_thread();
            running_threads += 1;
        }
    }
}

/// Spawns a task onto the lazily-initialized global executor.
///
/// The task can block or run CPU-intensive code if needed --- it will not block other tasks.
pub fn spawn<T: Send + 'static>(
    future: impl Future<Output = T> + Send + 'static,
) -> async_executor::Task<T> {
    start_monitor();
    EXEC.spawn(WrappedFuture::new(future))
}

pin_project! {
struct WrappedFuture<T, F: Future<Output = T>> {
    #[pin]
    fut: F,
}
}

impl<T, F: Future<Output = T>> Future for WrappedFuture<T, F> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let pval = FUTURES_BEING_POLLED.fetch_add(1, Ordering::SeqCst);
        if pval == 0 {
            FBP_NONZERO.notify(1);
        }
        POLL_COUNT.fetch_add(1, Ordering::Relaxed);
        scopeguard::defer!({
            FUTURES_BEING_POLLED.fetch_sub(1, Ordering::Relaxed);
        });
        this.fut.poll(cx)
    }
}

impl<T, F: Future<Output = T> + 'static> WrappedFuture<T, F> {
    pub fn new(fut: F) -> Self {
        WrappedFuture { fut }
    }
}
