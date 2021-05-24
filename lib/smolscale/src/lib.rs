//! A global, auto-scaling, preemptive scheduler based on `async-executor`.
//!
//! `smolscale` is a fairly thin wrapper around a global [`async-executor`]. Unlike `async-global-executor` and friends, however, it has a **preemptive** thread pool that ensures that tasks cannot block other tasks no matter what. This means that you can do things like run expensive computations or even do blocking I/O within a task without worrying about causing deadlocks. Even with "traditional" tasks that do not block, this approach can reduce worst-case latency.
//!
//! Furthermore, the thread pool is **adaptive**, using the least amount of threads required to "get the job done". This minimizes OS-level context switching, increasing performance in I/O bound tasks compared to the usual approach of spawning OS threads matching the number of CPUs.
//!
//! Finally, this crate has seriously minimal dependencies, and will not add significantly to your compilation times.
//!
//! This crate is heavily inspired by Stjepan Glavina's [previous work on async-std](https://async.rs/blog/stop-worrying-about-blocking-the-new-async-std-runtime/).
//!
//! `smolscale` also includes `Nursery`, a helper for [structured concurrency](https://vorpus.org/blog/notes-on-structured-concurrency-or-go-statement-considered-harmful/) on the `smolscale` global executor.

use futures_lite::prelude::*;
use once_cell::sync::OnceCell;
use std::{
    pin::Pin,
    sync::atomic::AtomicUsize,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
    time::{Duration, Instant},
};
mod nursery;
pub use nursery::*;

//const CHANGE_THRESH: u32 = 10;
const MONITOR_MS: u64 = 200;

const MAX_THREADS: usize = 500;

// thread_local! {
//     static LEXEC: Rc<async_executor::LocalExecutor<'static>> = Rc::new(async_executor::LocalExecutor::new())
// }
static EXEC: async_executor::Executor<'static> = async_executor::Executor::new();

static FUTURES_BEING_POLLED: AtomicUsize = AtomicUsize::new(0);
static POLL_COUNT: AtomicUsize = AtomicUsize::new(0);

static THREAD_COUNT: AtomicUsize = AtomicUsize::new(0);

static MONITOR: OnceCell<std::thread::JoinHandle<()>> = OnceCell::new();

static SINGLE_THREAD: AtomicBool = AtomicBool::new(false);

/// Irrevocably puts smolscale into single-threaded mode.
pub fn permanently_single_threaded() {
    SINGLE_THREAD.store(true, Ordering::Relaxed);
}

fn start_monitor() {
    MONITOR.get_or_init(|| {
        std::thread::Builder::new()
            .name("sscale-mon".into())
            .spawn(monitor_loop)
            .unwrap()
    });
}

fn monitor_loop() {
    fn start_thread(exitable: bool, process_io: bool) {
        THREAD_COUNT.fetch_add(1, Ordering::Relaxed);
        std::thread::Builder::new()
            .name(
                if exitable {
                    "sscale-wkr-e"
                } else {
                    "sscale-wkr-c"
                }
                .into(),
            )
            .spawn(move || {
                // let local_exec = LEXEC.with(|v| Rc::clone(v));
                let future = async {
                    scopeguard::defer!({
                        THREAD_COUNT.fetch_sub(1, Ordering::Relaxed);
                    });
                    // let run_local = local_exec.run(futures_lite::future::pending::<()>());
                    if exitable {
                        EXEC.run(async {
                            async_io::Timer::after(Duration::from_secs(5)).await;
                        })
                        .await;
                    } else {
                        EXEC.run(futures_lite::future::pending::<()>()).await;
                    };
                };
                if process_io {
                    async_io::block_on(future)
                } else {
                    futures_lite::future::block_on(future)
                }
            })
            .unwrap();
    }
    if SINGLE_THREAD.load(Ordering::Relaxed) {
        start_thread(false, true);
        return;
    } else {
        for _ in 0..num_cpus::get() {
            start_thread(false, true);
        }
    }

    loop {
        if SINGLE_THREAD.load(Ordering::Relaxed) {
            return;
        }
        let before_sleep = POLL_COUNT.load(Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(MONITOR_MS));
        let after_sleep = POLL_COUNT.load(Ordering::Relaxed);
        let running_threads = THREAD_COUNT.load(Ordering::Relaxed);
        let full_running = FUTURES_BEING_POLLED.load(Ordering::Relaxed) >= running_threads;
        if after_sleep == before_sleep && running_threads <= MAX_THREADS && full_running {
            start_thread(true, false);
        }
    }
}

/// Spawns a future onto the global executor and immediately blocks on it.
pub fn block_on<T: Send + 'static>(future: impl Future<Output = T> + Send + 'static) -> T {
    futures_lite::future::block_on(spawn(future))
}

/// Spawns a task onto the lazily-initialized global executor.
///
/// The task can block or run CPU-intensive code if needed --- it will not block other tasks.
pub fn spawn<T: Send + 'static>(
    future: impl Future<Output = T> + Send + 'static,
) -> async_executor::Task<T> {
    start_monitor();
    EXEC.spawn(WrappedFuture::new(future))
    // async_global_executor::spawn(future)
}

// /// Spawns a task onto the lazily-initialized thread-local executor.
// ///
// /// The task should **NOT** block or run CPU-intensive code
// pub fn spawn<T: 'static>(
//     future: impl Future<Output = T> + 'static,
// ) -> async_executor::Task<T> {
//     start_monitor();
//     LEXEC.with(|v| v.spawn(future))
//     // async_global_executor::spawn(future)
// }

struct WrappedFuture<T, F: Future<Output = T>> {
    fut: F,
}

static ACTIVE_TASKS: AtomicUsize = AtomicUsize::new(0);

/// Returns the current number of active tasks.
pub fn active_task_count() -> usize {
    ACTIVE_TASKS.load(Ordering::Relaxed)
}

/// Returns the current number of running tasks.
pub fn running_task_count() -> usize {
    FUTURES_BEING_POLLED.load(Ordering::Relaxed)
}

impl<T, F: Future<Output = T>> Drop for WrappedFuture<T, F> {
    fn drop(&mut self) {
        ACTIVE_TASKS.fetch_sub(1, Ordering::Relaxed);
    }
}

impl<T, F: Future<Output = T>> Future for WrappedFuture<T, F> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        FUTURES_BEING_POLLED.fetch_add(1, Ordering::Relaxed);
        POLL_COUNT.fetch_add(1, Ordering::Relaxed);
        scopeguard::defer!({
            FUTURES_BEING_POLLED.fetch_sub(1, Ordering::Relaxed);
        });

        let fut = unsafe { self.map_unchecked_mut(|v| &mut v.fut) };
        let start = Instant::now();
        let res = fut.poll(cx);
        log::trace!("poll took {:?}", start.elapsed());
        res
    }
}

impl<T, F: Future<Output = T> + 'static> WrappedFuture<T, F> {
    pub fn new(fut: F) -> Self {
        ACTIVE_TASKS.fetch_add(1, Ordering::Relaxed);
        WrappedFuture { fut }
    }
}
