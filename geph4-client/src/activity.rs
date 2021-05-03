use event_listener::Event;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use smol::prelude::*;
use std::time::{Duration, SystemTime};

static LAST_ACTIVITY: Lazy<Mutex<SystemTime>> = Lazy::new(|| Mutex::new(SystemTime::now()));
static ACTIVITY_EVENT: Event = Event::new();

/// Wait till there's activity
pub async fn wait_activity(timeout: Duration) {
    ACTIVITY_EVENT
        .listen()
        .or(async {
            smol::Timer::after(timeout).await;
        })
        .await
}

/// Notifies of activity.
pub fn notify_activity() {
    *LAST_ACTIVITY.lock() = SystemTime::now();
    ACTIVITY_EVENT.notify(usize::MAX);
}
