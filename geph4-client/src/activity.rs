use std::time::SystemTime;

use once_cell::sync::Lazy;
use parking_lot::Mutex;

static LAST_ACTIVITY: Lazy<Mutex<SystemTime>> = Lazy::new(|| Mutex::new(SystemTime::now()));

/// Returns a timeout multiplier based on last activity.
pub fn timeout_multiplier() -> f64 {
    let seconds = LAST_ACTIVITY
        .lock()
        .elapsed()
        .map(|v| v.as_secs_f64())
        .unwrap_or_default();
    // doubles every 10 seconds, maxing out at 20 times the original value
    2.0f64.powf(seconds / 10.0).min(10.0)
}

/// Notifies of activity.
pub fn notify_activity() {
    *LAST_ACTIVITY.lock() = SystemTime::now();
}
