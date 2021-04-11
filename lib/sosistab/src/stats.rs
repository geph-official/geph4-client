use std::time::SystemTime;

use dashmap::DashMap;

/// A generic statistics gatherer, logically a string-keyed map of f64-valued time series. It has a fairly cheap Clone implementation, allowing easy "snapshots" of the stats at a given point in time. The Default implementation creates a no-op that does nothing.
#[derive(Debug, Clone, Default)]
pub struct StatsGatherer {
    mapping: Option<DashMap<String, TimeSeries>>,
}

impl StatsGatherer {
    /// Creates a usable statistics gatherer. Unlike the Default implementation, this one actually does something.
    pub fn new_active() -> Self {
        Self {
            mapping: Some(Default::default()),
        }
    }

    /// Saves a statistical item.
    pub fn set_stat(&self, stat: &str, val: f64) {
        if let Some(mapping) = &self.mapping {
            let mut ts = mapping
                .entry(stat.to_string())
                .or_insert_with(|| TimeSeries::new(100000));
            ts.push(val)
        }
    }

    /// Obtains the last value of a statistical item.
    pub fn get_last(&self, stat: &str) -> Option<f64> {
        let series = self.mapping.as_ref()?.get(stat)?;
        series.items.last().map(|v| v.1)
    }

    /// Iterates through all the TimeSeries in this stats gatherer.
    pub fn iter(&self) -> impl Iterator<Item = (String, TimeSeries)> {
        self.mapping.clone().unwrap_or_default().into_iter()
    }
}

/// A time-series that is just a time-indexed vector of f64s that automatically decimates and compacts old data. It is actually a *persistent* vector, so the Clone implementation is constant-time.
#[derive(Debug, Clone, Default)]
pub struct TimeSeries {
    max_length: usize,
    items: im::Vector<(SystemTime, f64)>,
}

impl TimeSeries {
    /// Pushes a new item into the time series.
    pub fn push(&mut self, item: f64) {
        // skip the value if time less than 10 ms
        if let Some((last_time, _)) = self.items.last() {
            if let Ok(elapsed) = last_time.elapsed() {
                if elapsed.as_millis() < 10 {
                    return;
                }
            }
        }
        self.items.push_back((SystemTime::now(), item));
        if self.items.len() >= self.max_length {
            // decimate the whole vector
            let half_vector: im::Vector<_> = self
                .items
                .iter()
                .cloned()
                .enumerate()
                .filter_map(|(i, v)| if i % 10 != 0 { Some(v) } else { None })
                .collect();
            self.items = half_vector;
        }
    }

    /// Create a new time series with a given maximum length.
    pub fn new(max_length: usize) -> Self {
        Self {
            max_length,
            items: im::Vector::new(),
        }
    }

    /// Get an iterator over the elements
    pub fn iter(&self) -> impl Iterator<Item = &(SystemTime, f64)> {
        self.items.iter()
    }
}
