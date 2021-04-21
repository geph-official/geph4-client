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

    /// Updates a statistical item.
    pub fn update(&self, stat: &str, val: f32) {
        if let Some(mapping) = &self.mapping {
            let mut ts = mapping
                .entry(stat.to_string())
                .or_insert_with(|| TimeSeries::new(1000000));
            ts.push(val)
        }
    }

    /// Increments a statistical item.
    pub fn increment(&self, stat: &str, delta: f32) {
        if let Some(mapping) = &self.mapping {
            let mut ts = mapping
                .entry(stat.to_string())
                .or_insert_with(|| TimeSeries::new(1000000));
            ts.increment(delta)
        }
    }

    /// Obtains the last value of a statistical item.
    pub fn get_last(&self, stat: &str) -> Option<f32> {
        let series = self.mapping.as_ref()?.get(stat)?;
        series.items.get_max().map(|v| v.1)
    }

    /// Obtains the whole TimeSeries, taking ownership of a snapshot.
    pub fn get_timeseries(&self, stat: &str) -> Option<TimeSeries> {
        Some(self.mapping.as_ref()?.get(stat)?.clone())
    }

    /// Iterates through all the TimeSeries in this stats gatherer.
    pub fn iter(&self) -> impl Iterator<Item = (String, TimeSeries)> {
        self.mapping.clone().unwrap_or_default().into_iter()
    }
}

/// A time-series that is just a time-indexed vector of f32s that automatically decimates and compacts old data.
#[derive(Debug, Clone, Default)]
pub struct TimeSeries {
    max_length: usize,
    items: im::OrdMap<SystemTime, f32>,
}

impl TimeSeries {
    /// Pushes a new item into the time series.
    pub fn push(&mut self, item: f32) {
        self.items.insert(SystemTime::now(), item);
    }

    fn may_decimate(&mut self) {
        if self.items.len() >= self.max_length {
            // decimate the whole vector
            let half_map: im::OrdMap<_, _> = self
                .items
                .iter()
                .enumerate()
                .filter_map(|(i, v)| {
                    if i % 10 != 0 {
                        Some((*v.0, *v.1))
                    } else {
                        None
                    }
                })
                .collect();
            self.items = half_map;
        }
    }

    /// Pushes a new item into the time series.
    pub fn increment(&mut self, delta: f32) {
        let last_val = self.items.get_max().map(|v| v.1).unwrap_or_default();
        self.items.insert(SystemTime::now(), delta + last_val);
        self.may_decimate()
    }

    /// Create a new time series with a given maximum length.
    pub fn new(max_length: usize) -> Self {
        Self {
            max_length,
            items: im::OrdMap::new(),
        }
    }

    /// Get an iterator over the elements
    pub fn iter(&self) -> impl Iterator<Item = (&SystemTime, &f32)> {
        self.items.iter()
    }

    /// Restricts the time series to points after a certain time.
    pub fn after(&self, time: SystemTime) -> Self {
        let (_, after) = self.items.split(&time);
        Self {
            items: after,
            max_length: self.max_length,
        }
    }

    /// Get the value at a certain time.
    pub fn get(&self, time: SystemTime) -> f32 {
        self.items.get_prev(&time).map(|v| *v.1).unwrap_or_default()
    }
}
