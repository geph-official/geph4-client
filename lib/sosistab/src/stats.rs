/// A time-series that is just a vector of things that automatically decimates and compacts old data.
#[derive(Debug)]
pub struct TimeSeries<T: Clone> {
    max_length: usize,
    items: im::Vector<T>,
}

impl<T: Clone> TimeSeries<T> {
    /// Pushes a new item into the time series.
    pub fn push(&mut self, item: T) {
        self.items.push_back(item);
        if self.items.len() >= self.max_length {
            // decimate the whole vector
            let half_vector: im::Vector<T> = self
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

    /// Get items
    pub fn items(&self) -> im::Vector<T> {
        self.items.clone()
    }
}
