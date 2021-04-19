use std::time::{Duration, Instant};

const MAX_MEASUREMENTS: usize = 32;

pub struct RttCalculator {
    // sorted vector
    rtt_measurements: Vec<u64>,

    // rate estimation
    min_rtt: u64,
    rtt_update_time: Instant,
}

impl Default for RttCalculator {
    fn default() -> Self {
        RttCalculator {
            rtt_measurements: vec![300],
            min_rtt: 300,
            rtt_update_time: Instant::now(),
        }
    }
}

impl RttCalculator {
    pub fn record_sample(&mut self, sample: Duration) {
        let sample = (sample.as_millis() as u64).max(1);
        self.rtt_measurements.push(sample);
        self.rtt_measurements.sort_unstable();
        // if over limit, decimate
        if self.rtt_measurements.len() > MAX_MEASUREMENTS {
            for i in 0..self.rtt_measurements.len() / 2 {
                self.rtt_measurements[i] = self.rtt_measurements[i * 2]
            }
            self.rtt_measurements
                .truncate(self.rtt_measurements.len() / 2)
        }

        // delivery rate
        let now = Instant::now();
        if sample < self.min_rtt
            || now
                .saturating_duration_since(self.rtt_update_time)
                .as_millis()
                > 10000
        {
            self.min_rtt = sample;
            self.rtt_update_time = now;
        }
    }

    pub fn rto(&self) -> Duration {
        Duration::from_millis(*self.rtt_measurements.last().unwrap()) + self.srtt()
    }

    pub fn srtt(&self) -> Duration {
        Duration::from_millis(self.rtt_measurements[self.rtt_measurements.len() / 2])
    }

    pub fn rtt_var(&self) -> Duration {
        Duration::from_millis(
            *self.rtt_measurements.last().unwrap() - *self.rtt_measurements.first().unwrap(),
        )
    }

    pub fn min_rtt(&self) -> Duration {
        Duration::from_millis(self.min_rtt)
    }
}
