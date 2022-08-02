use std::collections::VecDeque;

pub struct LogBuffer {
    logs: VecDeque<char>,
    mem_limit: usize, // in # of characters
}

impl LogBuffer {
    pub fn new(mem_limit: usize) -> Self {
        Self {
            logs: VecDeque::new(),
            mem_limit,
        }
    }

    pub fn add_line(&mut self, line: &str) {
        for c in line.chars() {
            self.logs.push_back(c);
        }
        self.logs.push_back('\n');

        while self.logs.len() > self.mem_limit {
            self.logs.pop_front();
        }
    }

    pub fn get_logs(&self) -> String {
        self.logs.clone().into_iter().collect()
    }
}
