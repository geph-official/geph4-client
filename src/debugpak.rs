pub struct Debugpak {
    db_path: String,
}

impl Debugpak {
    pub fn new(storage_path: &str) -> Self {
        // open database & create tables if not exist

        Self {
            db_path: storage_path.to_owned(),
        }
    }

    pub fn add_logline(&self, logline: &str) {
        todo!()
    }

    pub fn add_timeseries(&self, key: &str, value: f64) {
        todo!()
    }
}
