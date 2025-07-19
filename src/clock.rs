use std::time::SystemTime;

#[cfg(test)]
use std::sync::Mutex;

#[cfg(test)]
use std::time::Duration;

pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

#[derive(Default)]
pub struct RealClock {}

impl RealClock {
    pub fn new() -> Self {
        Self {}
    }
}

impl Clock for RealClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[cfg(test)]
pub struct MockClock {
    time: Mutex<SystemTime>,
}

#[cfg(test)]
impl MockClock {
    pub fn new(start_time: SystemTime) -> Self {
        Self {
            time: Mutex::new(start_time),
        }
    }

    pub fn advance(&self, delta: Duration) {
        *self.time.lock().unwrap() += delta;
    }
}

#[cfg(test)]
impl Default for MockClock {
    fn default() -> Self {
        Self {
            time: Mutex::new(SystemTime::UNIX_EPOCH),
        }
    }
}

#[cfg(test)]
impl Clock for MockClock {
    fn now(&self) -> SystemTime {
        *self.time.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
