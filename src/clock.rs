use std::time::SystemTime;

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
pub mod test {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    pub struct MockClock {
        time: Mutex<SystemTime>,
    }

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

    impl Default for MockClock {
        fn default() -> Self {
            Self {
                time: Mutex::new(SystemTime::UNIX_EPOCH),
            }
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> SystemTime {
            *self.time.lock().unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use test::MockClock;

    #[test]
    fn test_default_mock_clock() {
        let clock = MockClock::default();
        assert_eq!(clock.now(), SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn test_new_mock_clock() {
        let clock = MockClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(123));
        assert_eq!(
            clock.now(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(123)
        );
    }

    #[test]
    fn test_advance_mock_clock() {
        let clock = MockClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(456));
        clock.advance(Duration::from_secs(789));
        assert_eq!(
            clock.now(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1245)
        );
    }
}
