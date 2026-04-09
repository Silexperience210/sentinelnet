//! Token-bucket rate limiter per IP address.
//! Used to protect POST /register from flooding.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BUCKET_CAPACITY: u32    = 20;     // max burst
const REFILL_RATE: u32        = 10;     // tokens added per window
const REFILL_WINDOW_SECS: u64 = 60;    // window size
const CLEANUP_EVERY: u32      = 1000;  // cleanup every N check() calls

struct Bucket {
    tokens:       u32,
    last_refill:  Instant,
}

impl Bucket {
    fn new() -> Self {
        Bucket { tokens: BUCKET_CAPACITY, last_refill: Instant::now() }
    }

    /// Attempt to consume 1 token. Returns true if allowed.
    fn try_consume(&mut self) -> bool {
        let elapsed = self.last_refill.elapsed();
        if elapsed >= Duration::from_secs(REFILL_WINDOW_SECS) {
            self.tokens = (self.tokens + REFILL_RATE).min(BUCKET_CAPACITY);
            self.last_refill = Instant::now();
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    fn is_stale(&self) -> bool {
        self.last_refill.elapsed() > Duration::from_secs(REFILL_WINDOW_SECS * 10)
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, Bucket>>>,
    check_count: Arc<Mutex<u32>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            check_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Returns true if request is allowed, false if rate-limited.
    pub fn check(&self, ip: &str) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        let mut count   = self.check_count.lock().unwrap();

        *count += 1;
        if *count >= CLEANUP_EVERY {
            buckets.retain(|_, b| !b.is_stale());
            *count = 0;
        }

        buckets.entry(ip.to_string())
            .or_insert_with(Bucket::new)
            .try_consume()
    }
}

impl Default for RateLimiter { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allows_initial_burst() {
        let rl = RateLimiter::new();
        for _ in 0..BUCKET_CAPACITY {
            assert!(rl.check("127.0.0.1"), "Should allow up to capacity");
        }
    }

    #[test]
    fn test_blocks_after_capacity() {
        let rl = RateLimiter::new();
        for _ in 0..BUCKET_CAPACITY { rl.check("10.0.0.1"); }
        assert!(!rl.check("10.0.0.1"), "Should block after capacity");
    }

    #[test]
    fn test_different_ips_independent() {
        let rl = RateLimiter::new();
        for _ in 0..BUCKET_CAPACITY { rl.check("1.2.3.4"); }
        assert!(!rl.check("1.2.3.4"), "IP1 blocked");
        assert!(rl.check("5.6.7.8"),  "IP2 still allowed");
    }
}
