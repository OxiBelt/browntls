//! Session ticket encryption with periodic key rotation.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use std::sync::Mutex;

use browntls_pki::UnixTime;

use crate::crypto::TicketProducer;
use crate::error::Error;
use crate::rand::GetRandomFailed;
use crate::server::ProducesTickets;
use crate::sync::Arc;
use crate::time_provider::{DefaultTimeProvider, TimeProvider};

/// Rotates ticket keys: tickets are encrypted with the current key and
/// accepted under the current or the previous one, so every ticket stays
/// usable for at least `lifetime` seconds and at most twice that.
pub struct TicketRotator {
    generator: fn() -> Result<Box<dyn TicketProducer>, GetRandomFailed>,
    lifetime: u32,
    state: Mutex<TicketRotatorState>,
    time_provider: Arc<dyn TimeProvider>,
}

struct TicketRotatorState {
    current: Box<dyn TicketProducer>,
    previous: Option<Box<dyn TicketProducer>>,
    next_switch_time: u64,
}

impl TicketRotator {
    /// Builds a rotator whose keys come from `generator` and change every `lifetime` seconds.
    pub fn new(
        lifetime: u32,
        generator: fn() -> Result<Box<dyn TicketProducer>, GetRandomFailed>,
    ) -> Result<Self, Error> {
        Self::new_with_time_provider(lifetime, generator, Arc::new(DefaultTimeProvider))
    }

    /// Like [`Self::new`] with an explicit clock.
    pub fn new_with_time_provider(
        lifetime: u32,
        generator: fn() -> Result<Box<dyn TicketProducer>, GetRandomFailed>,
        time_provider: Arc<dyn TimeProvider>,
    ) -> Result<Self, Error> {
        let now = time_provider
            .current_time()
            .ok_or(Error::FailedToGetCurrentTime)?;
        Ok(Self {
            generator,
            lifetime,
            state: Mutex::new(TicketRotatorState {
                current: generator()?,
                previous: None,
                next_switch_time: now.as_secs().saturating_add(u64::from(lifetime)),
            }),
            time_provider,
        })
    }

    /// Rotates if the switch time has passed; returns the locked state.
    fn maybe_roll(&self, now: UnixTime) -> Option<std::sync::MutexGuard<'_, TicketRotatorState>> {
        let mut state = self.state.lock().ok()?;
        let now = now.as_secs();
        if now >= state.next_switch_time {
            let new = (self.generator)().ok()?;
            let old = core::mem::replace(&mut state.current, new);
            let lifetime = u64::from(self.lifetime);
            // The old key issued tickets from `next_switch_time - lifetime`.
            // Keep it as the previous key only until twice the lifetime has
            // passed since then, also after an idle period without any
            // ticket activity; otherwise drop it.
            let old_expiry = state.next_switch_time.saturating_add(lifetime);
            if now < old_expiry {
                state.previous = Some(old);
                state.next_switch_time = old_expiry;
            } else {
                state.previous = None;
                state.next_switch_time = now.saturating_add(lifetime);
            }
        }
        Some(state)
    }
}

impl ProducesTickets for TicketRotator {
    fn lifetime(&self) -> u32 {
        self.lifetime
    }

    fn enabled(&self) -> bool {
        true
    }

    fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
        let now = self.time_provider.current_time()?;
        let state = self.maybe_roll(now)?;
        state.current.encrypt(message)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let now = self.time_provider.current_time()?;
        let state = self.maybe_roll(now)?;
        state
            .current
            .decrypt(ciphertext)
            .or_else(|| state.previous.as_ref().and_then(|p| p.decrypt(ciphertext)))
    }
}

impl fmt::Debug for TicketRotator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TicketRotator")
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, feature = "rustcrypto"))]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FixedTime(core::sync::atomic::AtomicU64);

    impl TimeProvider for FixedTime {
        fn current_time(&self) -> Option<UnixTime> {
            Some(UnixTime::since_unix_epoch(core::time::Duration::from_secs(
                self.0.load(core::sync::atomic::Ordering::Relaxed),
            )))
        }
    }

    fn generator() -> Result<Box<dyn TicketProducer>, GetRandomFailed> {
        Ok(Box::new(
            crate::crypto::rustcrypto::ticketer::AeadTicketProducer::new()?,
        ))
    }

    #[test]
    fn rotation_keeps_previous_key() {
        let clock = Arc::new(FixedTime(core::sync::atomic::AtomicU64::new(1000)));
        let rotator = TicketRotator::new_with_time_provider(100, generator, clock.clone()).unwrap();
        assert!(rotator.enabled());
        assert_eq!(rotator.lifetime(), 100);
        let t1 = rotator.encrypt(b"one").unwrap();
        assert_eq!(rotator.decrypt(&t1).unwrap(), b"one");

        clock.0.store(1100, core::sync::atomic::Ordering::Relaxed);
        let t2 = rotator.encrypt(b"two").unwrap();
        // old ticket still decrypts under the previous key
        assert_eq!(rotator.decrypt(&t1).unwrap(), b"one");
        assert_eq!(rotator.decrypt(&t2).unwrap(), b"two");

        clock.0.store(1200, core::sync::atomic::Ordering::Relaxed);
        let _t3 = rotator.encrypt(b"three").unwrap();
        // two rotations later, the first key is gone
        assert!(rotator.decrypt(&t1).is_none());
        assert_eq!(rotator.decrypt(&t2).unwrap(), b"two");
    }

    #[test]
    fn idle_periods_do_not_extend_ticket_lifetime() {
        use core::sync::atomic::Ordering::Relaxed;
        let clock = Arc::new(FixedTime(core::sync::atomic::AtomicU64::new(1000)));
        let rotator = TicketRotator::new_with_time_provider(100, generator, clock.clone()).unwrap();
        let t1 = rotator.encrypt(b"one").unwrap();
        // No ticket activity for ten lifetimes: the first key issued t1 at
        // 1000, so it must not be accepted after 1200 (twice the lifetime).
        clock.0.store(2000, Relaxed);
        assert!(rotator.decrypt(&t1).is_none());
        // The new key starts a fresh period.
        let t2 = rotator.encrypt(b"two").unwrap();
        clock.0.store(2150, Relaxed);
        assert_eq!(rotator.decrypt(&t2).unwrap(), b"two");
        // Just before twice the lifetime after its key was installed (2000):
        // still accepted; at 2200 the key is dropped.
        clock.0.store(2199, Relaxed);
        assert_eq!(rotator.decrypt(&t2).unwrap(), b"two");
        clock.0.store(2200, Relaxed);
        assert!(rotator.decrypt(&t2).is_none());
    }

    #[test]
    fn late_rotation_keeps_the_schedule() {
        use core::sync::atomic::Ordering::Relaxed;
        let clock = Arc::new(FixedTime(core::sync::atomic::AtomicU64::new(1000)));
        let rotator = TicketRotator::new_with_time_provider(100, generator, clock.clone()).unwrap();
        // Issued just after the first key was installed.
        let t1 = rotator.encrypt(b"one").unwrap();
        // The first rotation happens late, at 1150: the first key may still
        // decrypt until 1200 (twice the lifetime after 1000), not 1250.
        clock.0.store(1150, Relaxed);
        let _t2 = rotator.encrypt(b"two").unwrap();
        assert_eq!(rotator.decrypt(&t1).unwrap(), b"one");
        clock.0.store(1200, Relaxed);
        assert!(rotator.decrypt(&t1).is_none());
    }
}
