//! Kernel TLS at the head of the load-aware routing order
//! (`accel::load::kernel`) of the `crypto_util` target.

use browntls_crypto::Error;
use browntls_crypto::accel::load::kernel::{self, Place, Records};
use browntls_crypto::accel::load::{self, Config, Phase};

use crate::input::Input;

pub(super) const KERNEL_ACTIVATE: u8 = 0;
pub(super) const KERNEL_DEACTIVATE: u8 = 1;
pub(super) const KERNEL_ENABLE: u8 = 2;
pub(super) const KERNEL_DISABLE: u8 = 3;
pub(super) const KERNEL_PLACE: u8 = 4;
pub(super) const KERNEL_WRITE: u8 = 5;
pub(super) const KERNEL_SET_FIXED: u8 = 6;
pub(super) const KERNEL_CLEAR_FIXED: u8 = 7;
const KERNEL_CALLS: usize = 8;

/// Writes asked about until one is timed: one long write in sixteen is.
const TRIES: usize = 256;
/// The shortest write that is timed.
const MEASURABLE: usize = 4096;

/// One fuzzed `accel::load::kernel` call on the stream of a fuzzed kind of
/// record work, with its outcome checked against the documented
/// conditions.
pub(super) fn kernel_op(input: &mut Input<'_>) {
    let records = *input.pick(&Records::ALL);
    let before = kernel::status(records);
    let active = kernel::is_active();
    let routing = active && load::config().is_some();
    assert_eq!(before.is_some(), active, "{records:?}");
    match u8::try_from(input.choose(KERNEL_CALLS)).unwrap_or(0) {
        KERNEL_ACTIVATE => {
            kernel::activate();
            assert!(kernel::is_active());
            if active {
                assert_eq!(kernel::status(records), before, "activated twice");
            }
        }
        KERNEL_DEACTIVATE => deactivate_kernel(),
        KERNEL_ENABLE => {
            // The fuzz project builds `browntls-crypto` with `std`.
            assert_eq!(load::enable(Config::DEFAULT), Ok(()));
            // Statistics gathered so far are kept.
            assert_eq!(
                kernel::status(records).map(|s| (s.primary_cost, s.baseline_cost)),
                before.map(|s| (s.primary_cost, s.baseline_cost))
            );
        }
        KERNEL_DISABLE => {
            load::disable();
            assert_eq!(kernel::is_active(), active, "disabling changed the order");
        }
        KERNEL_PLACE => {
            let place = kernel::place(records);
            let state = before.map(|s| (s.phase, s.shifted_percent));
            match (routing, state) {
                // Not in the order: the backends.
                (_, None) => assert_eq!(place, Place::Userspace),
                // The order alone decides.
                (false, Some(_))
                | (true, Some((Phase::Steady, _)))
                | (true, Some((Phase::Fixed, 0))) => assert_eq!(place, Place::Kernel),
                (true, Some((Phase::Fixed, 100))) => assert_eq!(place, Place::Userspace),
                // A share: either place.
                (true, Some(_)) => {}
            }
            assert_eq!(
                kernel::status(records),
                before,
                "placing changed the stream"
            );
        }
        KERNEL_WRITE => {
            let place = if input.bool() {
                Place::Kernel
            } else {
                Place::Userspace
            };
            let bytes = usize::from(input.u16());
            let sent = bytes.min(usize::from(input.u16()));
            let nanos = input.u64();
            let sample = (0..TRIES).find_map(|_| kernel::sample(records, place, bytes));
            let timed = sample.is_some();
            if let Some(sample) = sample {
                assert!(routing && bytes >= MEASURABLE, "{sample:?}");
                sample.done(sent, nanos);
            }
            let after = kernel::status(records);
            if !routing || bytes < MEASURABLE || (timed && sent < MEASURABLE) {
                // Nothing is timed outside the routing, no short write is,
                // and a write the socket cut short is ignored.
                assert!(routing || !timed);
                assert_eq!(after, before, "{records:?}: an untimed write");
            } else if timed {
                let s = after.expect("kernel TLS is active");
                match place {
                    Place::Kernel => assert!(s.primary_cost.is_some(), "{s}"),
                    Place::Userspace if s.phase == Phase::Fixed => {
                        assert!(s.alternate_cost.is_some(), "{s}");
                    }
                    Place::Userspace => {}
                }
            }
        }
        KERNEL_SET_FIXED => {
            let percent = input.byte();
            let possible = routing && percent <= 100;
            let result = kernel::set_fixed(records, percent);
            let after = kernel::status(records);
            match result {
                Ok(()) => {
                    assert!(possible, "{records:?}: set_fixed({percent}) succeeded");
                    let s = after.expect("kernel TLS is active");
                    assert_eq!((s.phase, s.shifted_percent), (Phase::Fixed, percent), "{s}");
                    assert_eq!(s.alternate, Some(Place::Userspace.name()), "{s}");
                }
                Err(e) => {
                    assert_eq!(e, Error::Unsupported);
                    assert!(!possible, "{records:?}: set_fixed({percent}) failed");
                    assert_eq!(after, before, "a failed set_fixed changed the stream");
                }
            }
        }
        _ => {
            kernel::clear_fixed(records);
            let after = kernel::status(records);
            if before.is_some_and(|s| s.phase == Phase::Fixed) {
                let s = after.expect("kernel TLS is active");
                assert_eq!(
                    (s.phase, s.alternate, s.shifted_percent),
                    (Phase::Steady, None, 0),
                    "{s}"
                );
            } else {
                assert_eq!(after, before, "{records:?}: clear_fixed");
            }
        }
    }
    check_kernel();
}

/// Takes kernel TLS out of the routing order and checks that nothing of it
/// is left: no stream is reported and every connection stays in userspace.
pub(super) fn deactivate_kernel() {
    kernel::deactivate();
    assert!(!kernel::is_active());
    assert_eq!(kernel::status_all().count(), 0);
    for records in Records::ALL {
        assert_eq!(kernel::status(records), None);
        assert_eq!(kernel::place(records), Place::Userspace);
        assert!(kernel::sample(records, Place::Kernel, 16384).is_none());
        assert_eq!(kernel::set_fixed(records, 50), Err(Error::Unsupported));
    }
}

/// Every `accel::load::kernel` report agrees with the others, with the
/// backends' streams and with the configuration.
pub(super) fn check_kernel() {
    let active = kernel::is_active();
    let config = load::config();
    let all: Vec<load::StreamStatus> = kernel::status_all().collect();
    assert_eq!(all.len(), if active { Records::ALL.len() } else { 0 });
    for (i, records) in Records::ALL.into_iter().enumerate() {
        // The family's stream that routes what stays in userspace.
        let family = load::status(records.algorithm(), records.lane())
            .expect("the record work has a stream of its family");
        assert_eq!(family.unit, "byte", "{family}");
        let Some(s) = kernel::status(records) else {
            assert!(!active, "{records:?} is not reported");
            continue;
        };
        assert_eq!(all[i], s);
        assert_eq!((s.algorithm, s.lane), (family.algorithm, family.lane));
        assert_eq!((s.primary, s.alternates), (Place::Kernel.name(), 1), "{s}");
        assert_eq!(s.unit, "byte", "{s}");
        assert!(!s.name.is_empty() && s.name != family.name, "{s}");
        assert!(s.to_string().contains(s.phase.name()), "{s}");
        assert!(s.shifted_percent <= 100, "{s}");
        if s.phase == Phase::Steady {
            assert_eq!(
                (s.alternate, s.shifted_percent, s.alternate_cost),
                (None, 0, None),
                "{s}"
            );
        } else {
            assert!(config.is_some(), "{s} while routing is disabled");
            assert_eq!(s.alternate, Some(Place::Userspace.name()), "{s}");
        }
        if config.is_none() {
            // Disabling forgot the statistics, and nothing is timed since.
            assert_eq!((s.primary_cost, s.baseline_cost), (None, None), "{s}");
        }
    }
    for place in [Place::Kernel, Place::Userspace] {
        assert_eq!(place.name(), place.to_string());
    }
}
