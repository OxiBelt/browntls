//! Ticketers, session caches, the SNI certificate resolver, certificate
//! compression, the key log file and enum helpers.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use browntls_core::client::{ClientSessionMemoryCache, ClientSessionStore};
use browntls_core::compress::{self, CompressionLevel};
use browntls_core::crypto::{GetRandomFailed, TicketProducer, native, rustcrypto};
use browntls_core::pki_types::{ServerName, UnixTime};
use browntls_core::server::{
    ProducesTickets, ResolvesServerCertUsingSni, ServerSessionMemoryCache, StoresServerSessions,
};
use browntls_core::sign::CertifiedKey;
use browntls_core::ticketer::TicketRotator;
use browntls_core::time_provider::TimeProvider;
use browntls_core::{CipherSuite, KeyLog, KeyLogFile, NamedGroup, ProtocolVersion};

use super::fixtures;
use super::sign::{load, loadable};
use super::verifiers::{name_verdict, server_name};
use crate::input::Input;

// ----------------------------------------------------------------- tickets

/// A clock the harness moves.
#[derive(Debug)]
struct Clock(AtomicU64);

impl TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(core::time::Duration::from_secs(
            self.0.load(Ordering::Relaxed),
        )))
    }
}

fn native_producer() -> Result<Box<dyn TicketProducer>, GetRandomFailed> {
    Ok(Box::new(native::ticketer::AeadTicketProducer::new()?))
}

fn rustcrypto_producer() -> Result<Box<dyn TicketProducer>, GetRandomFailed> {
    Ok(Box::new(rustcrypto::ticketer::AeadTicketProducer::new()?))
}

/// The rotation schedule of `TicketRotator`, by key generation.
struct RotationModel {
    lifetime: u64,
    current: u32,
    previous: Option<u32>,
    next_switch: u64,
}

impl RotationModel {
    fn roll(&mut self, now: u64) {
        if now >= self.next_switch {
            let old = self.current;
            self.current += 1;
            let old_expiry = self.next_switch.saturating_add(self.lifetime);
            if now < old_expiry {
                self.previous = Some(old);
                self.next_switch = old_expiry;
            } else {
                self.previous = None;
                self.next_switch = now.saturating_add(self.lifetime);
            }
        }
    }
}

fn tamper(input: &mut Input<'_>, ticket: &[u8]) -> Vec<u8> {
    let mut bad = ticket.to_vec();
    match input.choose(3) {
        0 => {
            let at = usize::from(input.u16()) % bad.len();
            bad[at] ^= 1 << input.choose(8);
        }
        1 => bad.truncate(usize::from(input.u16()) % bad.len()),
        _ => bad.push(input.byte()),
    }
    bad
}

/// The AEAD ticket producers directly, and `TicketRotator` against a model
/// of its key schedule driven by a fuzzed clock.
pub(super) fn ticket_op(input: &mut Input<'_>) {
    // Producers: round trip, tampering, foreign keys.
    let producers: [Box<dyn TicketProducer>; 2] = [
        native_producer().expect("native producer"),
        rustcrypto_producer().expect("rustcrypto producer"),
    ];
    let which = input.choose(2);
    let producer = &producers[which];
    let plain = input.field();
    let ticket = producer.encrypt(plain).expect("encrypt");
    assert_eq!(producer.decrypt(&ticket).as_deref(), Some(plain));
    assert_ne!(
        producer.encrypt(plain).expect("encrypt"),
        ticket,
        "repeated nonce"
    );
    assert!(producer.decrypt(&tamper(input, &ticket)).is_none());
    assert!(producers[1 - which].decrypt(&ticket).is_none());
    let _ = producer.decrypt(input.field());
    let _ = producer.fips();

    // A rotator under a controlled clock.
    let start = input.u64() >> 1;
    let lifetime = input.u32() % 100_000;
    let clock = Arc::new(Clock(AtomicU64::new(start)));
    let generator = if input.bool() {
        native_producer
    } else {
        rustcrypto_producer
    };
    let rotator =
        TicketRotator::new_with_time_provider(lifetime, generator, clock.clone()).expect("rotator");
    assert_eq!(rotator.lifetime(), lifetime);
    assert!(rotator.enabled());
    let mut model = RotationModel {
        lifetime: u64::from(lifetime),
        current: 0,
        previous: None,
        next_switch: start.saturating_add(u64::from(lifetime)),
    };
    let mut tickets: Vec<(Vec<u8>, u32, Vec<u8>)> = Vec::new();
    for _ in 0..input.choose(12) {
        match input.choose(4) {
            0 => {
                let now = clock.0.load(Ordering::Relaxed);
                let step = u64::from(input.u32()) % (2 * u64::from(lifetime) + 2);
                clock.0.store(now.saturating_add(step), Ordering::Relaxed);
            }
            1 => {
                let now = clock.0.load(Ordering::Relaxed);
                model.roll(now);
                let plain = input.short_field().to_vec();
                let ticket = rotator.encrypt(&plain).expect("encrypt");
                tickets.push((ticket, model.current, plain));
            }
            2 if !tickets.is_empty() => {
                let now = clock.0.load(Ordering::Relaxed);
                model.roll(now);
                let (ticket, generation, plain) = &tickets[input.choose(tickets.len())];
                let live = *generation == model.current || model.previous == Some(*generation);
                let got = rotator.decrypt(ticket);
                assert_eq!(
                    got.as_deref(),
                    live.then_some(&plain[..]),
                    "generation {generation}, model {} {:?}",
                    model.current,
                    model.previous
                );
                model.roll(now);
                assert!(rotator.decrypt(&tamper(input, ticket)).is_none());
            }
            _ => {
                let now = clock.0.load(Ordering::Relaxed);
                model.roll(now);
                let _ = rotator.decrypt(input.field());
            }
        }
    }

    // The rotators behind the public constructors (real clock; a lifetime
    // long enough not to roll between the two calls).
    let rotator = TicketRotator::new(3600 + lifetime, generator).expect("rotator");
    let ticket = rotator.encrypt(plain).expect("encrypt");
    assert_eq!(rotator.decrypt(&ticket).as_deref(), Some(plain));
    let ticketer = rustcrypto::Ticketer::new().expect("ticketer");
    let ticket = ticketer.encrypt(plain).expect("encrypt");
    assert_eq!(ticketer.decrypt(&ticket).as_deref(), Some(plain));
    assert!(ticketer.decrypt(&tamper(input, &ticket)).is_none());
}

// ---------------------------------------------------------- session caches

/// `LimitedCache`'s behaviour: a map whose oldest key is evicted.
struct CacheModel<K> {
    map: HashMap<K, Vec<u8>>,
    order: VecDeque<K>,
    capacity: usize,
}

impl<K: std::hash::Hash + Eq + Clone> CacheModel<K> {
    fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    fn insert(&mut self, k: K, v: Vec<u8>) {
        if self.map.insert(k.clone(), v).is_none() {
            self.order.push_back(k);
            while self.map.len() > self.capacity {
                match self.order.pop_front() {
                    Some(old) => {
                        self.map.remove(&old);
                    }
                    None => break,
                }
            }
        }
    }

    fn remove(&mut self, k: &K) -> Option<Vec<u8>> {
        let v = self.map.remove(k)?;
        if let Some(pos) = self.order.iter().position(|x| x == k) {
            self.order.remove(pos);
        }
        Some(v)
    }
}

/// `ServerSessionMemoryCache` against the model.
pub(super) fn server_cache_op(input: &mut Input<'_>) {
    let size = input.choose(6);
    let cache = ServerSessionMemoryCache::new(size);
    assert!(cache.can_cache());
    let session = vec![0, 3, 4];
    assert!(cache.put(vec![0xff], session.clone()));
    assert_eq!(
        cache.session_version(&[0xff]),
        Some(ProtocolVersion::TLSv1_3)
    );
    assert_eq!(cache.take(&[0xff]), Some(session));
    let mut model = CacheModel::new(size);
    // Few distinct keys, so that operations collide.
    let key = |input: &mut Input<'_>| vec![input.byte() % 8; input.choose(3)];
    for _ in 0..input.choose(32) {
        match input.choose(3) {
            0 => {
                let k = key(input);
                let v = input.short_field().to_vec();
                assert!(cache.put(k.clone(), v.clone()));
                model.insert(k, v);
            }
            1 => {
                let k = key(input);
                assert_eq!(cache.get(&k), model.map.get(&k).cloned());
            }
            _ => {
                let k = key(input);
                assert_eq!(cache.take(&k), model.remove(&k));
            }
        }
    }
    let none = browntls_core::server::NoServerSessionStorage {};
    assert!(!none.can_cache());
    assert!(none.session_version(&[1]).is_none());
    assert!(!none.put(vec![1], vec![2]) || none.get(&[1]).is_none());
}

/// `ClientSessionMemoryCache` key exchange hints against the model; the
/// session lookups of servers never stored.
pub(super) fn client_cache_op(input: &mut Input<'_>) {
    let size = input.choose(40);
    let cache = ClientSessionMemoryCache::new(size);
    let mut model = CacheModel::new(size.div_ceil(8));
    let mut hints: HashMap<ServerName<'static>, NamedGroup> = HashMap::new();
    for _ in 0..input.choose(24) {
        let Some(name) = server_name(input).map(|n| n.to_owned()) else {
            continue;
        };
        match input.choose(4) {
            0 => {
                let group = NamedGroup::from(input.u16());
                cache.set_kx_hint(name.clone(), group);
                model.insert(name.clone(), Vec::new());
                hints.insert(name, group);
            }
            1 => {
                let expected = model.map.contains_key(&name).then(|| hints[&name]);
                assert_eq!(cache.kx_hint(&name), expected);
            }
            2 => {
                assert!(cache.tls12_session(&name).is_none());
                cache.remove_tls12_session(&name);
            }
            _ => assert!(cache.take_tls13_ticket(&name).is_none()),
        }
    }
}

// --------------------------------------------------------- SNI resolution

/// `ResolvesServerCertUsingSni::add`: a name is accepted exactly when it is
/// a DNS name the certificate is valid for.
pub(super) fn sni_op(input: &mut Input<'_>) {
    let fx = fixtures::get();
    let mut resolver = ResolvesServerCertUsingSni::new();
    for _ in 0..input.choose(4) {
        let k = input.choose(fx.keys.len());
        let p = input.choose(2);
        let Some(key) = load(p, k) else {
            assert!(!loadable(p, k));
            continue;
        };
        let ck = CertifiedKey::new(fx.keys[k].chain.clone(), key);
        let raw = if input.bool() {
            input.short_field()
        } else {
            const NAMES: [&[u8]; 4] = [
                b"localhost",
                b"x.wild.example",
                b"127.0.0.1",
                b"nope.example",
            ];
            input.pick(&NAMES)
        };
        let Ok(name) = core::str::from_utf8(raw) else {
            continue;
        };
        let parsed = ServerName::try_from(name);
        let has_cert = !fx.keys[k].chain.is_empty();
        match resolver.add(name, ck) {
            Ok(()) => {
                assert!(has_cert);
                let parsed = parsed.expect("accepted names parse");
                assert!(matches!(parsed, ServerName::DnsName(_)));
                assert_ne!(name_verdict(&parsed), Some(false), "{name:?}");
            }
            Err(e) => {
                if has_cert && let Ok(parsed @ ServerName::DnsName(_)) = &parsed {
                    assert_ne!(name_verdict(parsed), Some(true), "{name:?}: {e:?}");
                }
            }
        }
    }
}

// ---------------------------------------------------- compression, logging

/// Every default compressor against every default decompressor of the
/// same algorithm.
pub(super) fn compress_op(input: &mut Input<'_>) {
    let compressors = compress::default_cert_compressors();
    let decompressors = compress::default_cert_decompressors();
    let data = input.field();
    let level = if input.bool() {
        CompressionLevel::Interactive
    } else {
        CompressionLevel::Amortized
    };
    // The thorough levels are slow; keep their inputs small.
    let cap = if level == CompressionLevel::Interactive {
        2048
    } else {
        512
    };
    let data = &data[..data.len().min(cap)];
    let compressor = *input.pick(compressors);
    // Compression that does not shrink the input is refused; a long run of
    // one byte always shrinks.
    let compressed = match compressor.compress(data.to_vec(), level) {
        Ok(c) => {
            assert!(c.len() < data.len(), "{:?} grew", compressor.algorithm());
            c
        }
        Err(_) => {
            let run = data.len() >= 64 && data.iter().all(|b| *b == data[0]);
            assert!(!run, "{:?} refused a run", compressor.algorithm());
            Vec::new()
        }
    };
    for decompressor in decompressors {
        if compressed.is_empty() {
            break;
        }
        if decompressor.algorithm() != compressor.algorithm() {
            continue;
        }
        let mut out = vec![0u8; data.len()];
        decompressor
            .decompress(&compressed, &mut out)
            .expect("round trip");
        assert_eq!(out, data);
        // A wrong declared length is refused.
        let mut short = vec![0u8; data.len() + 1];
        assert!(decompressor.decompress(&compressed, &mut short).is_err());
        if let Some(len) = data.len().checked_sub(1) {
            let mut shorter = vec![0u8; len];
            assert!(decompressor.decompress(&compressed, &mut shorter).is_err());
        }
    }
    // Fuzzed input with a fuzzed declared length.
    let decompressor = *input.pick(decompressors);
    let mut out = vec![0u8; usize::from(input.u16()) % 4096];
    let size = usize::from(input.u16()) + 1;
    let limits = compress::ZstdDecompressionLimits::new(8 << 20, size).expect("positive limits");
    let _ = decompressor.decompress_with_zstd_limits(input.field(), &mut out, limits);
}

/// The key log file (without `SSLKEYLOGFILE` it logs nothing) and enum
/// helpers.
pub(super) fn keylog_enum_op(input: &mut Input<'_>) {
    let log = KeyLogFile::new();
    assert!(KeyLogFile::try_from_path("").is_err());
    let label = core::str::from_utf8(input.short_field()).unwrap_or("CLIENT_RANDOM");
    let _ = log.will_log(label);
    log.log(label, input.short_field(), input.short_field());

    let suite = CipherSuite::from(input.u16());
    let non_preferred = suite.is_non_preferred();
    for p in 0..2 {
        for s in super::crypto::suites(p) {
            if s.suite() == suite {
                // Exactly the CBC and CCM suites are deprioritised.
                let ccm = format!("{suite:?}").contains("CCM");
                assert_eq!(non_preferred, s.is_tls12_block_cipher() || ccm, "{suite:?}");
            }
        }
    }
}
