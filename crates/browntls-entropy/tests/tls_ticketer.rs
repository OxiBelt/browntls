//! Session ticket encryption keys and nonces (`AeadTicketProducer` of the
//! native and RustCrypto providers).
//!
//! Tickets are `nonce (12) || ciphertext || tag (16)` under AES-256-GCM with
//! a random key per producer and a random nonce per ticket. A repeated nonce
//! under one key breaks GCM, so the nonces of one long-lived producer are
//! checked for duplicates and bias. A fresh producer per sample sealing an
//! all-zero block yields keystream and tag that are uniform only if its key
//! is; each such key must also fail to open the previous sample's ticket.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Mutex;

use browntls_core::crypto::TicketProducer;
use browntls_core::crypto::native::ticketer::AeadTicketProducer as NativeProducer;
use browntls_core::crypto::rustcrypto::ticketer::AeadTicketProducer as RustCryptoProducer;
use browntls_entropy::{Stream, check, err, sample_count};

const NONCE_LEN: usize = 12;
const BLOCK: [u8; 16] = [0u8; 16];

fn ticketer<P: TicketProducer + 'static>(title: &str, new: fn() -> Result<P, String>) {
    let long_lived = new().unwrap();
    // Per worker thread: the previous fresh producer and its ticket.
    let previous: Mutex<Vec<(std::thread::ThreadId, P, Vec<u8>)>> = Mutex::new(Vec::new());
    check(
        title,
        sample_count(1, 1 << 12),
        &[
            Stream::new(format!("{title}: nonces under one key"), NONCE_LEN),
            Stream::new(
                format!("{title}: fresh key, nonce || sealed zero block || tag"),
                NONCE_LEN + 32,
            ),
        ],
        |out| {
            let ticket = long_lived.encrypt(&BLOCK).ok_or("encrypt failed")?;
            out[0].copy_from_slice(&ticket[..NONCE_LEN]);

            let fresh = new()?;
            let ticket = fresh.encrypt(&BLOCK).ok_or("encrypt failed")?;
            out[1].copy_from_slice(&ticket);
            if fresh.decrypt(&ticket).as_deref() != Some(&BLOCK[..]) {
                return Err("a producer cannot open its own ticket".into());
            }
            let me = std::thread::current().id();
            let mut prev = previous.lock().map_err(err)?;
            if let Some(slot) = prev.iter_mut().find(|(id, _, _)| *id == me) {
                if fresh.decrypt(&slot.2).is_some() || slot.1.decrypt(&ticket).is_some() {
                    return Err("two fresh producers share a key".into());
                }
                *slot = (me, fresh, ticket);
            } else {
                prev.push((me, fresh, ticket));
            }
            Ok(())
        },
    );
}

#[test]
fn native_ticketer() {
    ticketer("native ticketer", || NativeProducer::new().map_err(err));
}

#[test]
fn rustcrypto_ticketer() {
    ticketer("RustCrypto ticketer", || {
        RustCryptoProducer::new().map_err(err)
    });
}
