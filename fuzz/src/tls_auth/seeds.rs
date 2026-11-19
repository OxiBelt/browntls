//! Starting inputs of the `tls_auth` target.

use browntls::delegated_credential::{Credential, DelegatedCredential};
use browntls::{Side, SignatureScheme};

use super::fixture;
use crate::input::{put_field, put_short_field};

// ------------------------------------------------------------------- seeds

/// An issue operation: side selector, certificate selector (and garbage),
/// whether the certificate schemes include P-256, credential key, scheme
/// selector bytes, key selector bytes, tampering (with its arguments).
fn issue_seed(
    side: u8,
    cert: &[u8],
    p256: bool,
    key: u8,
    scheme: &[u8],
    spki: &[u8],
    tamper: u8,
) -> Vec<u8> {
    let mut seed = vec![2, side];
    seed.extend_from_slice(cert);
    seed.extend_from_slice(&[u8::from(p256), u8::from(!p256)]);
    if !p256 {
        // one scheme the certificate key lacks: P-384
        seed.extend_from_slice(&[1, 2]);
    }
    // valid for an hour
    seed.extend_from_slice(&[2, 0, 0, 0x0e, 0x10, key]);
    seed.extend_from_slice(scheme);
    seed.extend_from_slice(spki);
    seed.push(tamper);
    match tamper {
        0 => seed.extend_from_slice(&[0, 3, 5]),
        1 => seed.push(5),
        _ => {}
    }
    seed
}

/// Starting inputs for `tls_auth`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    crate::init();
    let fixture = fixture();
    let mut seeds = Vec::new();

    // 0: decode a valid credential, then malformed ones
    let dc = DelegatedCredential::issue(
        Side::Server,
        &fixture.delegation,
        &*fixture.delegation_key,
        &[SignatureScheme::ECDSA_NISTP256_SHA256],
        Credential {
            valid_time: 3600,
            dc_cert_verify_algorithm: SignatureScheme::ED25519,
            public_key: fixture.dc_keys[1].spki.clone(),
        },
    )
    .expect("issue")
    .to_bytes();
    let mut seed = vec![0];
    put_field(&mut seed, &dc);
    seed.push(0);
    put_field(&mut seed, &dc[..dc.len() - 1]);
    seed.push(0);
    put_field(&mut seed, &[1, 2, 3, 4, 4, 3, 0, 0, 0, 8, 7, 0, 1, 1]);
    seed.push(0);
    put_field(&mut seed, &[1, 2, 3, 4, 4, 3, 0, 0x40, 1]);
    seeds.push(seed);

    // 1: encode, decodable and not
    for (spki_sel, sig) in [(1u8, &b"sig"[..]), (0, b"sig"), (1, b"")] {
        let mut seed = vec![1, 0, 0, 0x0e, 0x10, 1, 1, spki_sel];
        put_short_field(&mut seed, b"\x30\x01\x00");
        if spki_sel == 0 {
            seed.push(1);
        }
        seed.extend_from_slice(&[1, 0]);
        put_field(&mut seed, sig);
        seeds.push(seed);
    }

    // 2: issue for each credential key, then each tampering; then the
    // refusals (client side, plain and garbage certificates, no usable
    // scheme, a forbidden credential scheme, fuzzed and oversized keys)
    for tamper in 0..5u8 {
        for key in 0..2u8 {
            seeds.push(issue_seed(1, &[2], true, key, &[1], &[2], tamper));
        }
    }
    seeds.push(issue_seed(0, &[2], true, 0, &[1], &[2], 4));
    seeds.push(issue_seed(1, &[0], true, 0, &[1], &[2], 4));
    seeds.push(issue_seed(1, &[1, 3, 0x30, 0, 0], true, 0, &[1], &[2], 4));
    seeds.push(issue_seed(1, &[2], false, 0, &[1], &[2], 4));
    seeds.push(issue_seed(1, &[2], true, 0, &[0, 1, 5], &[2], 4));
    seeds.push(issue_seed(1, &[2], true, 0, &[0, 1, 1], &[2], 4));
    seeds.push(issue_seed(1, &[2], true, 0, &[1], &[0, 3, 0x30, 1, 0], 4));
    seeds.push(issue_seed(1, &[2], true, 0, &[1], &[1, 1], 4));

    // 3: generate every native scheme, then an unsupported one
    for scheme in 0..6u8 {
        seeds.push(vec![3, 1, 2, 1, 0, 1, scheme, 2, 0, 0, 0x0e, 0x10]);
    }

    // 4: validity at the start, past 32 bits, of a plain certificate and
    // of garbage
    seeds.push(vec![4, 2, 0, 200, 0, 0, 0, 10]);
    seeds.push(vec![4, 2, 1, 200, 0, 0, 0, 10]);
    seeds.push(vec![4, 0, 2, 0, 0, 0x69, 0x55, 0, 0, 0, 0, 0, 0, 0, 1]);
    seeds.push(vec![4, 1, 1, 0x30, 2, 0, 0, 0, 0, 0]);

    // 5: handshakes: inside the window (two keys), at each boundary, with a
    // skewed server, and each tampering
    for (delta, key, skew, tamper) in [
        (6u8, 0u8, 0u8, 5u8),
        (6, 1, 0, 5),
        (0, 0, 0, 5),
        (1, 0, 0, 5),
        (2, 0, 0, 5),
        (3, 0, 0, 5),
        (4, 0, 0, 5),
        (5, 0, 0, 5),
        (6, 0, 2, 5),
        (6, 0, 0, 0),
        (6, 0, 0, 1),
        (6, 0, 0, 2),
    ] {
        let mut seed = vec![5, 0, 0x10, 0, 0, skew];
        if skew == 2 {
            seed.push(0);
        }
        seed.push(delta);
        if delta >= 6 {
            // two days
            seed.extend_from_slice(&[0, 3, 0xf4, 0x80]);
        }
        seed.extend_from_slice(&[key, tamper]);
        if tamper == 0 {
            seed.extend_from_slice(&[0, 3, 1]);
        }
        seeds.push(seed);
    }
    // the server's skew puts the credential past the client's window, or
    // after its expiry
    seeds.push(vec![5, 0, 0x10, 0, 0, 3, 0, 1, 0x51, 0x80, 4, 0, 5]);
    seeds.push(vec![5, 0, 0x10, 0, 0, 2, 0, 2, 0, 5]);

    // 6: exported authenticators over TLS 1.3 and TLS 1.2 (mode bit 0),
    // with a buffered or unbuffered client (bit 1) and server (bit 2): each
    // exchange with each identity, tampered and not
    for mode in 0..8u8 {
        let mut seed = Vec::new();
        for (exchange, identity) in [
            (0u8, 0u8),
            (0, 1),
            (0, 3),
            (1, 2),
            (1, 0),
            (1, 3),
            (2, 0),
            (2, 1),
            (2, 2),
            (2, 3),
        ] {
            seed.push(6);
            if seed.len() == 1 {
                seed.push(mode);
            }
            seed.push(exchange);
            if exchange < 2 {
                put_short_field(&mut seed, &[b'c', exchange, identity]);
                // default schemes, no authorities
                seed.extend_from_slice(&[0, 0]);
            }
            seed.extend_from_slice(&[identity, 1, 0, 0x20, 3]);
        }
        seeds.push(seed);
    }
    let mut seed = vec![6, 0, 0];
    put_short_field(&mut seed, b"ctx");
    // P-384 only (nothing to sign with), two authorities
    seed.extend_from_slice(&[1, 1, 1, 2, 0, 1, 2]);
    put_short_field(&mut seed, b"\x31\x00");
    put_short_field(&mut seed, b"");
    seed.extend_from_slice(&[0, 0]);
    // the same context again, then an empty one
    seed.extend_from_slice(&[6, 0]);
    put_short_field(&mut seed, b"ctx");
    seed.extend_from_slice(&[0, 0, 0, 0]);
    seed.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0]);
    // fuzzed authenticator and request, then a fuzzed request answered
    seed.extend_from_slice(&[6, 3]);
    put_field(&mut seed, &[11, 0, 0, 1, 0]);
    put_field(&mut seed, &[17, 0, 0, 0]);
    seed.extend_from_slice(&[6, 4]);
    put_field(
        &mut seed,
        &[17, 0, 0, 9, 3, b'a', b'b', b'c', 0, 4, 0, 13, 0, 0],
    );
    seed.push(0);
    // the same between two unbuffered ends
    let mut unbuffered = seed.clone();
    unbuffered[1] = 6;
    seeds.push(seed);
    seeds.push(unbuffered);
    seeds
}
