//! Starting inputs of the `tls_auth` target.

use browntls_core::delegated_credential::{Credential, DelegatedCredential};
use browntls_core::{Side, SignatureScheme};

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

/// A client-authentication operation: mode flags, the client's clock
/// twelve days into the certificate, the expiry selector (two days ahead
/// for 6), the server's skew (2: 128 seconds behind), credential key,
/// variant (a flipped signature bit for 2) and scheme mask, if any.
fn client_auth_seed(
    mode: u8,
    delta: u8,
    skew: u8,
    key: u8,
    variant: u8,
    mask: Option<u8>,
) -> Vec<u8> {
    let mut seed = vec![8, mode, 0, 0x10, 0, 0, skew];
    if skew == 2 {
        seed.push(0);
    }
    seed.push(delta);
    if delta >= 6 {
        seed.extend_from_slice(&[0, 3, 0xf4, 0x80]);
    }
    seed.extend_from_slice(&[key, variant]);
    if variant == 2 {
        seed.extend_from_slice(&[0, 3, 1]);
    }
    match mask {
        Some(mask) => seed.extend_from_slice(&[0, mask]),
        None => seed.push(1),
    }
    seed
}

/// A validation operation; the default is a sound client credential of
/// the client certificate, presented by the client two days before it
/// expires, with every scheme offered.
#[derive(Clone, Copy)]
struct ValidateSeed {
    client_cert: bool,
    /// Issuing side selector: 0 the client, otherwise the server.
    side: u8,
    /// Presented certificate: 0 plain, 1 garbage, 2 the other delegation
    /// certificate, 3 the issuer.
    cert: u8,
    /// 0: presented by the other side.
    side_sel: u8,
    /// Seconds after the certificate's start.
    now: u32,
    /// Expiry selector; 5 is relative to the certificate's end, by
    /// `at_end` - 128 seconds.
    delta: u8,
    at_end: u8,
    key: u8,
    /// 0 to 3 tamper; 5 does not.
    tamper: u8,
    dc_mask: u8,
    sig_mask: u8,
    /// 0: a P-384 CertificateVerify.
    cv_sel: u8,
}

impl Default for ValidateSeed {
    fn default() -> Self {
        Self {
            client_cert: true,
            side: 0,
            cert: 3,
            side_sel: 1,
            now: 0x0010_0000,
            delta: 6,
            at_end: 128,
            key: 0,
            tamper: 5,
            dc_mask: 0xff,
            sig_mask: 0xff,
            cv_sel: 1,
        }
    }
}

impl ValidateSeed {
    fn encode(self) -> Vec<u8> {
        let mut seed = vec![9, u8::from(self.client_cert), self.side, self.cert];
        if self.cert == 1 {
            put_short_field(&mut seed, b"\x30\x03\x02\x01\x00");
        }
        seed.push(self.side_sel);
        seed.extend_from_slice(&self.now.to_be_bytes());
        seed.push(self.delta);
        match self.delta {
            5 => seed.push(self.at_end),
            6.. => seed.extend_from_slice(&[0, 3, 0xf4, 0x80]),
            _ => {}
        }
        seed.extend_from_slice(&[self.key, self.tamper]);
        match self.tamper {
            0 => seed.extend_from_slice(&[0, 3, 1]),
            1 => seed.push(3),
            // P-384
            2 | 3 => seed.extend_from_slice(&[1, 2]),
            _ => {}
        }
        seed.extend_from_slice(&[self.dc_mask, self.sig_mask, self.cv_sel]);
        if self.cv_sel == 0 {
            seed.extend_from_slice(&[1, 2]);
        }
        seed
    }
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

    // 7: client certificate URLs
    seeds.extend(super::certificate_url::seeds(7));

    // 8: client authentication with a credential: each connection kind
    // (buffered or unbuffered ends, after the handshake, resumed, a server
    // that does not ask), each variant, the boundaries, a skewed server
    // and restricted schemes
    for mode in [0u8, 1, 2, 3, 4, 8, 10, 16, 19] {
        seeds.push(client_auth_seed(mode, 6, 0, 0, 5, None));
    }
    for (variant, key) in [(0u8, 0u8), (1, 0), (2, 1), (3, 0), (4, 1), (5, 1)] {
        seeds.push(client_auth_seed(0, 6, 0, key, variant, None));
    }
    seeds.push(client_auth_seed(10, 6, 0, 0, 2, None));
    seeds.push(client_auth_seed(2, 6, 0, 1, 4, None));
    for delta in 0..6u8 {
        seeds.push(client_auth_seed(0, delta, 0, 0, 5, None));
    }
    seeds.push(client_auth_seed(0, 6, 2, 0, 5, None));
    seeds.push(client_auth_seed(0, 2, 2, 0, 5, None));
    // P-256 only, Ed25519 only, P-256 with Ed25519 and RSA-PSS
    for (mask, key) in [(0x01u8, 1u8), (0x01, 0), (0x02, 1), (0x0b, 1)] {
        seeds.push(client_auth_seed(0, 6, 0, key, 5, Some(mask)));
    }

    // 9: validation: sound credentials of both certificates and keys, then
    // each refusal (tampering, the other side, other certificates,
    // unoffered schemes, another CertificateVerify scheme, the time
    // boundaries and the certificate's end)
    let sound = ValidateSeed::default();
    seeds.push(sound.encode());
    seeds.push(ValidateSeed { key: 1, ..sound }.encode());
    seeds.push(
        ValidateSeed {
            client_cert: false,
            side: 1,
            ..sound
        }
        .encode(),
    );
    for tamper in 0..4 {
        seeds.push(ValidateSeed { tamper, ..sound }.encode());
    }
    seeds.push(
        ValidateSeed {
            side_sel: 0,
            ..sound
        }
        .encode(),
    );
    for cert in 0..3 {
        seeds.push(ValidateSeed { cert, ..sound }.encode());
    }
    seeds.push(
        ValidateSeed {
            key: 1,
            dc_mask: 0x01,
            ..sound
        }
        .encode(),
    );
    seeds.push(
        ValidateSeed {
            sig_mask: 0x02,
            ..sound
        }
        .encode(),
    );
    seeds.push(ValidateSeed { cv_sel: 0, ..sound }.encode());
    for delta in 0..5 {
        seeds.push(ValidateSeed { delta, ..sound }.encode());
    }
    // three days before the certificate ends, a credential ending with it
    // and one a second later
    for at_end in [128u8, 129] {
        seeds.push(
            ValidateSeed {
                now: 0x01dd_3f00,
                delta: 5,
                at_end,
                ..sound
            }
            .encode(),
        );
    }
    seeds
}
