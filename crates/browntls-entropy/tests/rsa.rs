//! RSA key generation (`browntls-crypto`).
//!
//! Each sample is the pair of primes `p || q` of one 2048-bit key, read back
//! from its PKCS #1 encoding. Generation forces the two top bits and the low
//! bit of each prime, so those are excluded. Besides the generic checks, no
//! prime may occur twice anywhere in the run: a shared prime between two
//! moduli factors both (the failure mode of entropy-starved RSA key
//! generation found in deployed devices).
//!
//! Key generation costs tens of milliseconds, so this topic draws far fewer
//! samples than the others.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::rand::OsRng;
use browntls_crypto::rsa::{MAX_PKCS1_PRIVATE_KEY_DER_LEN, RsaPrivateKey};
use browntls_entropy::{Stream, collect, err, judge, sample_count};

const BITS: usize = 2048;
const PRIME_LEN: usize = BITS / 16;

/// Reads one DER TLV; returns `(tag, contents, rest)`.
fn tlv(der: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
    let (&tag, rest) = der.split_first().ok_or("truncated DER")?;
    let (&first, mut rest) = rest.split_first().ok_or("truncated DER")?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 2 || rest.len() < count {
            return Err("unsupported DER length".into());
        }
        let (bytes, tail) = rest.split_at(count);
        rest = tail;
        bytes.iter().fold(0, |acc, &b| acc << 8 | usize::from(b))
    };
    if rest.len() < len {
        return Err("truncated DER".into());
    }
    let (contents, rest) = rest.split_at(len);
    Ok((tag, contents, rest))
}

/// The primes `p` and `q` of a PKCS #1 `RSAPrivateKey`, without sign bytes.
fn primes(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (tag, mut body, _) = tlv(der)?;
    if tag != 0x30 {
        return Err("not a SEQUENCE".into());
    }
    let mut ints = Vec::new();
    for _ in 0..6 {
        let (tag, value, rest) = tlv(body)?;
        if tag != 0x02 {
            return Err("not an INTEGER".into());
        }
        let value = value.strip_prefix(&[0]).unwrap_or(value);
        ints.push(value.to_vec());
        body = rest;
    }
    // version, n, e, d, p, q
    Ok((ints[4].clone(), ints[5].clone()))
}

#[test]
fn rsa2048_primes() {
    let title = "RSA-2048 key generation";
    let stream = Stream::new("RSA-2048 primes p || q", 2 * PRIME_LEN)
        .fixed(0, 0xc0)
        .fixed(PRIME_LEN - 1, 0x01)
        .fixed(PRIME_LEN, 0xc0)
        .fixed(2 * PRIME_LEN - 1, 0x01);
    let samples = collect(sample_count(512, 16), &[stream], |out| {
        let key = RsaPrivateKey::generate(BITS, &OsRng).map_err(err)?;
        let mut der = vec![0u8; MAX_PKCS1_PRIVATE_KEY_DER_LEN];
        let len = key.to_pkcs1_der(&mut der).map_err(err)?;
        let (p, q) = primes(&der[..len])?;
        if p.len() != PRIME_LEN || q.len() != PRIME_LEN {
            return Err(format!("prime lengths {} and {}", p.len(), q.len()));
        }
        out[0][..PRIME_LEN].copy_from_slice(&p);
        out[0][PRIME_LEN..].copy_from_slice(&q);
        Ok(())
    })
    .unwrap_or_else(|e| panic!("{e}"));

    let s = &samples[0];
    let mut all: Vec<&[u8]> = (0..s.count())
        .flat_map(|i| {
            let (p, q) = s.sample(i).split_at(PRIME_LEN);
            [p, q]
        })
        .collect();
    all.sort_unstable();
    let shared = all.windows(2).filter(|w| w[0] == w[1]).count();
    println!(
        "== {title}: {} primes from {} keys, {shared} repeated",
        all.len(),
        s.count()
    );
    assert_eq!(shared, 0, "{shared} primes occur in more than one place");

    judge(title, &samples).unwrap_or_else(|e| panic!("{e}"));
}
