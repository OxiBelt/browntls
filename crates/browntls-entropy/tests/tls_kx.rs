//! TLS key exchange through the native provider's `SupportedKxGroup`s.
//!
//! For every group a client starts an exchange, a server completes it
//! against the client's share, and the client completes it against the
//! server's reply. Examined: the random-derived parts of both key shares and
//! the agreed shared secret, which keys the TLS 1.3 handshake. ML-KEM
//! encapsulation keys and ciphertexts encode coefficients modulo 3329,
//! which are not uniform bytes; of those only `rho` is examined. FFDHE4096
//! and larger groups are left out for cost; their exponents come from the
//! same code as FFDHE2048 and FFDHE3072.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls::crypto::SupportedKxGroup;
use browntls::crypto::native::kx_group;
use browntls_entropy::{Stream, check, err, sample_count};

/// One component of a share or secret.
#[derive(Clone, Copy)]
enum Part {
    /// An X25519 u-coordinate (little-endian, top bit always 0).
    X25519,
    /// An X448 u-coordinate.
    X448,
    /// A NIST point `0x04 || x || y` with `top` free bits in the first byte
    /// of each coordinate.
    Point(usize, u8),
    /// A NIST x-coordinate (the ECDH shared secret).
    Coord(usize, u8),
    /// An ML-KEM encapsulation key of this length; only `rho` is examined.
    MlKemEk(usize),
    /// An ML-KEM ciphertext of this length; not examined.
    MlKemCt(usize),
    /// An ML-KEM shared secret.
    MlKemSecret,
    /// An FFDHE group element of this length.
    Ffdhe(usize),
}

impl Part {
    fn wire_len(self) -> usize {
        match self {
            Part::X25519 | Part::MlKemSecret => 32,
            Part::X448 => 56,
            Part::Point(f, _) => 1 + 2 * f,
            Part::Coord(f, _) => f,
            Part::MlKemEk(l) | Part::MlKemCt(l) | Part::Ffdhe(l) => l,
        }
    }

    /// The examined bytes of `wire`, and per byte the free bits.
    fn examine(self, wire: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let all = |b: &[u8]| (b.to_vec(), vec![0xff; b.len()]);
        match self {
            Part::X25519 => {
                let (v, mut m) = all(wire);
                m[31] = 0x7f;
                (v, m)
            }
            Part::X448 | Part::MlKemSecret | Part::Ffdhe(_) => all(wire),
            Part::Point(f, top) => {
                let (v, mut m) = all(&wire[1..]);
                m[0] = top;
                m[f] = top;
                (v, m)
            }
            Part::Coord(_, top) => {
                let (v, mut m) = all(wire);
                m[0] = top;
                (v, m)
            }
            Part::MlKemEk(l) => all(&wire[l - 32..]),
            Part::MlKemCt(_) => (Vec::new(), Vec::new()),
        }
    }
}

/// The examined bytes of a value made of `parts`.
fn examine(parts: &[Part], wire: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let total: usize = parts.iter().map(|p| p.wire_len()).sum();
    if wire.len() != total {
        return Err(format!("{} bytes where {total} were expected", wire.len()));
    }
    let mut rest = wire;
    let (mut bytes, mut mask) = (Vec::new(), Vec::new());
    for p in parts {
        let (head, tail) = rest.split_at(p.wire_len());
        let (b, m) = p.examine(head);
        bytes.extend(b);
        mask.extend(m);
        rest = tail;
    }
    Ok((bytes, mask))
}

fn stream(name: String, parts: &[Part]) -> Option<Stream> {
    let len: usize = parts.iter().map(|p| p.wire_len()).sum();
    let (_, mask) = examine(parts, &vec![0u8; len]).ok()?;
    if mask.is_empty() {
        return None;
    }
    let mut s = Stream::new(name, mask.len());
    for (i, m) in mask.into_iter().enumerate() {
        s = s.only(i, m);
    }
    Some(s)
}

fn kx(
    title: &str,
    group: &'static dyn SupportedKxGroup,
    client: &[Part],
    server: &[Part],
    secret: &[Part],
    divisor: usize,
) {
    let named: Vec<(&[Part], Option<Stream>)> = vec![
        (client, stream(format!("{title} client share"), client)),
        (server, stream(format!("{title} server share"), server)),
        (secret, stream(format!("{title} shared secret"), secret)),
    ];
    let streams: Vec<Stream> = named.iter().filter_map(|(_, s)| s.clone()).collect();
    check(title, sample_count(divisor, 1 << 10), &streams, |out| {
        let c = group.start().map_err(err)?;
        let client_share = c.pub_key().to_vec();
        let done = group.start_and_complete(&client_share).map_err(err)?;
        let client_secret = c.complete(&done.pub_key).map_err(err)?;
        if client_secret.secret_bytes() != done.secret.secret_bytes() {
            return Err("client and server secrets differ".into());
        }
        let values = [
            &client_share[..],
            &done.pub_key[..],
            done.secret.secret_bytes(),
        ];
        let mut k = 0;
        for ((parts, s), value) in named.iter().zip(values) {
            if s.is_some() {
                let (bytes, _) = examine(parts, value)?;
                out[k].copy_from_slice(&bytes);
                k += 1;
            }
        }
        Ok(())
    });
}

const P256: Part = Part::Point(32, 0xff);
const P384: Part = Part::Point(48, 0xff);
const P521: Part = Part::Point(66, 0x01);

#[test]
fn x25519() {
    use Part::X25519 as X;
    kx("X25519", kx_group::X25519, &[X], &[X], &[X], 1);
}

#[test]
fn x448() {
    use Part::X448 as X;
    kx("X448", kx_group::X448, &[X], &[X], &[X], 4);
}

#[test]
fn secp256r1() {
    kx(
        "secp256r1",
        kx_group::SECP256R1,
        &[P256],
        &[P256],
        &[Part::Coord(32, 0xff)],
        4,
    );
}

#[test]
fn secp384r1() {
    kx(
        "secp384r1",
        kx_group::SECP384R1,
        &[P384],
        &[P384],
        &[Part::Coord(48, 0xff)],
        4,
    );
}

#[test]
fn secp521r1() {
    kx(
        "secp521r1",
        kx_group::SECP521R1,
        &[P521],
        &[P521],
        &[Part::Coord(66, 0x01)],
        16,
    );
}

#[test]
fn mlkem768() {
    kx(
        "MLKEM768",
        kx_group::MLKEM768,
        &[Part::MlKemEk(1184)],
        &[Part::MlKemCt(1088)],
        &[Part::MlKemSecret],
        1,
    );
}

#[test]
fn mlkem1024() {
    kx(
        "MLKEM1024",
        kx_group::MLKEM1024,
        &[Part::MlKemEk(1568)],
        &[Part::MlKemCt(1568)],
        &[Part::MlKemSecret],
        1,
    );
}

#[test]
fn x25519mlkem768() {
    kx(
        "X25519MLKEM768",
        kx_group::X25519MLKEM768,
        &[Part::MlKemEk(1184), Part::X25519],
        &[Part::MlKemCt(1088), Part::X25519],
        &[Part::MlKemSecret, Part::X25519],
        1,
    );
}

#[test]
fn secp256r1mlkem768() {
    kx(
        "SecP256r1MLKEM768",
        kx_group::SECP256R1MLKEM768,
        &[P256, Part::MlKemEk(1184)],
        &[P256, Part::MlKemCt(1088)],
        &[Part::Coord(32, 0xff), Part::MlKemSecret],
        4,
    );
}

#[test]
fn secp384r1mlkem1024() {
    kx(
        "SecP384r1MLKEM1024",
        kx_group::SECP384R1MLKEM1024,
        &[P384, Part::MlKemEk(1568)],
        &[P384, Part::MlKemCt(1568)],
        &[Part::Coord(48, 0xff), Part::MlKemSecret],
        4,
    );
}

#[test]
fn ffdhe2048() {
    let f = Part::Ffdhe(256);
    kx("FFDHE2048", kx_group::FFDHE2048, &[f], &[f], &[f], 32);
}

#[test]
fn ffdhe3072() {
    let f = Part::Ffdhe(384);
    kx("FFDHE3072", kx_group::FFDHE3072, &[f], &[f], &[f], 128);
}
