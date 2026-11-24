//! The RFC 9881 encodings: PKCS #8 `OneAsymmetricKey` (§6) and
//! `SubjectPublicKeyInfo` (§4), against the harness's own DER.

use browntls_crypto::Error;
use browntls_crypto::mldsa::{
    MlDsa44, MlDsa65, MlDsa87, PrivateKeyFormat, SEED_LEN, SigningKey, VerifyingKey,
};

use super::{FIXTURES, Kind, Set, flip, mutate};
use crate::input::Input;

const FORMATS: [PrivateKeyFormat; 3] = [
    PrivateKeyFormat::Seed,
    PrivateKeyFormat::Expanded,
    PrivateKeyFormat::Both,
];

/// The K range of an expanded key (see `keys`).
const K: core::ops::Range<usize> = 32..64;

// ---------------------------------------------------------------------------
// The harness's DER
// ---------------------------------------------------------------------------

/// A DER TLV with a minimal definite length.
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let len = contents.len();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(contents);
    out
}

/// `AlgorithmIdentifier { oid }` with absent parameters.
fn algorithm(oid: &[u8]) -> Vec<u8> {
    tlv(0x30, &tlv(0x06, oid))
}

/// The `ML-DSA-*-PrivateKey` CHOICE in `format`.
fn choice(format: PrivateKeyFormat, seed: &[u8], expanded: &[u8]) -> Vec<u8> {
    match format {
        PrivateKeyFormat::Seed => tlv(0x80, seed),
        PrivateKeyFormat::Expanded => tlv(0x04, expanded),
        PrivateKeyFormat::Both => tlv(0x30, &[tlv(0x04, seed), tlv(0x04, expanded)].concat()),
    }
}

/// A `OneAsymmetricKey` from its parts (`alg` and `extra` already encoded).
fn one_asymmetric_key(version: u8, alg: &[u8], private_key: &[u8], extra: &[u8]) -> Vec<u8> {
    let contents = [
        &tlv(0x02, &[version])[..],
        alg,
        &tlv(0x04, private_key),
        extra,
    ]
    .concat();
    tlv(0x30, &contents)
}

/// The `SubjectPublicKeyInfo` of a raw public key.
fn spki(oid: &[u8], pk: &[u8]) -> Vec<u8> {
    let bits = [&[0u8][..], pk].concat();
    tlv(0x30, &[algorithm(oid), tlv(0x03, &bits)].concat())
}

/// Splits one TLV off `data`, lengths of up to four octets, minimal or not.
fn read_tlv(data: &[u8]) -> Option<(u8, usize, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0, |acc, &b| acc << 8 | usize::from(b));
        (len, &rest[n..])
    };
    let header = data.len() - rest.len();
    (rest.len() >= len).then(|| (tag, header, &rest[..len], &rest[len..]))
}

/// For a `OneAsymmetricKey` that is exactly `version`, an algorithm and a
/// `privateKey` (no attributes, no `publicKey`), the CHOICE form of the
/// private key and the offset of the `version` contents octet.
fn plain_form(der: &[u8]) -> Option<(PrivateKeyFormat, usize)> {
    let (0x30, outer, contents, []) = read_tlv(der)? else {
        return None;
    };
    let (0x02, version_header, [_], rest) = read_tlv(contents)? else {
        return None;
    };
    let (0x30, _, _, rest) = read_tlv(rest)? else {
        return None;
    };
    let (0x04, _, private_key, []) = read_tlv(rest)? else {
        return None;
    };
    let format = match private_key.first()? {
        0x80 => PrivateKeyFormat::Seed,
        0x04 => PrivateKeyFormat::Expanded,
        0x30 => PrivateKeyFormat::Both,
        _ => return None,
    };
    Some((format, outer + version_header))
}

// ---------------------------------------------------------------------------
// Invariants of accepted keys
// ---------------------------------------------------------------------------

/// What every signing key must satisfy, however it was loaded:
///
/// - with a seed, the seed derives its expanded key; without, the expanded
///   key reloads to the same public key;
/// - its public key's SPKI is the harness's encoding and parses back;
/// - in each form it can write (`Expanded` always, `Seed` and `Both` only
///   with a seed, `Unsupported` otherwise), `to_pkcs8_der` writes exactly
///   the harness's `version` 0 encoding, which parses back to the same
///   expanded key, public key and seed (none for `Expanded`), and which
///   that key writes again identically; a buffer one byte short is an
///   `InvalidLength` error and stays untouched.
pub(super) fn check_signing_key<P: Set>(key: &SigningKey<P>) {
    let expanded = key.to_expanded_bytes();
    let expanded = expanded.as_ref();
    let vk = key.verifying_key();
    match key.seed() {
        Some(seed) => {
            let derived = SigningKey::<P>::from_seed(seed);
            assert_eq!(derived.to_expanded_bytes().as_ref(), expanded);
        }
        None => {
            let reloaded = SigningKey::<P>::from_expanded_bytes(expanded).expect("reloads");
            assert_eq!(reloaded.verifying_key(), vk);
        }
    }
    check_verifying_key(vk);

    let alg = algorithm(P::OID);
    for format in FORMATS {
        let mut out = vec![0u8; SigningKey::<P>::PKCS8_MAX_LEN];
        let result = key.to_pkcs8_der(format, &mut out);
        let seed = match (format, key.seed()) {
            (PrivateKeyFormat::Expanded, _) => &[][..],
            (_, Some(seed)) => &seed[..],
            (_, None) => {
                assert_eq!(result, Err(Error::Unsupported));
                assert!(out.iter().all(|&b| b == 0), "output left as it was");
                continue;
            }
        };
        let n = result.expect("an encodable form");
        let out = &out[..n];
        let ours = one_asymmetric_key(0, &alg, &choice(format, seed, expanded), &[]);
        assert_eq!(out, &ours[..], "{format:?}");
        let parsed = SigningKey::<P>::from_pkcs8_der(out).expect("its own encoding");
        assert_eq!(parsed.to_expanded_bytes().as_ref(), expanded);
        assert_eq!(parsed.verifying_key(), vk);
        let expected_seed = (format != PrivateKeyFormat::Expanded)
            .then_some(key.seed())
            .flatten();
        assert_eq!(parsed.seed(), expected_seed);
        let mut again = vec![0u8; n];
        assert_eq!(parsed.to_pkcs8_der(format, &mut again), Ok(n));
        assert_eq!(again, out);
        let mut short = vec![0xa5u8; n - 1];
        assert_eq!(
            key.to_pkcs8_der(format, &mut short),
            Err(Error::InvalidLength)
        );
        assert!(short.iter().all(|&b| b == 0xa5), "output left as it was");
    }
}

/// A public key's SPKI is the harness's encoding, `SPKI_LEN` long, and
/// parses back; a short buffer is refused and left untouched.
fn check_verifying_key<P: Set>(vk: &VerifyingKey<P>) {
    let mut out = vec![0u8; VerifyingKey::<P>::SPKI_LEN];
    assert_eq!(vk.to_spki_der(&mut out), Ok(VerifyingKey::<P>::SPKI_LEN));
    assert_eq!(out, spki(P::OID, vk.as_bytes()));
    assert_eq!(VerifyingKey::<P>::from_spki_der(&out).as_ref(), Ok(vk));
    let mut short = vec![0xa5u8; VerifyingKey::<P>::SPKI_LEN - 1];
    assert_eq!(vk.to_spki_der(&mut short), Err(Error::InvalidLength));
    assert!(short.iter().all(|&b| b == 0xa5), "output left as it was");
}

/// `from_pkcs8_der` with parameter set `P`: `None` if refused (with one of
/// the documented error kinds), else the key's public SPKI after checking
/// the invariants of accepted keys and, for an input without attributes
/// and `publicKey`, that the key re-encodes in its own form to the input
/// with `version` 0.
fn parse_pkcs8<P: Set>(der: &[u8]) -> Option<Vec<u8>> {
    let key = match SigningKey::<P>::from_pkcs8_der(der) {
        Ok(key) => key,
        Err(e) => {
            assert!(
                matches!(e, Error::InvalidEncoding | Error::InvalidKey),
                "{e:?}"
            );
            return None;
        }
    };
    check_signing_key(&key);
    if let Some((format, version_at)) = plain_form(der) {
        let mut expected = der.to_vec();
        expected[version_at] = 0;
        let mut out = vec![0u8; SigningKey::<P>::PKCS8_MAX_LEN];
        let n = key
            .to_pkcs8_der(format, &mut out)
            .expect("the input's own form");
        assert_eq!(&out[..n], &expected[..], "re-encoded in its own form");
    }
    Some(spki(P::OID, key.verifying_key().as_bytes()))
}

/// `from_spki_der` with parameter set `P`: whether it accepts, after
/// checking that an accepted input re-encodes to itself.
fn parse_spki<P: Set>(der: &[u8]) -> bool {
    match VerifyingKey::<P>::from_spki_der(der) {
        Ok(vk) => {
            check_verifying_key(&vk);
            assert_eq!(spki(P::OID, vk.as_bytes()), der, "re-encoded");
            assert_eq!(
                VerifyingKey::<P>::from_bytes(vk.as_bytes()).as_ref(),
                Ok(&vk)
            );
            true
        }
        Err(e) => {
            assert!(
                matches!(e, Error::InvalidEncoding | Error::InvalidKey),
                "{e:?}"
            );
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// A genuine encoding from a fuzzed seed: the private key in a fuzzed form
/// or the public key.
fn genuine<P: Set>(input: &mut Input<'_>, private: bool) -> Vec<u8> {
    let seed: [u8; SEED_LEN] = input.array();
    let key = SigningKey::<P>::from_seed(&seed);
    let format = FORMATS[input.choose(3)];
    let mut out = vec![0u8; SigningKey::<P>::PKCS8_MAX_LEN];
    let n = if private {
        key.to_pkcs8_der(format, &mut out)
    } else {
        key.verifying_key().to_spki_der(&mut out)
    };
    out.truncate(n.expect("encodable"));
    out
}

/// The DER an encoding operation works on: fuzzed (`0`), genuine (`1`) or
/// a fixture, then mutated. Returns the bytes and the fixture, if the
/// bytes are one unchanged.
fn source(input: &mut Input<'_>, private: bool) -> (Vec<u8>, Option<Kind>) {
    let which = input.choose(2 + FIXTURES.len());
    let (mut bytes, kind) = match which {
        0 => (input.field().to_vec(), None),
        1 => {
            let bytes = match input.choose(3) {
                0 => genuine::<MlDsa44>(input, private),
                1 => genuine::<MlDsa65>(input, private),
                _ => genuine::<MlDsa87>(input, private),
            };
            (bytes, None)
        }
        _ => {
            let (kind, der) = FIXTURES[which - 2];
            (der.to_vec(), Some(kind))
        }
    };
    let before = bytes.clone();
    mutate(input, &mut bytes);
    let kind = kind.filter(|_| bytes == before);
    (bytes, kind)
}

/// `from_pkcs8_der` under every parameter set.
pub(super) fn pkcs8_op(input: &mut Input<'_>) {
    let (der, fixture) = source(input, true);
    let parsed = [
        parse_pkcs8::<MlDsa44>(&der),
        parse_pkcs8::<MlDsa65>(&der),
        parse_pkcs8::<MlDsa87>(&der),
    ];
    let accepted: Vec<usize> = (0..3).filter(|&i| parsed[i].is_some()).collect();
    assert!(accepted.len() <= 1, "one OID, one parameter set");
    match fixture {
        // An Appendix C.1 key loads under its own set and has the
        // Appendix C.2 public key.
        Some(Kind::Private(set)) => {
            assert_eq!(accepted, [set]);
            let public = FIXTURES
                .iter()
                .find(|(kind, _)| *kind == Kind::Public(set))
                .map(|(_, der)| *der);
            assert_eq!(parsed[set].as_deref(), public);
        }
        // The Appendix C.4 keys are refused.
        Some(Kind::Inconsistent) => {
            assert!(accepted.is_empty());
            assert!(matches!(
                SigningKey::<MlDsa44>::from_pkcs8_der(&der),
                Err(Error::InvalidKey)
            ));
        }
        _ => {}
    }
}

/// `from_spki_der` under every parameter set.
pub(super) fn spki_op(input: &mut Input<'_>) {
    let (der, fixture) = source(input, false);
    let accepted: Vec<usize> = [
        parse_spki::<MlDsa44>(&der),
        parse_spki::<MlDsa65>(&der),
        parse_spki::<MlDsa87>(&der),
    ]
    .iter()
    .enumerate()
    .filter_map(|(i, &ok)| ok.then_some(i))
    .collect();
    assert!(accepted.len() <= 1, "one OID, one parameter set");
    if let Some(Kind::Public(set)) = fixture {
        assert_eq!(accepted, [set]);
    }
}

/// A `OneAsymmetricKey` built from fuzzed choices, accepted or refused as
/// the model predicts.
pub(super) fn build_op<P: Set>(input: &mut Input<'_>) {
    let seed: [u8; SEED_LEN] = input.array();
    let key = SigningKey::<P>::from_seed(&seed);
    let original = key.to_expanded_bytes().as_ref().to_vec();

    let version = u8::try_from(input.choose(3)).unwrap_or(0);
    let alg_mode = input.choose(3);
    let format = FORMATS[input.choose(3)];
    let short_seed = input.bool();
    let mut expanded = original.clone();
    flip(input, &mut expanded);
    let attr_mode = input.choose(3);
    let attribute_value = if attr_mode == 1 {
        input.short_field()
    } else {
        &[]
    };
    let pk_mode = input.choose(4);
    let mut pk = key.verifying_key().as_bytes().to_vec();
    let mut unused = 0;
    match pk_mode {
        2 => flip_one(input, &mut pk),
        3 => unused = 1 + input.byte() % 7,
        _ => {}
    }

    let alg = match alg_mode {
        0 => algorithm(P::OID),
        // NULL parameters
        1 => tlv(0x30, &[tlv(0x06, P::OID), vec![0x05, 0x00]].concat()),
        // another parameter set's identifier
        _ => {
            let mut oid = P::OID.to_vec();
            let last = oid.len() - 1;
            oid[last] = 0x11 + (oid[last] - 0x11 + 1) % 3;
            algorithm(&oid)
        }
    };
    let seed_bytes = if short_seed { &seed[1..] } else { &seed[..] };
    let private_key = choice(format, seed_bytes, &expanded);
    let mut extra = Vec::new();
    match attr_mode {
        1 => {
            let value = tlv(0x04, attribute_value);
            let attribute = tlv(
                0x30,
                &[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x31, &value)].concat(),
            );
            extra.extend(tlv(0xa0, &attribute));
        }
        // an attribute with an empty SET of values
        2 => extra.extend(tlv(
            0xa0,
            &tlv(
                0x30,
                &[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x31, &[])].concat(),
            ),
        )),
        _ => {}
    }
    if pk_mode != 0 {
        extra.extend(tlv(0x81, &[&[unused][..], &pk].concat()));
    }
    let der = one_asymmetric_key(version, &alg, &private_key, &extra);

    // The model, in the order the documented checks apply.
    let changed = expanded != original;
    let only_k =
        expanded[..K.start] == original[..K.start] && expanded[K.end..] == original[K.end..];
    let expected = if version > 1 {
        Err(Error::InvalidEncoding)
    } else if alg_mode != 0 {
        Err(Error::InvalidKey)
    } else if attr_mode == 2 || (pk_mode != 0 && version == 0) || pk_mode == 3 {
        Err(Error::InvalidEncoding)
    } else if (short_seed && format != PrivateKeyFormat::Expanded)
        || match format {
            PrivateKeyFormat::Seed => false,
            PrivateKeyFormat::Expanded => !only_k,
            PrivateKeyFormat::Both => changed,
        }
        || pk_mode == 2
    {
        // A seed of the wrong size, an expanded key that fails its check or
        // does not match the seed, then a `publicKey` that is not the key's.
        Err(Error::InvalidKey)
    } else {
        Ok(())
    };

    let result = SigningKey::<P>::from_pkcs8_der(&der);
    assert_eq!(
        result.as_ref().map(|_| ()).map_err(|e| *e),
        expected,
        "{format:?}"
    );
    if let Ok(loaded) = result {
        assert_eq!(loaded.verifying_key(), key.verifying_key());
        if format == PrivateKeyFormat::Expanded {
            assert_eq!(loaded.seed(), None);
            assert_eq!(loaded.to_expanded_bytes().as_ref(), &expanded[..]);
        } else {
            assert_eq!(loaded.seed(), Some(&seed));
            assert_eq!(loaded.to_expanded_bytes().as_ref(), &original[..]);
        }
        assert!(parse_pkcs8::<P>(&der).is_some());
    }
    // With `P`'s identifier, no other parameter set accepts it. (With
    // another set's identifier that set may: a seed suits every set.)
    if alg_mode == 0 {
        let accepted = [
            SigningKey::<MlDsa44>::from_pkcs8_der(&der).is_ok(),
            SigningKey::<MlDsa65>::from_pkcs8_der(&der).is_ok(),
            SigningKey::<MlDsa87>::from_pkcs8_der(&der).is_ok(),
        ];
        let expected_count = usize::from(expected.is_ok());
        assert_eq!(accepted.iter().filter(|&&ok| ok).count(), expected_count);
    }
}

/// Flips one byte of a non-empty `bytes` at a fuzzed position.
fn flip_one(input: &mut Input<'_>, bytes: &mut [u8]) {
    let at = usize::from(input.u16()) % bytes.len();
    bytes[at] ^= input.byte() | 1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harness_der() {
        for n in [0usize, 0x7f, 0x80, 0xff, 0x100, 0x1_0000] {
            let v = vec![7u8; n];
            let enc = tlv(0x04, &v);
            let (tag, header, contents, rest) = read_tlv(&enc).expect("parses");
            assert_eq!((tag, contents, rest), (0x04, &v[..], &[][..]));
            assert_eq!(header + n, enc.len());
        }
        let der = FIXTURES[0].1;
        assert_eq!(plain_form(der), Some((PrivateKeyFormat::Seed, 4)));
        assert_eq!(der[4], 0);
    }
}
