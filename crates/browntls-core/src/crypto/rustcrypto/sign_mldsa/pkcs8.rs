//! The RFC 9881 §6 PKCS #8 `OneAsymmetricKey` (RFC 5958) of an ML-DSA
//! private key, in strict DER.
//!
//! The `pkcs8` support of the `ml-dsa` crate reads the `seed` form only, so
//! the provider parses the structure itself. The structure accepted is that
//! of the native provider
//! (`browntls_crypto::mldsa::SigningKey::from_pkcs8_der`): the parse here
//! establishes it, and the caller checks the algorithm, the lengths, the
//! key and the public key, and refuses the `expandedKey` form.

/// The universal tags used here.
const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
/// `attributes [0] IMPLICIT Attributes` (constructed).
const ATTRIBUTES: u8 = 0xa0;
/// `publicKey [1] IMPLICIT PublicKey` (a primitive BIT STRING).
const PUBLIC_KEY: u8 = 0x81;
/// `seed [0] IMPLICIT OCTET STRING` in the private key CHOICE.
const SEED: u8 = 0x80;

/// The `ML-DSA-*-PrivateKey` CHOICE (RFC 9881 §6), not yet checked against
/// the parameter set.
#[derive(Clone, Copy)]
pub(super) enum PrivateKey<'a> {
    Seed(&'a [u8]),
    /// The `expandedKey` form, which the caller refuses.
    Expanded,
    Both {
        seed: &'a [u8],
        expanded: &'a [u8],
    },
}

/// A structurally valid `OneAsymmetricKey`.
pub(super) struct OneAsymmetricKey<'a> {
    /// The contents of `privateKeyAlgorithm` (without its SEQUENCE header).
    pub(super) algorithm: &'a [u8],
    pub(super) private_key: PrivateKey<'a>,
    /// The `publicKey` bits (without the unused-bits octet, which must be
    /// zero), present in version 1 (RFC 5958 v2) only.
    pub(super) public_key: Option<&'a [u8]>,
}

/// A strict DER cursor: single-byte tags, definite minimal lengths of at
/// most four octets.
struct Reader<'a> {
    input: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    fn read_any(&mut self) -> Option<(u8, &'a [u8])> {
        let (&tag, rest) = self.input.split_first()?;
        if tag & 0x1f == 0x1f {
            return None;
        }
        let (&first, rest) = rest.split_first()?;
        let (len, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 || rest.len() < n || rest[0] == 0 {
                return None;
            }
            let (len_bytes, rest) = rest.split_at(n);
            let len = len_bytes
                .iter()
                .fold(0usize, |len, b| (len << 8) | usize::from(*b));
            if len < 0x80 {
                return None;
            }
            (len, rest)
        };
        if rest.len() < len {
            return None;
        }
        let (value, rest) = rest.split_at(len);
        self.input = rest;
        Some((tag, value))
    }

    fn read(&mut self, tag: u8) -> Option<&'a [u8]> {
        self.read_any()
            .and_then(|(got, value)| (got == tag).then_some(value))
    }

    fn read_optional(&mut self, tag: u8) -> Option<Option<&'a [u8]>> {
        if self.input.first() == Some(&tag) {
            self.read(tag).map(Some)
        } else {
            Some(None)
        }
    }

    /// An OBJECT IDENTIFIER with well-formed contents (X.690 §8.19).
    fn read_oid(&mut self) -> Option<&'a [u8]> {
        let oid = self.read(OID)?;
        let truncated = oid.last().is_none_or(|b| b & 0x80 != 0);
        let padded = oid
            .iter()
            .enumerate()
            .any(|(i, &b)| b == 0x80 && (i == 0 || oid[i - 1] & 0x80 == 0));
        (!truncated && !padded).then_some(oid)
    }

    fn finish(&self) -> Option<()> {
        self.input.is_empty().then_some(())
    }
}

/// Checks `attributes`: zero or more `Attribute ::= SEQUENCE { attrType
/// OBJECT IDENTIFIER, attrValues SET OF AttributeValue }`, each with at
/// least one value (any TLV), each consumed in full. The values and the
/// DER order of the SET OFs are not checked, as in the native provider.
fn check_attributes(attributes: &[u8]) -> Option<()> {
    let mut r = Reader::new(attributes);
    while r.finish().is_none() {
        let mut attribute = Reader::new(r.read(SEQUENCE)?);
        attribute.read_oid()?;
        let mut values = Reader::new(attribute.read(SET)?);
        attribute.finish()?;
        values.finish().is_none().then_some(())?;
        while values.finish().is_none() {
            values.read_any()?;
        }
    }
    Some(())
}

/// Parses `der` as exactly one `OneAsymmetricKey`: `version` 0 or 1 (a
/// minimal INTEGER), `privateKeyAlgorithm` (a SEQUENCE), `privateKey` (an
/// OCTET STRING holding exactly one `seed`, `expandedKey` or `both`), then
/// optional `attributes` and, in version 1 only, an optional `publicKey`
/// without unused bits, and nothing else.
pub(super) fn parse(der: &[u8]) -> Option<OneAsymmetricKey<'_>> {
    let mut outer = Reader::new(der);
    let mut r = Reader::new(outer.read(SEQUENCE)?);
    outer.finish()?;

    let version = match r.read(INTEGER)? {
        [0] => 0,
        [1] => 1,
        _ => return None,
    };
    let algorithm = r.read(SEQUENCE)?;
    let private_key = r.read(OCTET_STRING)?;
    if let Some(attributes) = r.read_optional(ATTRIBUTES)? {
        check_attributes(attributes)?;
    }
    let public_key = match (version, r.read_optional(PUBLIC_KEY)?) {
        (_, None) => None,
        (1, Some([0, key @ ..])) => Some(key),
        _ => return None,
    };
    r.finish()?;

    let mut choice = Reader::new(private_key);
    let (tag, value) = choice.read_any()?;
    choice.finish()?;
    let private_key = match tag {
        SEED => PrivateKey::Seed(value),
        OCTET_STRING => PrivateKey::Expanded,
        SEQUENCE => {
            let mut both = Reader::new(value);
            let seed = both.read(OCTET_STRING)?;
            let expanded = both.read(OCTET_STRING)?;
            both.finish()?;
            PrivateKey::Both { seed, expanded }
        }
        _ => return None,
    };
    Some(OneAsymmetricKey {
        algorithm,
        private_key,
        public_key,
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn shapes() {
        // Version 0, an algorithm, a seed.
        let mut der = vec![0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09];
        der.extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11]);
        der.extend_from_slice(&[0x04, 0x22, 0x80, 0x20]);
        der.extend_from_slice(&[7; 32]);
        let key = parse(&der).unwrap();
        assert_eq!(key.algorithm.len(), 11);
        assert!(matches!(key.private_key, PrivateKey::Seed(s) if s == [7; 32]));
        assert!(key.public_key.is_none());
        for n in 0..der.len() {
            assert!(parse(&der[..n]).is_none());
        }
        let mut long = der.clone();
        long.push(0);
        assert!(parse(&long).is_none());
        // Version 2, and a negative version.
        for v in [2, 0xff] {
            let mut bad = der.clone();
            bad[4] = v;
            assert!(parse(&bad).is_none());
        }
    }

    #[test]
    fn oids_and_lengths() {
        for bad in [
            &[0x06, 0x00][..],
            &[0x06, 0x02, 0x80, 0x01],
            &[0x06, 0x01, 0x81],
        ] {
            assert!(Reader::new(bad).read_oid().is_none(), "{bad:02x?}");
        }
        assert!(
            Reader::new(&[0x06, 0x03, 0x2a, 0x81, 0x00])
                .read_oid()
                .is_some()
        );
        assert!(Reader::new(&[0x04, 0x81, 0x01, 0x00]).read_any().is_none());
        assert!(Reader::new(&[0x04, 0x80, 0x00, 0x00]).read_any().is_none());
        assert!(Reader::new(&[0x1f, 0x01, 0x00]).read_any().is_none());
    }
}
