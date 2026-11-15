//! DHKEM (RFC 9180 §4.1) over X25519, X448, P-256, P-384 and P-521.

use super::labeled::{Secret, labeled_expand, labeled_extract};
use super::{Kem, MAX_ENC_LEN, MAX_PRIVATE_KEY_LEN, MAX_PUBLIC_KEY_LEN};
use crate::Error;
use crate::curve448::x448;
use crate::curve25519::x25519;
use crate::nist::{p256, p384, p521};
use crate::zeroize::Zeroizing;

/// `suite_id = "KEM" || I2OSP(kem_id, 2)`.
fn kem_suite_id(kem: Kem) -> [u8; 5] {
    let [a, b] = kem.id().to_be_bytes();
    [b'K', b'E', b'M', a, b]
}

/// A serialized, validated KEM public key (`SerializePublicKey` output).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    kem: Kem,
    bytes: [u8; MAX_PUBLIC_KEY_LEN],
    len: usize,
}

impl PublicKey {
    /// `DeserializePublicKey(pkXm)`: X25519 and X448 keys are taken as is;
    /// NIST keys must be uncompressed SEC 1 points on the curve.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] for a wrong length or an invalid point.
    pub fn from_bytes(kem: Kem, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != kem.public_key_len() {
            return Err(Error::InvalidKey);
        }
        let valid = match kem {
            Kem::DhX25519HkdfSha256 | Kem::DhX448HkdfSha512 => true,
            Kem::DhP256HkdfSha256 => p256::PublicKey::from_sec1_bytes(bytes).is_ok(),
            Kem::DhP384HkdfSha384 => p384::PublicKey::from_sec1_bytes(bytes).is_ok(),
            Kem::DhP521HkdfSha512 => p521::PublicKey::from_sec1_bytes(bytes).is_ok(),
        };
        // The length check above excludes compressed encodings, which HPKE
        // does not use; require the uncompressed tag explicitly as well.
        let is_nist = !matches!(kem, Kem::DhX25519HkdfSha256 | Kem::DhX448HkdfSha512);
        if !valid || (is_nist && bytes[0] != 0x04) {
            return Err(Error::InvalidKey);
        }
        let mut out = Self {
            kem,
            bytes: [0; MAX_PUBLIC_KEY_LEN],
            len: bytes.len(),
        };
        out.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(out)
    }

    /// The KEM this key belongs to.
    #[must_use]
    pub fn kem(&self) -> Kem {
        self.kem
    }

    /// `SerializePublicKey(pk)`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublicKey")
            .field("kem", &self.kem)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// The encapsulated key `enc` produced by the sender.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EncapsulatedKey {
    bytes: [u8; MAX_ENC_LEN],
    len: usize,
}

impl EncapsulatedKey {
    /// The encoded bytes, `Nenc` long.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl AsRef<[u8]> for EncapsulatedKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl core::fmt::Debug for EncapsulatedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncapsulatedKey")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

enum Inner {
    X25519(x25519::PrivateKey),
    X448(x448::PrivateKey),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
}

/// A KEM private key with its public key. Secret material is zeroised on drop.
pub struct PrivateKey {
    kem: Kem,
    inner: Inner,
    public: PublicKey,
}

impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("kem", &self.kem)
            .finish_non_exhaustive()
    }
}

/// Clamps an X25519 scalar as RFC 7748 §5 does.
fn clamp_x25519(k: &mut [u8]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

/// Clamps an X448 scalar as RFC 7748 §5 does.
fn clamp_x448(k: &mut [u8]) {
    k[0] &= 252;
    k[55] |= 128;
}

impl PrivateKey {
    /// `DeserializePrivateKey(skXm)`. X25519 and X448 scalars are clamped
    /// (RFC 9180 §7.1.2); NIST scalars must lie in `[1, n - 1]`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] for a wrong length or out-of-range scalar.
    pub fn from_bytes(kem: Kem, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != kem.private_key_len() {
            return Err(Error::InvalidKey);
        }
        match kem {
            Kem::DhX25519HkdfSha256 => {
                let mut k = Zeroizing([0u8; 32]);
                k.copy_from_slice(bytes);
                clamp_x25519(&mut k[..]);
                let sk = x25519::PrivateKey::from_bytes(&k);
                let pk = sk.public_key();
                Ok(Self::assemble(kem, Inner::X25519(sk), &pk))
            }
            Kem::DhX448HkdfSha512 => {
                let mut k = Zeroizing([0u8; 56]);
                k.copy_from_slice(bytes);
                clamp_x448(&mut k[..]);
                let sk = x448::PrivateKey::from_bytes(&k);
                let pk = sk.public_key();
                Ok(Self::assemble(kem, Inner::X448(sk), &pk))
            }
            Kem::DhP256HkdfSha256 => {
                let sk = p256::SecretKey::from_bytes(bytes)?;
                let pk = sk.public_key().to_uncompressed();
                Ok(Self::assemble(kem, Inner::P256(sk), &pk))
            }
            Kem::DhP384HkdfSha384 => {
                let sk = p384::SecretKey::from_bytes(bytes)?;
                let pk = sk.public_key().to_uncompressed();
                Ok(Self::assemble(kem, Inner::P384(sk), &pk))
            }
            Kem::DhP521HkdfSha512 => {
                let sk = p521::SecretKey::from_bytes(bytes)?;
                let pk = sk.public_key().to_uncompressed();
                Ok(Self::assemble(kem, Inner::P521(sk), &pk))
            }
        }
    }

    fn assemble(kem: Kem, inner: Inner, public: &[u8]) -> Self {
        let mut pk = PublicKey {
            kem,
            bytes: [0; MAX_PUBLIC_KEY_LEN],
            len: public.len(),
        };
        pk.bytes[..public.len()].copy_from_slice(public);
        Self {
            kem,
            inner,
            public: pk,
        }
    }

    /// The KEM this key belongs to.
    #[must_use]
    pub fn kem(&self) -> Kem {
        self.kem
    }

    /// The public key (`pk(skX)`).
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// `SerializePrivateKey(skX)` into `out`, returning `Nsk`. X25519 and X448
    /// output is clamped (RFC 9180 §7.1.2).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if `out` is shorter than `Nsk`.
    pub fn write_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.kem.private_key_len();
        let out = out.get_mut(..n).ok_or(Error::InvalidLength)?;
        match &self.inner {
            Inner::X25519(k) => {
                out.copy_from_slice(k.as_bytes());
                clamp_x25519(out);
            }
            Inner::X448(k) => {
                out.copy_from_slice(k.as_bytes());
                clamp_x448(out);
            }
            Inner::P256(k) => out.copy_from_slice(&k.to_bytes()[..]),
            Inner::P384(k) => out.copy_from_slice(&k.to_bytes()[..]),
            Inner::P521(k) => out.copy_from_slice(&k.to_bytes()[..]),
        }
        Ok(n)
    }

    /// `DH(skX, pkY)` into a zeroising buffer; returns the output length.
    fn dh(&self, peer: &PublicKey) -> Result<(Zeroizing<[u8; MAX_PRIVATE_KEY_LEN]>, usize), Error> {
        if peer.kem != self.kem {
            return Err(Error::InvalidKey);
        }
        let mut out = Zeroizing([0u8; MAX_PRIVATE_KEY_LEN]);
        let p = peer.as_bytes();
        let len = match &self.inner {
            Inner::X25519(k) => {
                let peer: &[u8; 32] = p.try_into().map_err(|_| Error::InvalidKey)?;
                let s = Zeroizing(k.diffie_hellman(peer)?);
                out[..32].copy_from_slice(&s[..]);
                32
            }
            Inner::X448(k) => {
                let peer: &[u8; 56] = p.try_into().map_err(|_| Error::InvalidKey)?;
                let s = Zeroizing(k.diffie_hellman(peer)?);
                out[..56].copy_from_slice(&s[..]);
                56
            }
            Inner::P256(k) => {
                let s = Zeroizing(k.diffie_hellman(&p256::PublicKey::from_sec1_bytes(p)?)?);
                out[..s.len()].copy_from_slice(&s[..]);
                s.len()
            }
            Inner::P384(k) => {
                let s = Zeroizing(k.diffie_hellman(&p384::PublicKey::from_sec1_bytes(p)?)?);
                out[..s.len()].copy_from_slice(&s[..]);
                s.len()
            }
            Inner::P521(k) => {
                let s = Zeroizing(k.diffie_hellman(&p521::PublicKey::from_sec1_bytes(p)?)?);
                out[..s.len()].copy_from_slice(&s[..]);
                s.len()
            }
        };
        Ok((out, len))
    }
}

/// `DeriveKeyPair(ikm)` (RFC 9180 §7.1.3).
pub(super) fn derive_key_pair(kem: Kem, ikm: &[u8]) -> Result<PrivateKey, Error> {
    let kdf = kem.kdf();
    let sid = kem_suite_id(kem);
    let dkp_prk = labeled_extract(kdf, &sid, b"", b"dkp_prk", ikm);
    let nsk = kem.private_key_len();
    let mut sk = Zeroizing([0u8; MAX_PRIVATE_KEY_LEN]);
    let sk = &mut sk[..nsk];
    match kem {
        Kem::DhX25519HkdfSha256 | Kem::DhX448HkdfSha512 => {
            labeled_expand(kdf, &sid, dkp_prk.as_bytes(), b"sk", (b"", b""), sk)?;
            PrivateKey::from_bytes(kem, sk)
        }
        Kem::DhP256HkdfSha256 | Kem::DhP384HkdfSha384 | Kem::DhP521HkdfSha512 => {
            let bitmask = if kem == Kem::DhP521HkdfSha512 {
                0x01
            } else {
                0xff
            };
            // Rejection sampling over a public counter: the number of
            // iterations depends only on whether candidates fall outside
            // `[1, n - 1]`, which reveals nothing usable about the key.
            for counter in 0..=255u8 {
                labeled_expand(
                    kdf,
                    &sid,
                    dkp_prk.as_bytes(),
                    b"candidate",
                    (&[counter], b""),
                    sk,
                )?;
                sk[0] &= bitmask;
                if let Ok(key) = PrivateKey::from_bytes(kem, sk) {
                    return Ok(key);
                }
            }
            Err(Error::InvalidKey)
        }
    }
}

/// `ExtractAndExpand(dh, kem_context)`.
fn extract_and_expand(kem: Kem, dh: &[u8], enc: &[u8], pk_rm: &[u8]) -> Result<Secret, Error> {
    let kdf = kem.kdf();
    let sid = kem_suite_id(kem);
    let eae_prk = labeled_extract(kdf, &sid, b"", b"eae_prk", dh);
    let mut shared = Secret::zeroed(kem.shared_secret_len());
    labeled_expand(
        kdf,
        &sid,
        eae_prk.as_bytes(),
        b"shared_secret",
        (enc, pk_rm),
        shared.as_mut_bytes(),
    )?;
    Ok(shared)
}

/// `Encap(pkR)` with the given ephemeral key pair.
pub(super) fn encap(
    ephemeral: &PrivateKey,
    pk_r: &PublicKey,
) -> Result<(EncapsulatedKey, Secret), Error> {
    let (dh, dh_len) = ephemeral.dh(pk_r)?;
    let pk_e = ephemeral.public_key().as_bytes();
    let mut enc = EncapsulatedKey {
        bytes: [0; MAX_ENC_LEN],
        len: pk_e.len(),
    };
    enc.bytes[..pk_e.len()].copy_from_slice(pk_e);
    let shared = extract_and_expand(ephemeral.kem, &dh[..dh_len], pk_e, pk_r.as_bytes())?;
    Ok((enc, shared))
}

/// `Decap(enc, skR)`.
pub(super) fn decap(enc: &[u8], sk_r: &PrivateKey) -> Result<Secret, Error> {
    let pk_e = PublicKey::from_bytes(sk_r.kem, enc)?;
    let (dh, dh_len) = sk_r.dh(&pk_e)?;
    extract_and_expand(sk_r.kem, &dh[..dh_len], enc, sk_r.public_key().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_compressed_and_off_curve_points() {
        let sk = Kem::DhP256HkdfSha256.derive_key_pair(&[7; 32]).unwrap();
        let pk = sk.public_key().as_bytes();
        let mut bad = [0u8; 65];
        bad.copy_from_slice(pk);
        bad[64] ^= 1;
        assert_eq!(
            PublicKey::from_bytes(Kem::DhP256HkdfSha256, &bad),
            Err(Error::InvalidKey)
        );
        assert_eq!(
            PublicKey::from_bytes(Kem::DhP256HkdfSha256, &pk[..33]),
            Err(Error::InvalidKey)
        );
        assert!(PublicKey::from_bytes(Kem::DhP256HkdfSha256, pk).is_ok());
    }

    #[test]
    fn x25519_low_order_point_is_rejected() {
        let sk = Kem::DhX25519HkdfSha256.derive_key_pair(&[1; 32]).unwrap();
        let zero = [0u8; 32];
        assert_eq!(decap(&zero, &sk).err(), Some(Error::KeyAgreementFailed));
    }
}
