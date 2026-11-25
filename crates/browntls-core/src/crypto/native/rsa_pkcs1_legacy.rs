//! The legacy RSASSA-PKCS1-v1_5 signature schemes of RFC 9963 for TLS 1.3
//! client authentication: a signing key restricted to PKCS #1 v1.5, and
//! the opt-in algorithm table with which a server verifies such a client.
//!
//! The key type and its loader are re-exported from [`super::sign`], the
//! table from [`super`] (the `native` module), which documents what opting
//! in means.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Debug};

use browntls_crypto::hash::HashAlgorithm as BcHash;
use browntls_crypto::rand::OsRng;
use browntls_crypto::rsa::{RsaKeyAlgorithm, RsaPrivateKey};
use browntls_pki::{PrivateKeyDer, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer};

use super::sign::RsaSigningKey;
use super::{ALL_VERIFICATION_ALGS, VERIFICATION_ALG_MAPPING, verify};
use crate::crypto::signer::{Signer, SigningKey};
use crate::crypto::verify_list::concat;
use crate::enums::{SignatureAlgorithm, SignatureScheme};
use crate::error::Error;
use crate::sync::Arc;
use crate::webpki::WebPkiSupportedAlgorithms;

/// The schemes of an [`RsaPkcs1LegacySigningKey`], larger hashes first:
/// `rsa_pkcs1_*` for TLS 1.2, then the RFC 9963 legacy schemes for a
/// TLS 1.3 client `CertificateVerify`. No handshake offers both kinds to a
/// key: TLS 1.2 never lists the legacy schemes, and TLS 1.3 never the
/// `rsa_pkcs1_*` ones.
static SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512_LEGACY,
    SignatureScheme::RSA_PKCS1_SHA384_LEGACY,
    SignatureScheme::RSA_PKCS1_SHA256_LEGACY,
];

/// The hash of an RSASSA-PKCS1-v1_5 scheme of [`SCHEMES`].
fn hash_of(scheme: SignatureScheme) -> Option<BcHash> {
    Some(match scheme {
        SignatureScheme::RSA_PKCS1_SHA256 | SignatureScheme::RSA_PKCS1_SHA256_LEGACY => {
            BcHash::Sha256
        }
        SignatureScheme::RSA_PKCS1_SHA384 | SignatureScheme::RSA_PKCS1_SHA384_LEGACY => {
            BcHash::Sha384
        }
        SignatureScheme::RSA_PKCS1_SHA512 | SignatureScheme::RSA_PKCS1_SHA512_LEGACY => {
            BcHash::Sha512
        }
        _ => return None,
    })
}

/// An `rsaEncryption` signing key (2048 to 8192 bits, two primes) that
/// makes RSASSA-PKCS1-v1_5 signatures only, never RSASSA-PSS: the
/// behaviour of an RSA key in a hardware token or an operating system key
/// store that predates RSASSA-PSS, which RFC 9963 exists for.
///
/// * Offered the legacy schemes of RFC 9963, which only the
///   CertificateRequest of a TLS 1.3 server that opted in to them lists,
///   it signs with `rsa_pkcs1_sha512_legacy`, `rsa_pkcs1_sha384_legacy`
///   or `rsa_pkcs1_sha256_legacy` (0x0620, 0x0520, 0x0420): the first of
///   these, in this order, that the list holds, wherever the list puts
///   it.
/// * Offered TLS 1.2 schemes, it signs with `rsa_pkcs1_sha512`,
///   `rsa_pkcs1_sha384` or `rsa_pkcs1_sha256`, chosen in the same way, as
///   a client or as a server.
/// * Offered neither, it does not sign. That is every other TLS 1.3 list:
///   the key cannot authenticate a TLS 1.3 server (RFC 9963 §3 defines
///   the legacy schemes for the client's `CertificateVerify` only, and
///   the handshake never offers them to a server's key), nor a client to
///   a server that did not opt in: that client sends an empty Certificate
///   message.
///
/// So as a TLS 1.3 client key it authenticates, in the handshake or in
/// post-handshake authentication, to servers whose CertificateRequest
/// lists a legacy scheme, and to no other.
///
/// The signature is RSASSA-PKCS1-v1_5 as RFC 8017 §8.2 specifies it, the
/// `DigestInfo` in DER with its NULL parameters (RFC 9963 §4), with CRT,
/// blinding and a fault check as for the other RSA keys.
///
/// Use this only for a key that cannot sign with RSASSA-PSS, or to stand
/// in for one in tests. A key that can (every software key) should be
/// loaded with [`any_rsa_type`](super::sign::any_rsa_type) and
/// authenticate with `rsa_pss_rsae_*`: RFC 9963 §3 says clients should not
/// negotiate the legacy schemes with such keys. This type wraps key
/// material held in memory; a key that lives in a token is used through
/// an application's own [`SigningKey`], which may choose a legacy scheme
/// from the offered list in the same way.
///
/// Load one with [`any_rsa_pkcs1_legacy_type`]. No key provider of this
/// crate does: the choice is made per key, by the application.
pub struct RsaPkcs1LegacySigningKey {
    key: Arc<RsaPrivateKey>,
    spki: SubjectPublicKeyInfoDer<'static>,
}

/// Loads an `rsaEncryption` private key (PKCS #8 or PKCS #1 DER, 2048 to
/// 8192 bits, two primes) as a key that signs with RSASSA-PKCS1-v1_5 only:
/// see [`RsaPkcs1LegacySigningKey`] for what it does and when to use it.
///
/// An `id-RSASSA-PSS` key is refused: its identifier restricts it to
/// RSASSA-PSS (RFC 4055 §1.2).
pub fn any_rsa_pkcs1_legacy_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    let RsaSigningKey {
        key,
        algorithm,
        spki,
    } = RsaSigningKey::load(der)?;
    match algorithm {
        RsaKeyAlgorithm::RsaEncryption => Ok(Arc::new(RsaPkcs1LegacySigningKey { key, spki })),
        RsaKeyAlgorithm::RsassaPss(_) => Err(Error::general(
            "an id-RSASSA-PSS key cannot sign with RSASSA-PKCS1-v1_5",
        )),
    }
}

impl SigningKey for RsaPkcs1LegacySigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let scheme = SCHEMES
            .iter()
            .copied()
            .find(|scheme| offered.contains(scheme))?;
        Some(Box::new(RsaPkcs1Signer {
            key: self.key.clone(),
            scheme,
        }))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from_slice(self.spki.as_ref()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

impl Debug for RsaPkcs1LegacySigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPkcs1LegacySigningKey")
            .field("bits", &self.key.modulus_bits())
            .finish_non_exhaustive()
    }
}

struct RsaPkcs1Signer {
    key: Arc<RsaPrivateKey>,
    scheme: SignatureScheme,
}

impl Signer for RsaPkcs1Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let hash = hash_of(self.scheme)
            .ok_or_else(|| Error::general("unsupported RSA signature scheme"))?;
        let mut out = vec![0u8; self.key.modulus_len_bytes()];
        let len = self
            .key
            .sign_pkcs1v15_with_rng(hash, message, &OsRng, &mut out)
            .map_err(|_| Error::general("RSA signing failed"))?;
        out.truncate(len);
        Ok(out)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl Debug for RsaPkcs1Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPkcs1Signer")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

/// The legacy schemes of RFC 9963 and the algorithm that verifies each:
/// `rsa_pkcs1_sha512_legacy`, `rsa_pkcs1_sha384_legacy` and
/// `rsa_pkcs1_sha256_legacy` (0x0620, 0x0520, 0x0420), larger hashes first
/// as in [`VERIFICATION_ALG_MAPPING`]. Each maps to RSASSA-PKCS1-v1_5 with
/// its hash and an `rsaEncryption` key of 2048 to 8192 bits, verified by
/// comparing the whole encoded message (RFC 8017 §8.2.2): a `DigestInfo`
/// without the NULL parameters, or in any other encoding, does not verify
/// (RFC 9963 §4).
#[allow(clippy::type_complexity)]
pub static RSA_PKCS1_LEGACY_VERIFICATION_ALG_MAPPING: &[(
    SignatureScheme,
    &[&dyn SignatureVerificationAlgorithm],
)] = &[
    (
        SignatureScheme::RSA_PKCS1_SHA512_LEGACY,
        &[&verify::RSA_PKCS1_2048_8192_SHA512],
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA384_LEGACY,
        &[&verify::RSA_PKCS1_2048_8192_SHA384],
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA256_LEGACY,
        &[&verify::RSA_PKCS1_2048_8192_SHA256],
    ),
];

#[allow(clippy::type_complexity)]
static MAPPING_WITH_RSA_PKCS1_LEGACY: [(SignatureScheme, &[&dyn SignatureVerificationAlgorithm]);
    VERIFICATION_ALG_MAPPING.len() + RSA_PKCS1_LEGACY_VERIFICATION_ALG_MAPPING.len()] = concat(
    VERIFICATION_ALG_MAPPING,
    RSA_PKCS1_LEGACY_VERIFICATION_ALG_MAPPING,
);

/// [`VERIFICATION_ALG_MAPPING`] followed by
/// [`RSA_PKCS1_LEGACY_VERIFICATION_ALG_MAPPING`]: the TLS scheme mapping
/// of [`SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY`], computed at compile
/// time so that every default scheme stays ahead of the legacy ones, in
/// the default order.
#[allow(clippy::type_complexity)]
pub static VERIFICATION_ALG_MAPPING_WITH_RSA_PKCS1_LEGACY: &[(
    SignatureScheme,
    &[&dyn SignatureVerificationAlgorithm],
)] = &MAPPING_WITH_RSA_PKCS1_LEGACY;

/// [`SUPPORTED_SIG_ALGS`](super::SUPPORTED_SIG_ALGS) with the legacy
/// RSASSA-PKCS1-v1_5 schemes of RFC 9963 for TLS 1.3 client
/// authentication: `all` is [`ALL_VERIFICATION_ALGS`], `mapping` is
/// [`VERIFICATION_ALG_MAPPING_WITH_RSA_PKCS1_LEGACY`].
///
/// This is an explicit opt-in, for a server whose clients hold RSA keys
/// that cannot make RSASSA-PSS signatures; RFC 9963 §3 says to leave the
/// code points disabled by default, and the provider's defaults do. With
/// this table,
/// [`verify_tls13_client_signature`](crate::crypto::verify_tls13_client_signature)
/// and a [`WebPkiClientVerifier`](crate::server::WebPkiClientVerifier)
/// (built through a provider whose `signature_verification_algorithms` it
/// is):
///
/// * name `rsa_pkcs1_sha512_legacy`, `rsa_pkcs1_sha384_legacy` and
///   `rsa_pkcs1_sha256_legacy` after the other schemes, so that a server
///   with that verifier lists them, last, in the `signature_algorithms`
///   of its TLS 1.3 CertificateRequests;
/// * accept a client's TLS 1.3 `CertificateVerify` signed with one of
///   them: RSASSA-PKCS1-v1_5 over the same content as any other scheme,
///   by an `rsaEncryption` key, in the exact encoding (see
///   [`RSA_PKCS1_LEGACY_VERIFICATION_ALG_MAPPING`]).
///
/// Nothing else changes, whatever uses the table. The schemes are never
/// listed in a ClientHello and never accepted in a server's
/// `CertificateVerify`, so a client configuration is unaffected by it and
/// server authentication keeps requiring RSASSA-PSS of an RSA key. TLS 1.2
/// handshakes, delegated credentials (RFC 9345) and exported
/// authenticators (RFC 9261) never use them. The certificate path
/// algorithms are the default ones.
///
/// A client signs with these schemes only with a key that chooses them:
/// [`RsaPkcs1LegacySigningKey`], or an application's own [`SigningKey`].
pub static SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY: WebPkiSupportedAlgorithms =
    WebPkiSupportedAlgorithms {
        all: ALL_VERIFICATION_ALGS,
        mapping: VERIFICATION_ALG_MAPPING_WITH_RSA_PKCS1_LEGACY,
    };

#[cfg(test)]
mod tests;
