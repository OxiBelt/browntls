//! The opt-in algorithm table for the legacy RSASSA-PKCS1-v1_5 signature
//! schemes of RFC 9963, with which a server verifies a TLS 1.3 client
//! whose RSA key cannot make RSASSA-PSS signatures. The items are
//! re-exported from [`super`] (the `rustcrypto` module).
//!
//! The provider has no signing key for these schemes: it does not sign
//! with RSA at all (see [`super::sign`]).

use browntls_pki::SignatureVerificationAlgorithm;

use super::{SUPPORTED_SIG_ALGS, verify};
use crate::crypto::verify_list::concat;
use crate::enums::SignatureScheme;
use crate::webpki::WebPkiSupportedAlgorithms;

/// The legacy schemes of RFC 9963 and the algorithm that verifies each:
/// `rsa_pkcs1_sha512_legacy`, `rsa_pkcs1_sha384_legacy` and
/// `rsa_pkcs1_sha256_legacy` (0x0620, 0x0520, 0x0420), larger hashes first
/// as in the default mapping. Each maps to RSASSA-PKCS1-v1_5 with its hash
/// and an `rsaEncryption` key of 2048 to 8192 bits, which the `rsa` crate
/// verifies by comparing the whole encoded message (RFC 8017 §8.2.2): a
/// `DigestInfo` without the NULL parameters, or in any other encoding,
/// does not verify (RFC 9963 §3).
#[allow(clippy::type_complexity)]
pub static RSA_PKCS1_LEGACY_VERIFICATION_ALG_MAPPING: &[(
    SignatureScheme,
    &[&dyn SignatureVerificationAlgorithm],
)] = &[
    (
        SignatureScheme::RSA_PKCS1_SHA512_LEGACY,
        &[&verify::RSA_PKCS1_SHA512],
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA384_LEGACY,
        &[&verify::RSA_PKCS1_SHA384],
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA256_LEGACY,
        &[&verify::RSA_PKCS1_SHA256],
    ),
];

#[allow(clippy::type_complexity)]
static MAPPING_WITH_RSA_PKCS1_LEGACY: [(SignatureScheme, &[&dyn SignatureVerificationAlgorithm]);
    SUPPORTED_SIG_ALGS.mapping.len() + RSA_PKCS1_LEGACY_VERIFICATION_ALG_MAPPING.len()] = concat(
    SUPPORTED_SIG_ALGS.mapping,
    RSA_PKCS1_LEGACY_VERIFICATION_ALG_MAPPING,
);

/// The `mapping` of [`SUPPORTED_SIG_ALGS`] followed by
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
/// authentication: `all` is that of [`SUPPORTED_SIG_ALGS`], `mapping` is
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
///   `rsa_pkcs1_sha256_legacy` after the other schemes;
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
pub static SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY: WebPkiSupportedAlgorithms =
    WebPkiSupportedAlgorithms {
        all: SUPPORTED_SIG_ALGS.all,
        mapping: VERIFICATION_ALG_MAPPING_WITH_RSA_PKCS1_LEGACY,
    };

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use browntls_pki::alg_id;

    use super::*;
    use SignatureScheme as S;

    #[test]
    fn table_adds_the_legacy_schemes_after_the_defaults() {
        let table = &SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY;
        let defaults = SUPPORTED_SIG_ALGS.mapping.len();
        assert_eq!(table.mapping.len(), defaults + 3);
        for (default, opt_in) in SUPPORTED_SIG_ALGS.mapping.iter().zip(table.mapping) {
            assert_eq!(default.0, opt_in.0);
            assert_eq!(default.1.len(), opt_in.1.len());
        }
        let added: Vec<S> = table.mapping[defaults..].iter().map(|m| m.0).collect();
        assert_eq!(
            added,
            [
                S::RSA_PKCS1_SHA512_LEGACY,
                S::RSA_PKCS1_SHA384_LEGACY,
                S::RSA_PKCS1_SHA256_LEGACY
            ]
        );
        for (scheme, algs) in RSA_PKCS1_LEGACY_VERIFICATION_ALG_MAPPING {
            assert!(scheme.is_rsa_pkcs1_legacy());
            assert_eq!(algs.len(), 1);
            assert_eq!(algs[0].public_key_alg_id(), alg_id::RSA_ENCRYPTION);
            assert!(!SUPPORTED_SIG_ALGS.supported_schemes().contains(scheme));
        }
        assert_eq!(table.all.len(), SUPPORTED_SIG_ALGS.all.len());
        assert!(
            !SUPPORTED_SIG_ALGS
                .supported_schemes()
                .iter()
                .any(S::is_rsa_pkcs1_legacy)
        );
    }
}
