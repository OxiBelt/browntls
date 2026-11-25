//! ML-DSA (FIPS 204) signature verification for X.509 (RFC 9881) with the
//! RustCrypto `ml-dsa` crate, and the opt-in algorithm tables that add it
//! to the provider's defaults.
//!
//! The algorithms are re-exported from [`super::verify`], the tables from
//! [`super`] (the `rustcrypto` module), which documents what opting in
//! means. The design is that of the native provider's ML-DSA algorithms
//! (`crypto::native::verify::MlDsaVerify`).

use core::fmt;

use browntls_pki::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id};
use ml_dsa::{
    EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signature, VerifyingKey,
};

use super::SUPPORTED_SIG_ALGS;
use crate::crypto::verify_list::concat;
use crate::webpki::WebPkiSupportedAlgorithms;

/// The ML-DSA parameter sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Set {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

/// Pure ML-DSA verification (FIPS 204 Algorithm 3, ML-DSA.Verify) with the
/// empty context string, as RFC 9881 §3 requires for certificate and CRL
/// signatures, by the RustCrypto `ml-dsa` crate. HashML-DSA is not
/// supported (RFC 9881 does not allow it in X.509).
///
/// The public key is the content of the `subjectPublicKey` BIT STRING: the
/// FIPS 204 `pkEncode` output of 1312, 1952 or 2592 octets (RFC 9881 §4).
/// The signature is the content of the signature BIT STRING, 2420, 3309 or
/// 4627 octets. A key or signature of another length, a signature that does
/// not decode (`sigDecode`, FIPS 204 Algorithm 27), and every other
/// failure, is [`InvalidSignature`]. Unlike the native provider's
/// algorithms, verification allocates: the `ml-dsa` crate keeps the
/// expanded public matrix and the decoded signature on the heap. The
/// matrix is built on the stack first, so one verification needs more
/// stack than the native algorithms: about 64 to 80 KiB for ML-DSA-87
/// against under 32 KiB, measured on one x86-64 host.
///
/// Both identifiers are the RFC 9881 §2 `id-ml-dsa-*` identifier with
/// absent parameters ([`alg_id::ML_DSA_44`] and so on), matched byte for
/// byte. These algorithms are not in the provider's defaults: see
/// [`ALL_VERIFICATION_ALGS_WITH_ML_DSA`](super::ALL_VERIFICATION_ALGS_WITH_ML_DSA).
pub struct MlDsaVerify {
    set: Set,
}

/// Verifies with parameter set `P`; every failure is `InvalidSignature`.
fn verify<P: MlDsaParams>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    // Both lengths and the signature encoding are checked before the key
    // is decoded, which expands the public matrix.
    let key = EncodedVerifyingKey::<P>::try_from(public_key).map_err(|_| InvalidSignature)?;
    let signature = Signature::<P>::try_from(signature).map_err(|_| InvalidSignature)?;
    let key = VerifyingKey::<P>::decode(&key);
    if key.verify_with_context(message, &[], &signature) {
        Ok(())
    } else {
        Err(InvalidSignature)
    }
}

impl MlDsaVerify {
    fn alg_id(&self) -> AlgorithmIdentifier {
        match self.set {
            Set::MlDsa44 => alg_id::ML_DSA_44,
            Set::MlDsa65 => alg_id::ML_DSA_65,
            Set::MlDsa87 => alg_id::ML_DSA_87,
        }
    }
}

impl SignatureVerificationAlgorithm for MlDsaVerify {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        match self.set {
            Set::MlDsa44 => verify::<MlDsa44>(public_key, message, signature),
            Set::MlDsa65 => verify::<MlDsa65>(public_key, message, signature),
            Set::MlDsa87 => verify::<MlDsa87>(public_key, message, signature),
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.alg_id()
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.alg_id()
    }
}

impl fmt::Debug for MlDsaVerify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.set {
            Set::MlDsa44 => "ML-DSA-44",
            Set::MlDsa65 => "ML-DSA-65",
            Set::MlDsa87 => "ML-DSA-87",
        };
        f.debug_struct("MlDsaVerify")
            .field("parameter_set", &name)
            .finish()
    }
}

/// ML-DSA-44 (`id-ml-dsa-44`, RFC 9881). Not in the defaults.
pub static ML_DSA_44: MlDsaVerify = MlDsaVerify { set: Set::MlDsa44 };

/// ML-DSA-65 (`id-ml-dsa-65`, RFC 9881). Not in the defaults.
pub static ML_DSA_65: MlDsaVerify = MlDsaVerify { set: Set::MlDsa65 };

/// ML-DSA-87 (`id-ml-dsa-87`, RFC 9881). Not in the defaults.
pub static ML_DSA_87: MlDsaVerify = MlDsaVerify { set: Set::MlDsa87 };

/// The three ML-DSA verification algorithms (RFC 9881), in the order
/// ML-DSA-44, ML-DSA-65, ML-DSA-87. Not in the `all` list of
/// [`SUPPORTED_SIG_ALGS`]; see [`ALL_VERIFICATION_ALGS_WITH_ML_DSA`] for
/// what adding them changes.
pub static ML_DSA_VERIFICATION_ALGS: &[&dyn SignatureVerificationAlgorithm] =
    &[&ML_DSA_44, &ML_DSA_65, &ML_DSA_87];

static WITH_ML_DSA: [&dyn SignatureVerificationAlgorithm;
    SUPPORTED_SIG_ALGS.all.len() + ML_DSA_VERIFICATION_ALGS.len()] =
    concat(SUPPORTED_SIG_ALGS.all, ML_DSA_VERIFICATION_ALGS);

/// The `all` list of [`SUPPORTED_SIG_ALGS`] followed by
/// [`ML_DSA_VERIFICATION_ALGS`]: the certificate path algorithms of
/// [`SUPPORTED_SIG_ALGS_WITH_ML_DSA`].
///
/// The list is computed from the two lists at compile time, so it always
/// holds every default algorithm, in the same order, ahead of the ML-DSA
/// ones.
///
/// Using it (directly with `browntls_pki`, or through
/// [`SUPPORTED_SIG_ALGS_WITH_ML_DSA`] in a provider or verifier) means that
/// signatures made with ML-DSA keys verify wherever this crate verifies
/// signatures with the `all` list of [`WebPkiSupportedAlgorithms`]:
///
/// * certificate signatures during path validation by
///   [`WebPkiServerVerifier`](crate::client::WebPkiServerVerifier) and
///   [`WebPkiClientVerifier`](crate::server::WebPkiClientVerifier), with or
///   without a revocation policy, and by
///   [`verify_server_cert_signed_by_trust_anchor`](crate::client::verify_server_cert_signed_by_trust_anchor)
///   when given this list;
/// * CRL signatures checked during that path validation, including those
///   of the CRLs that may clear a delegated OCSP responder;
/// * OCSP response signatures, stapled or fetched, and the signatures of
///   delegated OCSP responder certificates, under a
///   [`RevocationPolicy`](crate::revocation::RevocationPolicy), under the
///   Certificate Transparency 2.0 requirements, and in the server's
///   `revocation::ServerStapleResolver` (feature `std`);
/// * the server's own chain, which `ServerStapleResolver` validates with
///   the provider's list.
///
/// Certificate Transparency logs cannot have ML-DSA keys: version 1 SCTs
/// name a TLS hash and signature pair that maps to no ML-DSA identifier,
/// and version 2 logs are restricted to P-256 and Ed25519 keys.
///
/// The RFC 9881 §5 key usage rules for ML-DSA keys apply with or without
/// this list.
pub static ALL_VERIFICATION_ALGS_WITH_ML_DSA: &[&dyn SignatureVerificationAlgorithm] = &WITH_ML_DSA;

/// [`SUPPORTED_SIG_ALGS`] with ML-DSA added to the certificate path
/// algorithms: `all` is [`ALL_VERIFICATION_ALGS_WITH_ML_DSA`], `mapping` is
/// the unchanged `mapping` of [`SUPPORTED_SIG_ALGS`].
///
/// This is an explicit opt-in for X.509 validation (RFC 9881); the
/// provider's defaults do not include ML-DSA. Because the TLS scheme
/// mapping is unchanged, the `signature_algorithms` lists this library
/// sends, in a ClientHello and in a CertificateRequest, do not name
/// ML-DSA, and a `CertificateVerify` or `ServerKeyExchange` signed with an
/// ML-DSA scheme is refused as unadvertised. With this table an ML-DSA end
/// entity certificate validates but cannot authenticate a TLS handshake,
/// and nothing on the wire tells a peer that chains signed with ML-DSA are
/// accepted; TLS 1.3 authentication with ML-DSA keys
/// (`draft-ietf-tls-mldsa`) is the separate opt-in
/// [`SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13`](super::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13).
/// See [`ALL_VERIFICATION_ALGS_WITH_ML_DSA`] for every signature the
/// opt-in applies to.
pub static SUPPORTED_SIG_ALGS_WITH_ML_DSA: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: ALL_VERIFICATION_ALGS_WITH_ML_DSA,
    mapping: SUPPORTED_SIG_ALGS.mapping,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::SignatureScheme;

    fn same(
        a: &dyn SignatureVerificationAlgorithm,
        b: &dyn SignatureVerificationAlgorithm,
    ) -> bool {
        core::ptr::addr_eq(
            a as *const dyn SignatureVerificationAlgorithm,
            b as *const dyn SignatureVerificationAlgorithm,
        ) && a.public_key_alg_id() == b.public_key_alg_id()
            && a.signature_alg_id() == b.signature_alg_id()
    }

    fn is_ml_dsa(alg: &dyn SignatureVerificationAlgorithm) -> bool {
        [alg_id::ML_DSA_44, alg_id::ML_DSA_65, alg_id::ML_DSA_87]
            .iter()
            .any(|id| alg.public_key_alg_id() == *id || alg.signature_alg_id() == *id)
    }

    #[test]
    fn opt_in_list_extends_the_default_list() {
        let default = SUPPORTED_SIG_ALGS.all;
        let (head, tail) = ALL_VERIFICATION_ALGS_WITH_ML_DSA.split_at(default.len());
        for (a, b) in head.iter().zip(default) {
            assert!(same(*a, *b), "{a:?} {b:?}");
        }
        assert_eq!(tail.len(), 3);
        for (a, b) in tail.iter().zip(ML_DSA_VERIFICATION_ALGS) {
            assert!(same(*a, *b), "{a:?} {b:?}");
        }
        let all = SUPPORTED_SIG_ALGS_WITH_ML_DSA.all;
        assert_eq!(all.len(), ALL_VERIFICATION_ALGS_WITH_ML_DSA.len());
        for (a, b) in all.iter().zip(ALL_VERIFICATION_ALGS_WITH_ML_DSA) {
            assert!(same(*a, *b), "{a:?} {b:?}");
        }
        let mapping = SUPPORTED_SIG_ALGS_WITH_ML_DSA.mapping;
        assert_eq!(mapping.len(), SUPPORTED_SIG_ALGS.mapping.len());
        for ((s1, a1), (s2, a2)) in mapping.iter().zip(SUPPORTED_SIG_ALGS.mapping) {
            assert_eq!(s1, s2);
            assert_eq!(a1.len(), a2.len());
            for (a, b) in a1.iter().zip(*a2) {
                assert!(same(*a, *b), "{s1:?}: {a:?} {b:?}");
            }
        }
        assert!(!SUPPORTED_SIG_ALGS_WITH_ML_DSA.fips());
    }

    #[test]
    fn defaults_exclude_ml_dsa_and_no_scheme_maps_to_it() {
        assert!(!SUPPORTED_SIG_ALGS.all.iter().any(|a| is_ml_dsa(*a)));
        let p = super::super::default_provider();
        assert!(
            !p.signature_verification_algorithms
                .all
                .iter()
                .any(|a| is_ml_dsa(*a))
        );
        let count = ALL_VERIFICATION_ALGS_WITH_ML_DSA
            .iter()
            .filter(|a| is_ml_dsa(**a))
            .count();
        assert_eq!(count, 3);
        for table in [&SUPPORTED_SIG_ALGS, &SUPPORTED_SIG_ALGS_WITH_ML_DSA] {
            for (_, algs) in table.mapping {
                for alg in *algs {
                    assert!(!is_ml_dsa(*alg), "{alg:?}");
                    // Every mapped algorithm is in both `all` lists.
                    for list in [SUPPORTED_SIG_ALGS.all, ALL_VERIFICATION_ALGS_WITH_ML_DSA] {
                        assert!(list.iter().any(|a| same(*a, *alg)), "{alg:?}");
                    }
                }
            }
            let schemes = table.supported_schemes();
            for scheme in [
                SignatureScheme::ML_DSA_44,
                SignatureScheme::ML_DSA_65,
                SignatureScheme::ML_DSA_87,
            ] {
                assert!(!schemes.contains(&scheme), "{scheme:?}");
            }
        }
        assert_eq!(
            SUPPORTED_SIG_ALGS_WITH_ML_DSA.supported_schemes(),
            SUPPORTED_SIG_ALGS.supported_schemes()
        );
    }

    #[test]
    fn identifiers_and_debug() {
        let ids = [alg_id::ML_DSA_44, alg_id::ML_DSA_65, alg_id::ML_DSA_87];
        for (alg, id) in ML_DSA_VERIFICATION_ALGS.iter().zip(ids) {
            assert_eq!(alg.public_key_alg_id(), id);
            assert_eq!(alg.signature_alg_id(), id);
            assert!(!alg.fips());
            assert!(alg.public_key_alg_id().matches_public_key(id.as_bytes()));
            let with_null = [id.as_bytes(), &[0x05, 0x00]].concat();
            assert!(!alg.public_key_alg_id().matches_public_key(&with_null));
        }
        assert_eq!(
            alloc::format!("{:?}", ML_DSA_65),
            "MlDsaVerify { parameter_set: \"ML-DSA-65\" }"
        );
    }

    #[test]
    fn malformed_inputs_are_invalid() {
        for alg in [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87] {
            assert_eq!(alg.verify_signature(&[], b"", &[]), Err(InvalidSignature));
            assert_eq!(
                alg.verify_signature(&[0; 2592], b"m", &[0; 4627]),
                Err(InvalidSignature)
            );
            assert_eq!(
                alg.verify_signature(&[0xff; 1952], b"m", &[0xff; 3309]),
                Err(InvalidSignature)
            );
        }
    }
}
