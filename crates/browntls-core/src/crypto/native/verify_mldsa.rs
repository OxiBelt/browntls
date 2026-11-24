//! ML-DSA (FIPS 204) signature verification for X.509 (RFC 9881), and the
//! opt-in algorithm tables that add it to the provider's defaults.
//!
//! The algorithms are re-exported from [`super::verify`], the tables from
//! [`super`] (the `native` module), which documents what opting in means.

use core::fmt;

use browntls_crypto::mldsa::{self, MlDsa44, MlDsa65, MlDsa87, ParameterSet};
use browntls_pki::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id};

use super::{ALL_VERIFICATION_ALGS, VERIFICATION_ALG_MAPPING};
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
/// signatures. HashML-DSA is not supported (RFC 9881 does not allow it in
/// X.509).
///
/// The public key is the content of the `subjectPublicKey` BIT STRING: the
/// FIPS 204 `pkEncode` output of 1312, 1952 or 2592 octets (RFC 9881 §4).
/// The signature is the content of the signature BIT STRING, 2420, 3309 or
/// 4627 octets. A key or signature of another length, and every other
/// failure, is [`InvalidSignature`]. Verification does not allocate.
///
/// Both identifiers are the RFC 9881 §2 `id-ml-dsa-*` identifier with
/// absent parameters ([`alg_id::ML_DSA_44`] and so on), matched byte for
/// byte. These algorithms are not in the provider's defaults: see
/// [`ALL_VERIFICATION_ALGS_WITH_ML_DSA`](super::ALL_VERIFICATION_ALGS_WITH_ML_DSA).
pub struct MlDsaVerify {
    set: Set,
}

/// Verifies with parameter set `P`; every failure is `InvalidSignature`.
fn verify<P: ParameterSet>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    let key = mldsa::VerifyingKey::<P>::from_bytes(public_key).map_err(|_| InvalidSignature)?;
    key.verify(message, signature).map_err(|_| InvalidSignature)
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
            Set::MlDsa44 => MlDsa44::NAME,
            Set::MlDsa65 => MlDsa65::NAME,
            Set::MlDsa87 => MlDsa87::NAME,
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
/// ML-DSA-44, ML-DSA-65, ML-DSA-87. Not in [`ALL_VERIFICATION_ALGS`]; see
/// [`ALL_VERIFICATION_ALGS_WITH_ML_DSA`] for what adding them changes.
pub static ML_DSA_VERIFICATION_ALGS: &[&dyn SignatureVerificationAlgorithm] =
    &[&ML_DSA_44, &ML_DSA_65, &ML_DSA_87];

/// `a` followed by `b`, as an array of exactly `N` entries. A wrong `N` is
/// a compile-time error where the result initialises a static.
const fn concat<const N: usize>(
    a: &[&'static dyn SignatureVerificationAlgorithm],
    b: &[&'static dyn SignatureVerificationAlgorithm],
) -> [&'static dyn SignatureVerificationAlgorithm; N] {
    assert!(a.len() + b.len() == N && N > 0);
    let first = if a.is_empty() { b[0] } else { a[0] };
    let mut out = [first; N];
    let mut i = 0;
    while i < a.len() {
        out[i] = a[i];
        i += 1;
    }
    let mut j = 0;
    while j < b.len() {
        out[a.len() + j] = b[j];
        j += 1;
    }
    out
}

static WITH_ML_DSA: [&dyn SignatureVerificationAlgorithm;
    ALL_VERIFICATION_ALGS.len() + ML_DSA_VERIFICATION_ALGS.len()] =
    concat(ALL_VERIFICATION_ALGS, ML_DSA_VERIFICATION_ALGS);

/// [`ALL_VERIFICATION_ALGS`] followed by [`ML_DSA_VERIFICATION_ALGS`]: the
/// certificate path algorithms of [`SUPPORTED_SIG_ALGS_WITH_ML_DSA`].
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
/// * OCSP response signatures and the signatures of delegated OCSP
///   responder certificates: stapled responses under a
///   [`RevocationPolicy`](crate::revocation::RevocationPolicy) and in the
///   initial staple of the server's `revocation::ServerStapleResolver`
///   (feature `std`), both tested; responses that resolver installs
///   later, responses fetched live under a `RevocationPolicy` and stapled
///   responses read for the Certificate Transparency 2.0 requirements use
///   the same list, which is not tested for ML-DSA;
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

/// [`SUPPORTED_SIG_ALGS`](super::SUPPORTED_SIG_ALGS) with ML-DSA added to
/// the certificate path algorithms: `all` is
/// [`ALL_VERIFICATION_ALGS_WITH_ML_DSA`], `mapping` is the unchanged
/// [`VERIFICATION_ALG_MAPPING`].
///
/// This is an explicit opt-in for X.509 validation (RFC 9881) only; the
/// provider's defaults do not include ML-DSA. Its `mapping` is and will
/// stay the default TLS scheme mapping: TLS authentication with ML-DSA
/// keys, if added, will be a separate, explicit choice, not a change to
/// this table. Because the TLS scheme
/// mapping is unchanged, the `signature_algorithms` lists this library
/// sends, in a ClientHello and in a CertificateRequest, do not name
/// ML-DSA, and a `CertificateVerify` or `ServerKeyExchange` signed with an
/// ML-DSA scheme is refused as unadvertised. TLS 1.3 authentication with
/// ML-DSA keys (`draft-ietf-tls-mldsa`) is not implemented: an ML-DSA end
/// entity certificate validates, but cannot authenticate a TLS handshake,
/// and nothing on the wire tells a peer that chains signed with ML-DSA are
/// accepted. See [`ALL_VERIFICATION_ALGS_WITH_ML_DSA`] for every signature
/// the opt-in applies to.
pub static SUPPORTED_SIG_ALGS_WITH_ML_DSA: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: ALL_VERIFICATION_ALGS_WITH_ML_DSA,
    mapping: VERIFICATION_ALG_MAPPING,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::native::SUPPORTED_SIG_ALGS;

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

    #[test]
    fn opt_in_list_extends_the_default_list() {
        let (head, tail) = ALL_VERIFICATION_ALGS_WITH_ML_DSA.split_at(ALL_VERIFICATION_ALGS.len());
        assert_eq!(head.len(), ALL_VERIFICATION_ALGS.len());
        for (a, b) in head.iter().zip(ALL_VERIFICATION_ALGS) {
            assert!(same(*a, *b), "{a:?} {b:?}");
        }
        assert_eq!(tail.len(), 3);
        for (a, b) in tail.iter().zip(ML_DSA_VERIFICATION_ALGS) {
            assert!(same(*a, *b), "{a:?} {b:?}");
        }
        // Slices of the same static data need not share an address (the
        // compiler may duplicate anonymous allocations), so compare the
        // entries, which are named statics.
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
    fn identifiers_and_debug() {
        let ids = [alg_id::ML_DSA_44, alg_id::ML_DSA_65, alg_id::ML_DSA_87];
        for (alg, id) in ML_DSA_VERIFICATION_ALGS.iter().zip(ids) {
            assert_eq!(alg.public_key_alg_id(), id);
            assert_eq!(alg.signature_alg_id(), id);
            assert!(!alg.fips());
            // Only the identifier bytes match: no NULL parameters.
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
    fn verifies_only_its_own_parameter_set() {
        let seed = [7u8; 32];
        let sk = mldsa::SigningKey::<MlDsa44>::from_seed(&seed);
        let sig = sk.sign_deterministic(b"tbs", b"").unwrap();
        let pk = sk.verifying_key().as_bytes();
        assert!(ML_DSA_44.verify_signature(pk, b"tbs", sig.as_ref()).is_ok());
        assert!(
            ML_DSA_44
                .verify_signature(pk, b"tbt", sig.as_ref())
                .is_err()
        );
        assert!(
            ML_DSA_65
                .verify_signature(pk, b"tbs", sig.as_ref())
                .is_err()
        );
        assert!(
            ML_DSA_87
                .verify_signature(pk, b"tbs", sig.as_ref())
                .is_err()
        );
        assert!(ML_DSA_44.verify_signature(&[], b"tbs", &[]).is_err());
        // A non-empty context makes a different signature, which the
        // empty-context verification of RFC 9881 refuses.
        let ctx_sig = sk.sign_deterministic(b"tbs", b"ctx").unwrap();
        assert!(
            ML_DSA_44
                .verify_signature(pk, b"tbs", ctx_sig.as_ref())
                .is_err()
        );
    }
}
