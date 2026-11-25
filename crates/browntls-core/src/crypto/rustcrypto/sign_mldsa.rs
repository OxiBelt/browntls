//! ML-DSA (FIPS 204) signing keys for TLS 1.3 authentication
//! (`draft-ietf-tls-mldsa-06`) with the RustCrypto `ml-dsa` crate, and the
//! opt-in key provider and algorithm table that enable it.
//!
//! The key type and loader are re-exported from [`super::sign`], the
//! provider items from [`super`] (the `rustcrypto` module), which documents
//! what opting in means. The design and the behaviour are those of the
//! native provider's ML-DSA keys (`crypto::native::sign::MlDsaSigningKey`).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{self, Debug};

use browntls_pki::{
    PrivateKeyDer, PrivatePkcs8KeyDer, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer,
    alg_id,
};
use ml_dsa::signature::rand_core::{TryCryptoRng, TryRng};
use ml_dsa::{
    B32, ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa44, MlDsa65, MlDsa87, MlDsaParams,
};
use zeroize::Zeroizing;

use super::verify_mldsa::ALL_VERIFICATION_ALGS_WITH_ML_DSA;
use super::{RustCrypto, SUPPORTED_SIG_ALGS, sign, verify};
use crate::crypto::signer::{NO_TLS12_SIGNATURE_ALGORITHM, Signer, SigningKey};
use crate::crypto::verify_list::concat;
use crate::crypto::{GetRandomFailed, KeyProvider, SecureRandom};
use crate::enums::{SignatureAlgorithm, SignatureScheme};
use crate::error::Error;
use crate::sync::Arc;
use crate::webpki::WebPkiSupportedAlgorithms;

mod expanded;
mod pkcs8;

use pkcs8::PrivateKey;

/// A parameter set of `ml-dsa` with what [`expanded`] needs of it.
trait ParameterSet: MlDsaParams {
    const EXPANDED: expanded::ParameterSet;
}

impl ParameterSet for MlDsa44 {
    const EXPANDED: expanded::ParameterSet = expanded::ML_DSA_44;
}

impl ParameterSet for MlDsa65 {
    const EXPANDED: expanded::ParameterSet = expanded::ML_DSA_65;
}

impl ParameterSet for MlDsa87 {
    const EXPANDED: expanded::ParameterSet = expanded::ML_DSA_87;
}

/// A key of one parameter set.
#[derive(Clone)]
enum Key {
    MlDsa44(Arc<ExpandedSigningKey<MlDsa44>>),
    MlDsa65(Arc<ExpandedSigningKey<MlDsa65>>),
    MlDsa87(Arc<ExpandedSigningKey<MlDsa87>>),
}

impl Key {
    fn scheme(&self) -> SignatureScheme {
        match self {
            Self::MlDsa44(_) => SignatureScheme::ML_DSA_44,
            Self::MlDsa65(_) => SignatureScheme::ML_DSA_65,
            Self::MlDsa87(_) => SignatureScheme::ML_DSA_87,
        }
    }

    fn parameter_set(&self) -> &'static str {
        match self {
            Self::MlDsa44(_) => "ML-DSA-44",
            Self::MlDsa65(_) => "ML-DSA-65",
            Self::MlDsa87(_) => "ML-DSA-87",
        }
    }
}

/// The operating system's random source (`getrandom`) for `ml-dsa`'s
/// hedged signing, read through [`RustCrypto`] directly: a `secure_random`
/// that an application puts in its `CryptoProvider` is not consulted. It
/// records a failure, which `ml-dsa` reports only as an opaque signing
/// error.
struct OsRandom {
    fill: fn(&mut [u8]) -> Result<(), GetRandomFailed>,
    failed: bool,
}

impl OsRandom {
    fn new() -> Self {
        Self {
            fill: |buf| RustCrypto.fill(buf),
            failed: false,
        }
    }
}

/// The random source failed.
#[derive(Debug)]
struct RandomFailed;

impl fmt::Display for RandomFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no randomness from the operating system")
    }
}

impl core::error::Error for RandomFailed {}

impl TryRng for OsRandom {
    type Error = RandomFailed;

    fn try_next_u32(&mut self) -> Result<u32, RandomFailed> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, RandomFailed> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), RandomFailed> {
        (self.fill)(dst).map_err(|_| {
            self.failed = true;
            RandomFailed
        })
    }
}

impl TryCryptoRng for OsRandom {}

/// Hedged pure ML-DSA (FIPS 204 Algorithm 2, ML-DSA.Sign) with the empty
/// context string. `ml-dsa` draws the 32 random bytes from `rng` and fails,
/// rather than signing deterministically, when it cannot: that failure is
/// [`Error::FailedToGetRandomBytes`], any other one a generic error.
fn sign_with<P: MlDsaParams>(
    key: &ExpandedSigningKey<P>,
    message: &[u8],
    rng: &mut OsRandom,
) -> Result<Vec<u8>, Error> {
    key.sign_randomized(message, &[], rng)
        .map(|signature| signature.encode().to_vec())
        .map_err(|_| match rng.failed {
            true => Error::FailedToGetRandomBytes,
            false => Error::general("ML-DSA signing failed"),
        })
}

/// An ML-DSA-44, ML-DSA-65 or ML-DSA-87 signing key for TLS 1.3
/// (`draft-ietf-tls-mldsa-06`, an Internet-Draft: experimental), backed by
/// the RustCrypto `ml-dsa` crate.
///
/// It signs only with the scheme of its parameter set (`mldsa44`,
/// `mldsa65` or `mldsa87`, code points 0x0904 to 0x0906), and only when the
/// peer offered that scheme: pure ML-DSA (FIPS 204 Algorithm 2,
/// ML-DSA.Sign) with the empty context string, as §3.2 of the draft
/// requires. Signing is hedged with 32 fresh random bytes from the
/// operating system's random source (`getrandom`, whatever `secure_random`
/// the `CryptoProvider` holds); without them it fails with
/// [`Error::FailedToGetRandomBytes`] (there is no deterministic fallback).
/// HashML-DSA is not supported.
///
/// These schemes exist in TLS 1.3 only. [`SigningKey::algorithm`] is a
/// value outside the TLS 1.2 `SignatureAlgorithm` registry's assignments,
/// so a server holding only this key completes no TLS 1.2 handshake and a
/// client does not answer a TLS 1.2 CertificateRequest with it. The key is
/// not usable with delegated credentials (RFC 9345) or exported
/// authenticators (RFC 9261), which no specification defines for ML-DSA.
///
/// [`SigningKey::public_key`] is the RFC 9881 §4 `SubjectPublicKeyInfo`
/// (`id-ml-dsa-*` with absent parameters), so the key is matched against
/// its certificate like any other.
///
/// # Memory, stack and zeroisation
///
/// The key is held in the expanded form of `ml-dsa`: the secret vectors
/// and their NTT forms (about 24, 34 and 46 KiB for ML-DSA-44, -65 and
/// -87) and, in separate heap blocks, the public matrix (16, 30 and
/// 56 KiB), so about 40, 64 and 102 KiB a key.
///
/// `ml-dsa` builds and moves these values on the stack. In measurements of
/// ML-DSA-87 on x86-64 hosts, loading a key needed between about 260 and
/// 430 KiB of stack in optimised builds and up to about 1.25 MiB in an
/// unoptimised one; signing, on the thread that drives the handshake,
/// about 100 to 145 KiB optimised and up to about 512 KiB unoptimised.
/// Other targets and compilers differ. Load and sign on threads with that
/// much stack: where the stack has no guard page (as on many `no_std`
/// targets), running out of it is not detected. The native provider needs
/// about 20 KiB to derive a key and about 102 KiB to sign in an optimised
/// build (see `browntls_crypto::mldsa`).
///
/// Zeroisation is partial. With its `zeroize` feature, `ml-dsa` wipes the
/// stored key (the secret vectors, `K` and `tr`) when the last reference
/// to it is dropped, the seed it derives a key from, and its SHAKE states.
/// It does not wipe the temporaries of key derivation and signing (among
/// them `rho'`, the per-signature randomness, `rho''` and the mask `y`,
/// from which the private key can be computed), and loading moves the
/// expanded key by value, several times, before it rests on the heap.
/// Such copies stay on the stack until something overwrites them. The
/// native provider's implementation wipes its signing temporaries (though
/// not its SHAKE states); use it where this matters.
///
/// # Loading
///
/// Loaded from the RFC 9881 `seed`, `expandedKey` or `both` form, as in
/// the native provider: see [`any_ml_dsa_type`] for the checks, of which
/// the provider makes those of an `expandedKey` itself.
///
/// Load one with [`any_ml_dsa_type`]; [`RustCrypto`](super::RustCrypto)
/// does not load ML-DSA keys,
/// [`KEY_PROVIDER_WITH_ML_DSA`](super::KEY_PROVIDER_WITH_ML_DSA) does.
pub struct MlDsaSigningKey {
    key: Key,
    spki: SubjectPublicKeyInfoDer<'static>,
}

impl SigningKey for MlDsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&self.key.scheme()).then(|| {
            Box::new(MlDsaSigner {
                key: self.key.clone(),
            }) as Box<dyn Signer>
        })
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from_slice(self.spki.as_ref()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        NO_TLS12_SIGNATURE_ALGORITHM
    }
}

impl Debug for MlDsaSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaSigningKey")
            .field("parameter_set", &self.key.parameter_set())
            .finish_non_exhaustive()
    }
}

struct MlDsaSigner {
    key: Key,
}

impl Signer for MlDsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        match &self.key {
            Key::MlDsa44(key) => sign_with(key, message, &mut OsRandom::new()),
            Key::MlDsa65(key) => sign_with(key, message, &mut OsRandom::new()),
            Key::MlDsa87(key) => sign_with(key, message, &mut OsRandom::new()),
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.key.scheme()
    }
}

impl Debug for MlDsaSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaSigner")
            .field("parameter_set", &self.key.parameter_set())
            .finish_non_exhaustive()
    }
}

/// Whether `a` and `b` are equal, without stopping at the first difference.
fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The key of parameter set `P` in `key`, and its public key (`pkEncode`),
/// or `None` if any check fails.
fn load_set<P: ParameterSet>(
    key: &pkcs8::OneAsymmetricKey<'_>,
) -> Option<(ExpandedSigningKey<P>, Vec<u8>)> {
    let seed = |bytes: &[u8]| B32::try_from(bytes).ok().map(Zeroizing::new);
    // The public key that the checks of an `expandedKey` established.
    let mut checked = None;
    let signing_key = match key.private_key {
        PrivateKey::Seed(bytes) => ExpandedSigningKey::<P>::from_seed(&*seed(bytes)?),
        PrivateKey::Expanded(bytes) => {
            // `ml-dsa` decodes an expanded key without checking it (its
            // deprecated `from_expanded` keeps any `t0` and `tr` and
            // panics on an out-of-range `s1` or `s2` coefficient), so the
            // provider checks it first.
            checked = Some(expanded::public_key(&P::EXPANDED, bytes)?);
            let bytes = Zeroizing::new(ExpandedSigningKeyBytes::<P>::try_from(bytes).ok()?);
            #[allow(deprecated)] // Decoding what `expanded` has checked.
            ExpandedSigningKey::<P>::from_expanded(&bytes)
        }
        PrivateKey::Both {
            seed: bytes,
            expanded,
        } => {
            // RFC 9881 §8.2: the expanded key must be the one the seed
            // derives; the key used is the seed's.
            let signing_key = ExpandedSigningKey::<P>::from_seed(&*seed(bytes)?);
            #[allow(deprecated)] // Encoding only: `to_expanded` checks nothing.
            let derived = Zeroizing::new(signing_key.to_expanded());
            if !equal(derived.as_slice(), expanded) {
                return None;
            }
            signing_key
        }
    };
    let public_key = signing_key.verifying_key().encode().to_vec();
    // `ml-dsa` recomputes the public key from `rho`, `s1` and `s2`: an
    // `expandedKey` loads only if the provider's arithmetic agrees with it.
    if checked.is_some_and(|checked| checked != public_key) {
        return None;
    }
    match key.public_key {
        Some(stated) if stated != public_key.as_slice() => None,
        _ => Some((signing_key, public_key)),
    }
}

/// The RFC 9881 §4 `SubjectPublicKeyInfo` of `public_key` under `alg`.
fn spki(alg: &[u8], public_key: &[u8]) -> SubjectPublicKeyInfoDer<'static> {
    let mut contents = crate::x509::wrap_in_sequence(alg);
    contents.extend_from_slice(&crate::x509::wrap_in_bit_string(public_key));
    SubjectPublicKeyInfoDer::from(crate::x509::wrap_in_sequence(&contents))
}

fn load(der: &[u8]) -> Option<MlDsaSigningKey> {
    let key = pkcs8::parse(der)?;
    let alg = key.algorithm;
    let (key, public_key) = if alg == alg_id::ML_DSA_44.as_ref() {
        let (k, pk) = load_set::<MlDsa44>(&key)?;
        (Key::MlDsa44(Arc::new(k)), pk)
    } else if alg == alg_id::ML_DSA_65.as_ref() {
        let (k, pk) = load_set::<MlDsa65>(&key)?;
        (Key::MlDsa65(Arc::new(k)), pk)
    } else if alg == alg_id::ML_DSA_87.as_ref() {
        let (k, pk) = load_set::<MlDsa87>(&key)?;
        (Key::MlDsa87(Arc::new(k)), pk)
    } else {
        return None;
    };
    Some(MlDsaSigningKey {
        key,
        spki: spki(alg, &public_key),
    })
}

/// Loads an ML-DSA-44, ML-DSA-65 or ML-DSA-87 private key from an RFC 9881
/// §6 PKCS #8 `OneAsymmetricKey` in strict DER, in the `seed`,
/// `expandedKey` or `both` form:
///
/// * `version` 0 or 1; `privateKeyAlgorithm` `id-ml-dsa-*` with absent
///   parameters; attributes with the DER `Attribute` structure (otherwise
///   ignored); in version 1, an optional `publicKey` that must equal the
///   key's public key; nothing else, at any level.
/// * `seed`: 32 bytes, from which `ml-dsa` derives the key.
/// * `expandedKey`: the FIPS 204 private key encoding, of the parameter
///   set's length. Every `s1` and `s2` coefficient must be in range, and
///   `t0` and `tr` must be the values that `rho`, `s1` and `s2` determine;
///   the signing seed `K`, which nothing else in the key determines, is
///   taken as it is.
/// * `both`: the expanded key must equal the one derived from the seed
///   (RFC 9881 §8.2), and the seed's key is used.
///
/// These are the keys the native provider's loader
/// (`crypto::native::sign::any_ml_dsa_type`) accepts. The `ml-dsa` crate
/// offers no checked decoding of an expanded key (its deprecated decoder
/// keeps any `t0` and `tr` and panics on an out-of-range coefficient), so
/// the provider checks an `expandedKey` itself before the crate decodes
/// it: it recomputes `t = A s1 + s2` with its own arithmetic (SHAKE from
/// the `shake` crate), in time independent of the secret values, and
/// loads the key only if the crate then derives the same public key.
/// RFC 9881 recommends the `seed` form.
///
/// The key signs TLS 1.3 handshakes as [`MlDsaSigningKey`] describes
/// (`draft-ietf-tls-mldsa-06`, experimental).
/// [`any_supported_type`](sign::any_supported_type) does not call this.
///
/// Loading derives the key on the calling thread's stack: for ML-DSA-87,
/// up to about 430 KiB in optimised builds and about 1.25 MiB in an
/// unoptimised one, as measured on x86-64 (see
/// [`MlDsaSigningKey`](MlDsaSigningKey#memory-stack-and-zeroisation), also
/// for what is and is not zeroised). An `expandedKey`, which is decoded
/// rather than derived, needed about 335 KiB and 950 KiB in the same
/// measurements; the provider's checks, which run before the crate
/// decodes the key and wipe their temporaries, need under 16 KiB and
/// about 44 KiB. Call it on a thread with that much stack.
///
/// Every failure is one generic error.
pub fn any_ml_dsa_type(der: &PrivatePkcs8KeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    match load(der.secret_der()) {
        Some(key) => Ok(Arc::new(key)),
        None => Err(Error::general(
            "failed to parse PKCS#8 private key as ML-DSA",
        )),
    }
}

/// The key loader of [`KEY_PROVIDER_WITH_ML_DSA`].
#[derive(Debug)]
pub struct RustCryptoWithMlDsa;

/// The provider's key loader ([`RustCrypto`](super::RustCrypto)) that also
/// loads ML-DSA-44, -65 and -87 private keys (RFC 9881 PKCS #8) for
/// TLS 1.3 authentication: an explicit opt-in to `draft-ietf-tls-mldsa-06`,
/// an Internet-Draft, not a published RFC. See [`MlDsaSigningKey`] for
/// what such a key does, and the
/// [module documentation](super#ml-dsa-in-tls-13-opt-in-experimental) for
/// the whole opt-in.
///
/// A key is first loaded as [`RustCrypto`](super::RustCrypto) loads it
/// ([`sign::any_supported_type`]); a PKCS #8 key that fails there is tried
/// as ML-DSA ([`any_ml_dsa_type`]). When both fail, a key whose
/// `privateKeyAlgorithm` names an ML-DSA parameter set gets the ML-DSA
/// loader's error (so that, for instance, an inconsistent `both` key or an
/// `expandedKey` that fails its checks is not reported as a malformed
/// ECDSA key), and any other key the first error.
///
/// Loading an ML-DSA key needs a large stack on the calling thread (the
/// one that calls `with_single_cert`, `with_client_auth_cert` or
/// `CertifiedKey::from_der`): see [`any_ml_dsa_type`].
pub static KEY_PROVIDER_WITH_ML_DSA: &dyn KeyProvider = &RustCryptoWithMlDsa;

impl KeyProvider for RustCryptoWithMlDsa {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        sign::any_supported_type(&key_der).or_else(|err| match &key_der {
            PrivateKeyDer::Pkcs8(pkcs8) => any_ml_dsa_type(pkcs8).map_err(|ml_dsa_err| {
                if names_ml_dsa(pkcs8.secret_der()) {
                    ml_dsa_err
                } else {
                    err
                }
            }),
            _ => Err(err),
        })
    }
}

/// Whether the `privateKeyAlgorithm` of the PKCS #8 key `der` begins with an
/// `id-ml-dsa-*` object identifier (RFC 9881 §2), as the native provider
/// decides it. Only the choice of error message depends on it.
fn names_ml_dsa(der: &[u8]) -> bool {
    crate::x509::pkcs8_algorithm_identifier(der).is_some_and(|algorithm| {
        [alg_id::ML_DSA_44, alg_id::ML_DSA_65, alg_id::ML_DSA_87]
            .iter()
            .any(|id| algorithm.starts_with(id.as_ref()))
    })
}

/// The TLS 1.3 signature schemes of `draft-ietf-tls-mldsa-06` and the
/// algorithm that verifies each: `mldsa44`, `mldsa65`, `mldsa87` (0x0904,
/// 0x0905, 0x0906), in that order. Each scheme maps to the one algorithm of
/// its parameter set, whose key identifier is the matching `id-ml-dsa-*`,
/// so a signature under a scheme verifies only with a key of that
/// parameter set (§3.2 of the draft).
#[allow(clippy::type_complexity)]
pub static ML_DSA_VERIFICATION_ALG_MAPPING: &[(
    SignatureScheme,
    &[&dyn SignatureVerificationAlgorithm],
)] = &[
    (SignatureScheme::ML_DSA_44, &[&verify::ML_DSA_44]),
    (SignatureScheme::ML_DSA_65, &[&verify::ML_DSA_65]),
    (SignatureScheme::ML_DSA_87, &[&verify::ML_DSA_87]),
];

#[allow(clippy::type_complexity)]
static MAPPING_WITH_ML_DSA: [(SignatureScheme, &[&dyn SignatureVerificationAlgorithm]);
    SUPPORTED_SIG_ALGS.mapping.len() + ML_DSA_VERIFICATION_ALG_MAPPING.len()] =
    concat(SUPPORTED_SIG_ALGS.mapping, ML_DSA_VERIFICATION_ALG_MAPPING);

/// The `mapping` of [`SUPPORTED_SIG_ALGS`] followed by
/// [`ML_DSA_VERIFICATION_ALG_MAPPING`]: the TLS scheme mapping of
/// [`SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13`], computed at compile time so
/// that every default scheme stays ahead of the ML-DSA ones, in the
/// default order.
#[allow(clippy::type_complexity)]
pub static VERIFICATION_ALG_MAPPING_WITH_ML_DSA: &[(
    SignatureScheme,
    &[&dyn SignatureVerificationAlgorithm],
)] = &MAPPING_WITH_ML_DSA;

/// [`SUPPORTED_SIG_ALGS`](super::SUPPORTED_SIG_ALGS) with ML-DSA for
/// certificate paths (RFC 9881) and for TLS 1.3 handshake signatures
/// (`draft-ietf-tls-mldsa-06`): `all` is
/// [`ALL_VERIFICATION_ALGS_WITH_ML_DSA`], `mapping` is
/// [`VERIFICATION_ALG_MAPPING_WITH_ML_DSA`].
///
/// This is an explicit, experimental opt-in: the draft is not a published
/// RFC (its code points are registered with "Recommended: N"), and the
/// provider's defaults do not include ML-DSA. On top of what
/// [`SUPPORTED_SIG_ALGS_WITH_ML_DSA`](super::SUPPORTED_SIG_ALGS_WITH_ML_DSA)
/// does for X.509 validation, a provider or verifier using this table:
///
/// * offers `mldsa44`, `mldsa65` and `mldsa87` after its other schemes in
///   the `signature_algorithms` of every ClientHello that offers TLS 1.3
///   and every TLS 1.3 CertificateRequest, which every peer and observer
///   of the handshake start can see;
/// * accepts a TLS 1.3 `CertificateVerify` signed with one of them, from a
///   peer whose end-entity key is an ML-DSA key of the same parameter set
///   (pure ML-DSA, empty context string).
///
/// TLS 1.2 handshake signatures never use these schemes: they are never
/// listed in a ClientHello that offers TLS 1.2 alone or in a TLS 1.2
/// CertificateRequest, and never accepted in a TLS 1.2 `ServerKeyExchange`
/// or `CertificateVerify`. (Certificate path signatures are another
/// matter: as with `SUPPORTED_SIG_ALGS_WITH_ML_DSA`, ML-DSA-signed
/// certificates validate in every protocol version.) Delegated credentials
/// (RFC 9345) and exported authenticators (RFC 9261) never use them.
/// Signing with an ML-DSA key is a separate choice:
/// [`KEY_PROVIDER_WITH_ML_DSA`].
pub static SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13: WebPkiSupportedAlgorithms =
    WebPkiSupportedAlgorithms {
        all: ALL_VERIFICATION_ALGS_WITH_ML_DSA,
        mapping: VERIFICATION_ALG_MAPPING_WITH_ML_DSA,
    };

#[cfg(test)]
mod tests;
