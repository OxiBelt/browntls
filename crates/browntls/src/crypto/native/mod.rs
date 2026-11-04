//! The default [`CryptoProvider`], backed by `browntls-crypto`.
//!
//! Everything here is plain static data, so any item can be combined with
//! items from another provider (or an application's own implementation) to
//! build a mixed provider:
//!
//! ```
//! # #[cfg(feature = "rustcrypto")] {
//! use browntls::crypto::{native, rustcrypto};
//!
//! // Native record protection, hashing and key exchange, with RustCrypto
//! // certificate and handshake signature verification and key loading.
//! let mut provider = native::default_provider();
//! provider.signature_verification_algorithms = rustcrypto::SUPPORTED_SIG_ALGS;
//! provider.key_provider = &rustcrypto::RustCrypto;
//! # let _ = provider;
//! # }
//! ```
//!
//! | Item | Backing |
//! |---|---|
//! | [`cipher_suite`] | SHA-2, HMAC, HKDF, the TLS 1.2 PRF, AES-GCM, ChaCha20-Poly1305 and AES-CCM from `browntls_crypto::{hash, hmac, hkdf, tls12_prf, gcm, chacha, ccm}` |
//! | [`kx_group`] | `browntls_crypto::{curve25519::x25519, curve448::x448, nist, mlkem, ffdhe}` |
//! | [`SUPPORTED_SIG_ALGS`] | `browntls_crypto::{nist, curve25519::ed25519, curve448::ed448, rsa}` |
//! | [`KEY_PROVIDER`] ([`sign`]) | ECDSA, Ed25519, Ed448 and RSA signing keys from `browntls-crypto` |
//! | [`SECURE_RANDOM`] | `browntls_crypto::rand::OsRng` |
//! | [`ticketer`] | AES-256-GCM from `browntls_crypto::gcm` |
//!
//! The random source, `browntls_crypto::rand::OsRng`, issues `getrandom(2)`
//! directly on Linux x86-64, aarch64 and riscv64. Other targets need
//! `browntls-crypto`'s `getrandom` feature.
//!
//! Nothing here claims FIPS validation.
//!
//! # Hardware acceleration
//!
//! The primitives select accelerated backends at run time under a
//! process-wide policy per algorithm family, re-exported here as [`accel`].
//! Acceleration comes in two kinds, each with its own level (`Required`,
//! `Preferred` (default) or `None`):
//!
//! * SIMD: AVX2/AVX-512, NEON, RVV vector units.
//! * Dedicated instructions: AES-NI, PCLMULQDQ, SHA, Armv8 AES/PMULL/SHA,
//!   RISC-V Zk\*/Zvk\*, and scalar multi-precision extensions (BMI2/ADX).
//!
//! [`accel::status_all`], [`accel::accelerated`] and
//! [`accel::accelerated_by`] report what is in use.
//!
//! ```
//! use browntls::crypto::native::{self, accel::{self, Acceleration, Algorithm, Kind, Policy}};
//!
//! // Which algorithms run accelerated right now, and how?
//! for s in accel::accelerated() {
//!     println!("{s}"); // e.g. "AES: AES-NI [uses dedicated] (...)"
//! }
//!
//! // Never use the SIMD units, but keep dedicated instructions such as AES-NI.
//! let provider = native::default_provider_with_acceleration(Policy::new(
//!     Acceleration::None,
//!     Acceleration::Preferred,
//! ))?;
//! # let _ = provider;
//!
//! // Require dedicated AES instructions, or fail at start-up.
//! if accel::set_kind(Algorithm::Aes, Kind::Dedicated, Acceleration::Required).is_err() {
//!     // No AES instructions on this CPU: decide what to do (here: continue).
//! }
//! # accel::set_policy_all(Policy::PREFERRED).unwrap();
//! # Ok::<(), browntls::Error>(())
//! ```
//!
//! Keys select their backend when created, so set policies before building
//! configurations and connections.

use browntls_crypto::rand::{OsRng, SecureRandom as _};
use browntls_pki::{PrivateKeyDer, SignatureVerificationAlgorithm};

use crate::Error;
use crate::crypto::{CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom, SupportedKxGroup};
use crate::enums::SignatureScheme;
use crate::sign::SigningKey;
use crate::suites::SupportedCipherSuite;
use crate::sync::Arc;
use crate::webpki::WebPkiSupportedAlgorithms;

pub mod aead;
pub mod hash;
pub mod hkdf;
pub mod hmac;
#[cfg(feature = "tls12")]
pub mod prf;
pub mod sign;
pub mod ticketer;
pub mod verify;

pub(crate) mod ccm;
pub(crate) mod kx;
#[cfg(feature = "tls12")]
pub(crate) mod tls12;
pub(crate) mod tls13;

/// The provider with [`DEFAULT_CIPHER_SUITES`], [`DEFAULT_KX_GROUPS`],
/// [`SUPPORTED_SIG_ALGS`], [`SECURE_RANDOM`] and [`KEY_PROVIDER`].
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: DEFAULT_CIPHER_SUITES.to_vec(),
        kx_groups: DEFAULT_KX_GROUPS.to_vec(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: SECURE_RANDOM,
        key_provider: KEY_PROVIDER,
    }
}

/// Acceleration policy and status of the primitives behind this provider
/// (`browntls_crypto::accel`).
pub use browntls_crypto::accel;

/// [`default_provider`] after applying `policy` (SIMD and dedicated-
/// instruction levels) to every algorithm family of [`accel`].
///
/// The policy is process-wide and also affects other users of
/// `browntls-crypto` in the process. To set levels for selected families
/// only, use [`accel::set_policy`] or [`accel::set_kind`].
///
/// # Errors
///
/// When a kind is [`accel::Acceleration::Required`], returns
/// [`Error::General`] and changes no policy unless every family has an
/// available backend satisfying `policy` (see [`accel::status_all`]).
pub fn default_provider_with_acceleration(policy: accel::Policy) -> Result<CryptoProvider, Error> {
    accel::set_policy_all(policy).map_err(|_| {
        Error::General(alloc::string::String::from(
            "the requested hardware acceleration is not available for every algorithm",
        ))
    })?;
    Ok(default_provider())
}

/// The provider's random source and private key loader.
#[derive(Debug)]
pub struct Native;

/// The random source: the operating system's (`browntls_crypto::rand::OsRng`).
pub static SECURE_RANDOM: &dyn SecureRandom = &Native;

/// Loads ECDSA (P-256, P-384, P-521; PKCS #8 or SEC 1), Ed25519 and Ed448
/// (PKCS #8) and RSA (PKCS #8 or PKCS #1; in PKCS #8 also RSASSA-PSS keys)
/// private keys; see [`sign::any_supported_type`].
pub static KEY_PROVIDER: &dyn KeyProvider = &Native;

impl SecureRandom for Native {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        OsRng.fill(buf).map_err(|_| GetRandomFailed)
    }
}

impl KeyProvider for Native {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        sign::any_supported_type(&key_der)
    }
}

/// The cipher suites enabled by [`default_provider`], in preference order:
/// [`ALL_CIPHER_SUITES`] without `TLS13_AES_128_CCM_8_SHA256`, whose 64-bit
/// tag would weaken the default security level.
///
/// `TLS13_AES_128_CCM_SHA256` is in the non-preferred tier: after every
/// AES-GCM and ChaCha20-Poly1305 suite, so it is negotiated only with a peer
/// that shares none of those.
pub static DEFAULT_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    tls13::TLS13_AES_256_GCM_SHA384,
    tls13::TLS13_AES_128_GCM_SHA256,
    tls13::TLS13_CHACHA20_POLY1305_SHA256,
    tls13::TLS13_AES_128_CCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// Every cipher suite this provider implements, in preference order.
///
/// The TLS 1.3 suites of RFC 9846's optional, non-preferred tier,
/// `TLS13_AES_128_CCM_SHA256` and `TLS13_AES_128_CCM_8_SHA256`, follow every
/// AES-GCM and ChaCha20-Poly1305 suite.
pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    tls13::TLS13_AES_256_GCM_SHA384,
    tls13::TLS13_AES_128_GCM_SHA256,
    tls13::TLS13_CHACHA20_POLY1305_SHA256,
    tls13::TLS13_AES_128_CCM_SHA256,
    tls13::TLS13_AES_128_CCM_8_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// The individual cipher suites.
pub mod cipher_suite {
    #[cfg(feature = "tls12")]
    pub use super::tls12::{
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    pub use super::tls13::{
        TLS13_AES_128_CCM_8_SHA256, TLS13_AES_128_CCM_SHA256, TLS13_AES_128_GCM_SHA256,
        TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    };
}

/// The individual key exchange groups.
pub mod kx_group {
    pub use super::kx::{
        FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192, MLKEM768, MLKEM1024, SECP256R1,
        SECP256R1MLKEM768, SECP384R1, SECP384R1MLKEM1024, SECP384R1MLKEM1024_CODEPOINT, SECP521R1,
        X448, X25519, X25519MLKEM768,
    };
}

/// The key exchange groups enabled by [`default_provider`], in preference
/// order. With the `prefer-post-quantum` feature X25519MLKEM768 comes first;
/// otherwise it comes after the elliptic curves.
///
/// The RFC 9846 optional groups follow as a non-preferred tier, behind every
/// other group: X448 (RFC 7748), then the RFC 7919 finite-field groups,
/// usable for TLS 1.3 only (RFC 10015 §3). A client never sends their key
/// shares first; a server selects one only when the client sent no key share
/// for an earlier group and either sent one for the optional group or
/// supports no earlier group.
///
/// FFDHE6144 and FFDHE8192 are left out of the defaults (they remain in
/// [`ALL_KX_GROUPS`]): a server spends about 10 and 20 ms per handshake on
/// them, more than 100 times X25519, which a client offering only those
/// groups could exploit. FFDHE2048 to FFDHE4096 cost about 1 to 5 ms.
pub static DEFAULT_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    #[cfg(feature = "prefer-post-quantum")]
    kx::X25519MLKEM768,
    kx::X25519,
    kx::SECP256R1,
    kx::SECP384R1,
    #[cfg(not(feature = "prefer-post-quantum"))]
    kx::X25519MLKEM768,
    kx::X448,
    kx::FFDHE2048,
    kx::FFDHE3072,
    kx::FFDHE4096,
];

/// Every key exchange group this provider implements, in preference order.
///
/// As in [`DEFAULT_KX_GROUPS`], the RFC 9846 optional groups come last as a
/// non-preferred tier: X448, then FFDHE2048 to FFDHE8192 (TLS 1.3 only).
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    kx::X25519MLKEM768,
    kx::SECP256R1MLKEM768,
    kx::SECP384R1MLKEM1024,
    kx::MLKEM768,
    kx::MLKEM1024,
    kx::X25519,
    kx::SECP256R1,
    kx::SECP384R1,
    kx::SECP521R1,
    kx::X448,
    kx::FFDHE2048,
    kx::FFDHE3072,
    kx::FFDHE4096,
    kx::FFDHE6144,
    kx::FFDHE8192,
];

/// Every signature verification algorithm this provider implements, used
/// for certificate path signatures.
///
/// The non-preferred tier at the end holds the optional algorithms of
/// RFC 9846 §4.3.3: Ed448, then RSASSA-PSS with RSASSA-PSS public keys
/// (`rsa_pss_pss_*`, RFC 4055), for keys without parameters and for keys
/// restricted to one hash.
pub static ALL_VERIFICATION_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    &verify::ECDSA_P256_SHA256,
    &verify::ECDSA_P256_SHA384,
    &verify::ECDSA_P256_SHA512,
    &verify::ECDSA_P384_SHA256,
    &verify::ECDSA_P384_SHA384,
    &verify::ECDSA_P384_SHA512,
    &verify::ECDSA_P521_SHA256,
    &verify::ECDSA_P521_SHA384,
    &verify::ECDSA_P521_SHA512,
    &verify::ED25519,
    &verify::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &verify::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &verify::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &verify::RSA_PKCS1_2048_8192_SHA256,
    &verify::RSA_PKCS1_2048_8192_SHA384,
    &verify::RSA_PKCS1_2048_8192_SHA512,
    &verify::ED448,
    &verify::RSA_PSS_PSS_2048_8192_SHA512,
    &verify::RSA_PSS_PSS_2048_8192_SHA512_RESTRICTED,
    &verify::RSA_PSS_PSS_2048_8192_SHA384,
    &verify::RSA_PSS_PSS_2048_8192_SHA384_RESTRICTED,
    &verify::RSA_PSS_PSS_2048_8192_SHA256,
    &verify::RSA_PSS_PSS_2048_8192_SHA256_RESTRICTED,
];

/// How each TLS signature scheme maps onto [`ALL_VERIFICATION_ALGS`], in
/// preference order. An ECDSA scheme names a hash; in TLS 1.2 it does not bind
/// the curve, so each maps to every curve with that hash (the key's own curve
/// first). The optional RFC 9846 schemes form the non-preferred tier at the
/// end: ed448, then the `rsa_pss_pss_*` schemes, each mapping to the
/// RSASSA-PSS key without parameters and to the key restricted to the
/// scheme's hash.
#[allow(clippy::type_complexity)]
pub static VERIFICATION_ALG_MAPPING: &[(
    SignatureScheme,
    &[&dyn SignatureVerificationAlgorithm],
)] = &[
    (
        SignatureScheme::ECDSA_NISTP384_SHA384,
        &[
            &verify::ECDSA_P384_SHA384,
            &verify::ECDSA_P256_SHA384,
            &verify::ECDSA_P521_SHA384,
        ],
    ),
    (
        SignatureScheme::ECDSA_NISTP256_SHA256,
        &[
            &verify::ECDSA_P256_SHA256,
            &verify::ECDSA_P384_SHA256,
            &verify::ECDSA_P521_SHA256,
        ],
    ),
    (
        SignatureScheme::ECDSA_NISTP521_SHA512,
        &[
            &verify::ECDSA_P521_SHA512,
            &verify::ECDSA_P384_SHA512,
            &verify::ECDSA_P256_SHA512,
        ],
    ),
    (SignatureScheme::ED25519, &[&verify::ED25519]),
    (
        SignatureScheme::RSA_PSS_SHA512,
        &[&verify::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
    ),
    (
        SignatureScheme::RSA_PSS_SHA384,
        &[&verify::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
    ),
    (
        SignatureScheme::RSA_PSS_SHA256,
        &[&verify::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA512,
        &[&verify::RSA_PKCS1_2048_8192_SHA512],
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA384,
        &[&verify::RSA_PKCS1_2048_8192_SHA384],
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA256,
        &[&verify::RSA_PKCS1_2048_8192_SHA256],
    ),
    (SignatureScheme::ED448, &[&verify::ED448]),
    (
        SignatureScheme::RSA_PSS_PSS_SHA512,
        &[
            &verify::RSA_PSS_PSS_2048_8192_SHA512,
            &verify::RSA_PSS_PSS_2048_8192_SHA512_RESTRICTED,
        ],
    ),
    (
        SignatureScheme::RSA_PSS_PSS_SHA384,
        &[
            &verify::RSA_PSS_PSS_2048_8192_SHA384,
            &verify::RSA_PSS_PSS_2048_8192_SHA384_RESTRICTED,
        ],
    ),
    (
        SignatureScheme::RSA_PSS_PSS_SHA256,
        &[
            &verify::RSA_PSS_PSS_2048_8192_SHA256,
            &verify::RSA_PSS_PSS_2048_8192_SHA256_RESTRICTED,
        ],
    ),
];

/// The signature verification algorithms and their TLS scheme mapping.
pub static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: ALL_VERIFICATION_ALGS,
    mapping: VERIFICATION_ALG_MAPPING,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NamedGroup;

    #[test]
    fn provider_is_consistent() {
        let p = default_provider();
        // Everything but TLS13_AES_128_CCM_8_SHA256, in the same order.
        let without_ccm_8: alloc::vec::Vec<_> = ALL_CIPHER_SUITES
            .iter()
            .filter(|s| s.suite() != crate::CipherSuite::TLS13_AES_128_CCM_8_SHA256)
            .copied()
            .collect();
        assert_eq!(p.cipher_suites, without_ccm_8);
        assert_eq!(p.cipher_suites.len() + 1, ALL_CIPHER_SUITES.len());
        assert!(!p.kx_groups.is_empty());
        assert!(!p.fips());
        let mut buf = [0u8; 32];
        p.secure_random.fill(&mut buf).unwrap();
        assert_ne!(buf, [0u8; 32]);
        #[cfg(feature = "prefer-post-quantum")]
        assert_eq!(p.kx_groups[0].name(), NamedGroup::X25519MLKEM768);
        #[cfg(not(feature = "prefer-post-quantum"))]
        assert_eq!(p.kx_groups[0].name(), NamedGroup::X25519);
    }

    #[test]
    fn mapping_only_references_listed_algorithms() {
        for (_, algs) in VERIFICATION_ALG_MAPPING {
            for alg in *algs {
                assert!(ALL_VERIFICATION_ALGS.iter().any(|a| core::ptr::addr_eq(
                    *a as *const dyn SignatureVerificationAlgorithm,
                    *alg as *const dyn SignatureVerificationAlgorithm
                )));
            }
        }
        // Every scheme in the TLS 1.2 suite lists has a verifier.
        let schemes = SUPPORTED_SIG_ALGS.supported_schemes();
        #[cfg(feature = "tls12")]
        for scheme in crate::tls12::TLS12_ECDSA_SCHEMES
            .iter()
            .chain(crate::tls12::TLS12_RSA_SCHEMES)
        {
            assert!(schemes.contains(scheme), "{scheme:?}");
        }
        assert_eq!(schemes.len(), 14);
        // The optional schemes come last (non-preferred): ed448, then the
        // RSASSA-PSS public key schemes.
        assert_eq!(
            schemes[schemes.len() - 4..],
            [
                SignatureScheme::ED448,
                SignatureScheme::RSA_PSS_PSS_SHA512,
                SignatureScheme::RSA_PSS_PSS_SHA384,
                SignatureScheme::RSA_PSS_PSS_SHA256,
            ]
        );
    }

    #[test]
    fn optional_algorithms_are_non_preferred() {
        // The lists end with exactly the entries the server ranks last
        // (`is_non_preferred`), so list order and selection agree.
        for list in [DEFAULT_KX_GROUPS, ALL_KX_GROUPS] {
            let flags: alloc::vec::Vec<bool> =
                list.iter().map(|g| g.name().is_non_preferred()).collect();
            let first = flags.iter().position(|f| *f).unwrap();
            assert!(flags[first..].iter().all(|f| *f), "{flags:?}");
        }
        for list in [DEFAULT_CIPHER_SUITES, ALL_CIPHER_SUITES] {
            let tls13: alloc::vec::Vec<bool> = list
                .iter()
                .filter(|s| s.tls13().is_some())
                .map(|s| s.suite().is_non_preferred())
                .collect();
            let first = tls13.iter().position(|f| *f).unwrap();
            assert!(tls13[first..].iter().all(|f| *f), "{tls13:?}");
        }
        // X448, then FFDHE, follow every mandatory and recommended group.
        for list in [DEFAULT_KX_GROUPS, ALL_KX_GROUPS] {
            let pos = |n: NamedGroup| list.iter().position(|g| g.name() == n).unwrap();
            let x448 = pos(NamedGroup::X448);
            assert!(x448 < pos(NamedGroup::FFDHE2048));
            for n in [
                NamedGroup::X25519MLKEM768,
                NamedGroup::X25519,
                NamedGroup::secp256r1,
                NamedGroup::secp384r1,
            ] {
                assert!(pos(n) < x448, "{n:?}");
            }
        }
        // ed448 follows every mandatory and recommended scheme.
        let schemes = SUPPORTED_SIG_ALGS.supported_schemes();
        let pos = |s: SignatureScheme| schemes.iter().position(|x| *x == s).unwrap();
        for s in [
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ] {
            assert!(pos(s) < pos(SignatureScheme::ED448), "{s:?}");
        }
        // Identified by key type: the EdDSA verifiers are zero-sized, so
        // their addresses do not tell them apart.
        let ed448 = ALL_VERIFICATION_ALGS
            .iter()
            .position(|a| a.public_key_alg_id() == browntls_pki::alg_id::ED448)
            .unwrap();
        let existing = [
            browntls_pki::alg_id::ECDSA_P256,
            browntls_pki::alg_id::ECDSA_P384,
            browntls_pki::alg_id::ECDSA_P521,
            browntls_pki::alg_id::ED25519,
            browntls_pki::alg_id::RSA_ENCRYPTION,
        ];
        for (i, alg) in ALL_VERIFICATION_ALGS.iter().enumerate() {
            if existing.contains(&alg.public_key_alg_id()) {
                assert!(i < ed448, "{alg:?}");
            }
        }
    }

    #[test]
    fn kx_group_names_are_unique() {
        for (i, a) in ALL_KX_GROUPS.iter().enumerate() {
            for b in &ALL_KX_GROUPS[i + 1..] {
                assert_ne!(a.name(), b.name());
            }
        }
    }
}
