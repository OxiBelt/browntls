//! Key exchange: X25519 (RFC 7748), the NIST curves (RFC 8422), ML-KEM
//! (FIPS 203, draft-ietf-tls-mlkem), the hybrid groups of
//! draft-ietf-tls-ecdhe-mlkem and the RFC 7919 finite-field groups (TLS 1.3
//! only).
//!
//! Every peer share is validated before use: exact lengths, the uncompressed
//! point format for NIST curves, full point validation (on the curve, not the
//! identity), rejection of an all-zero X25519 output (RFC 8446 §7.4.2), the
//! FIPS 203 §7.2 encapsulation-key check and `1 < Y < p - 1` for FFDHE
//! (RFC 9846 §4.3.8.1). All failures map to
//! [`PeerMisbehaved::InvalidKeyShare`].

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use browntls_crypto::curve25519::x25519;
use browntls_crypto::ffdhe;
use browntls_crypto::mlkem::{self, DecapsulationKey, EncapsulationKey, ParameterSet};
use browntls_crypto::nist::{p256, p384, p521};
use browntls_crypto::rand::OsRng;
use browntls_crypto::zeroize::zeroize_bytes;

use crate::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use crate::enums::ProtocolVersion;
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::enums::NamedGroup;
use crate::rand::GetRandomFailed;

fn invalid_share() -> Error {
    PeerMisbehaved::InvalidKeyShare.into()
}

/// Maps a key generation failure (only the random source can fail).
fn keygen_error(_: browntls_crypto::Error) -> Error {
    GetRandomFailed.into()
}

/// Copies `secret` into a [`SharedSecret`] (zeroised on drop) and wipes it.
fn shared_secret<const N: usize>(mut secret: [u8; N]) -> SharedSecret {
    let out = SharedSecret::from(&secret[..]);
    zeroize_bytes(&mut secret);
    out
}

// ---------------------------------------------------------------------------
// X25519

/// X25519 key exchange.
pub static X25519: &dyn SupportedKxGroup = &X25519_GROUP;

pub(crate) static X25519_GROUP: X25519Group = X25519Group;

/// X25519 (RFC 7748, RFC 8446 §7.4.2).
pub(crate) struct X25519Group;

impl SupportedKxGroup for X25519Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = x25519::PrivateKey::generate(&OsRng).map_err(keygen_error)?;
        let pub_key = secret.public_key();
        Ok(Box::new(X25519Kx { secret, pub_key }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl fmt::Debug for X25519Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519")
    }
}

/// The private scalar is zeroised on drop by `browntls-crypto`.
struct X25519Kx {
    secret: x25519::PrivateKey,
    pub_key: [u8; 32],
}

impl ActiveKeyExchange for X25519Kx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer: &[u8; 32] = peer_pub_key.try_into().map_err(|_| invalid_share())?;
        // `diffie_hellman` rejects an all-zero output (a low-order peer point).
        let shared = self
            .secret
            .diffie_hellman(peer)
            .map_err(|_| invalid_share())?;
        Ok(shared_secret(shared))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

// ---------------------------------------------------------------------------
// NIST curves

macro_rules! nist_group {
    ($group:ident, $kx:ident, $static_name:ident, $pub_name:ident, $curve:ident, $named:expr, $doc:literal) => {
        #[doc = concat!("ECDHE over ", $doc, ".")]
        pub static $pub_name: &dyn SupportedKxGroup = &$static_name;

        pub(crate) static $static_name: $group = $group;

        #[doc = concat!("ECDHE over ", $doc, " (RFC 8422, RFC 8446 §4.2.8.2).")]
        pub(crate) struct $group;

        impl SupportedKxGroup for $group {
            fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
                let secret = $curve::SecretKey::generate(&OsRng).map_err(keygen_error)?;
                let pub_key = secret.public_key().to_uncompressed();
                Ok(Box::new($kx { secret, pub_key }))
            }

            fn name(&self) -> NamedGroup {
                $named
            }
        }

        impl fmt::Debug for $group {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:?}", $named)
            }
        }

        /// The private scalar is zeroised on drop by `browntls-crypto`.
        struct $kx {
            secret: $curve::SecretKey,
            pub_key: [u8; $curve::UNCOMPRESSED_LEN],
        }

        impl ActiveKeyExchange for $kx {
            fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
                // RFC 8446 §4.2.8.2 / RFC 8422 §5.1.2: only the uncompressed
                // form is negotiated, so anything else is invalid.
                if peer_pub_key.len() != $curve::UNCOMPRESSED_LEN || peer_pub_key[0] != 0x04 {
                    return Err(invalid_share());
                }
                // Validates the coordinates and that the point is on the curve.
                let peer = $curve::PublicKey::from_sec1_bytes(peer_pub_key)
                    .map_err(|_| invalid_share())?;
                let shared = self
                    .secret
                    .diffie_hellman(&peer)
                    .map_err(|_| invalid_share())?;
                Ok(shared_secret(shared))
            }

            fn pub_key(&self) -> &[u8] {
                &self.pub_key
            }

            fn group(&self) -> NamedGroup {
                $named
            }
        }
    };
}

nist_group!(
    P256Group,
    P256Kx,
    SECP256R1_GROUP,
    SECP256R1,
    p256,
    NamedGroup::secp256r1,
    "secp256r1 (P-256)"
);
nist_group!(
    P384Group,
    P384Kx,
    SECP384R1_GROUP,
    SECP384R1,
    p384,
    NamedGroup::secp384r1,
    "secp384r1 (P-384)"
);
nist_group!(
    P521Group,
    P521Kx,
    SECP521R1_GROUP,
    SECP521R1,
    p521,
    NamedGroup::secp521r1,
    "secp521r1 (P-521)"
);

// ---------------------------------------------------------------------------
// ML-KEM

/// ML-KEM-768 used alone (TLS 1.3 only).
pub static MLKEM768: &dyn SupportedKxGroup = &MLKEM768_GROUP;
/// ML-KEM-1024 used alone (TLS 1.3 only).
pub static MLKEM1024: &dyn SupportedKxGroup = &MLKEM1024_GROUP;

pub(crate) static MLKEM768_GROUP: MlKemGroup<mlkem::MlKem768> = MlKemGroup {
    name: NamedGroup::MLKEM768,
    _params: PhantomData,
};
pub(crate) static MLKEM1024_GROUP: MlKemGroup<mlkem::MlKem1024> = MlKemGroup {
    name: NamedGroup::MLKEM1024,
    _params: PhantomData,
};

/// ML-KEM as a key exchange: the client offers an encapsulation key, the
/// server answers with a ciphertext.
pub(crate) struct MlKemGroup<P> {
    name: NamedGroup,
    _params: PhantomData<P>,
}

impl<P: ParameterSet + Send + Sync + 'static> MlKemGroup<P> {
    /// The server side: validates the client's encapsulation key and
    /// encapsulates to it, returning the ciphertext and the shared secret.
    fn encapsulate(client_share: &[u8]) -> Result<(Vec<u8>, SharedSecret), Error> {
        if client_share.len() != P::ENCAPSULATION_KEY_LEN {
            return Err(invalid_share());
        }
        // FIPS 203 §7.2 length and modulus checks.
        let ek = EncapsulationKey::<P>::from_bytes(client_share).map_err(|_| invalid_share())?;
        let (ct, ss) = ek.encapsulate(&OsRng).map_err(keygen_error)?;
        Ok((ct.as_ref().to_vec(), shared_secret(ss)))
    }
}

impl<P: ParameterSet + Send + Sync + 'static> SupportedKxGroup for MlKemGroup<P>
where
    DecapsulationKey<P>: Send + Sync,
{
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let (dk, ek) = DecapsulationKey::<P>::generate(&OsRng).map_err(keygen_error)?;
        Ok(Box::new(MlKemKx {
            dk: Box::new(dk),
            pub_key: ek.as_bytes().to_vec(),
            name: self.name,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (pub_key, secret) = Self::encapsulate(client_share)?;
        Ok(CompletedKeyExchange {
            group: self.name,
            pub_key,
            secret,
        })
    }

    fn name(&self) -> NamedGroup {
        self.name
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

impl<P> fmt::Debug for MlKemGroup<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.name)
    }
}

/// The client side of ML-KEM. The decapsulation key is zeroised on drop by
/// `browntls-crypto`.
struct MlKemKx<P: ParameterSet> {
    dk: Box<DecapsulationKey<P>>,
    pub_key: Vec<u8>,
    name: NamedGroup,
}

impl<P: ParameterSet + Send + Sync + 'static> ActiveKeyExchange for MlKemKx<P>
where
    DecapsulationKey<P>: Send + Sync,
{
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != P::CIPHERTEXT_LEN {
            return Err(invalid_share());
        }
        // A well-sized but invalid ciphertext yields the implicit-rejection
        // secret, so the handshake fails later at Finished (FIPS 203 §6.3).
        let ss = self
            .dk
            .decapsulate(peer_pub_key)
            .map_err(|_| invalid_share())?;
        Ok(shared_secret(ss))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        self.name
    }
}

// ---------------------------------------------------------------------------
// Hybrid groups

/// The draft-ietf-tls-ecdhe-mlkem code point of `SecP384r1MLKEM1024`.
///
/// [`NamedGroup`] has no named variant for it yet; it is resolved through
/// `NamedGroup::from` so that it compares equal to a named variant if one is
/// added later.
pub const SECP384R1MLKEM1024_CODEPOINT: u16 = 0x11ed;

/// X25519 combined with ML-KEM-768 (TLS 1.3 only).
pub static X25519MLKEM768: &dyn SupportedKxGroup = &X25519MLKEM768_GROUP;
/// secp256r1 combined with ML-KEM-768 (TLS 1.3 only).
pub static SECP256R1MLKEM768: &dyn SupportedKxGroup = &SECP256R1MLKEM768_GROUP;
/// secp384r1 combined with ML-KEM-1024 (TLS 1.3 only), code point
/// [`SECP384R1MLKEM1024_CODEPOINT`].
pub static SECP384R1MLKEM1024: &dyn SupportedKxGroup = &SECP384R1MLKEM1024_GROUP;

/// The ML-KEM half of a hybrid group.
pub(crate) trait PqComponent: Send + Sync + 'static {
    const CLIENT_SHARE_LEN: usize;
    const SERVER_SHARE_LEN: usize;
    fn group(&self) -> &'static dyn SupportedKxGroup;
    fn encapsulate(&self, client_share: &[u8]) -> Result<(Vec<u8>, SharedSecret), Error>;
}

pub(crate) struct Pq<P>(PhantomData<P>);

impl PqComponent for Pq<mlkem::MlKem768> {
    const CLIENT_SHARE_LEN: usize = mlkem::MlKem768::ENCAPSULATION_KEY_LEN;
    const SERVER_SHARE_LEN: usize = mlkem::MlKem768::CIPHERTEXT_LEN;

    fn group(&self) -> &'static dyn SupportedKxGroup {
        &MLKEM768_GROUP
    }

    fn encapsulate(&self, client_share: &[u8]) -> Result<(Vec<u8>, SharedSecret), Error> {
        MlKemGroup::<mlkem::MlKem768>::encapsulate(client_share)
    }
}

impl PqComponent for Pq<mlkem::MlKem1024> {
    const CLIENT_SHARE_LEN: usize = mlkem::MlKem1024::ENCAPSULATION_KEY_LEN;
    const SERVER_SHARE_LEN: usize = mlkem::MlKem1024::CIPHERTEXT_LEN;

    fn group(&self) -> &'static dyn SupportedKxGroup {
        &MLKEM1024_GROUP
    }

    fn encapsulate(&self, client_share: &[u8]) -> Result<(Vec<u8>, SharedSecret), Error> {
        MlKemGroup::<mlkem::MlKem1024>::encapsulate(client_share)
    }
}

/// A classical group combined with ML-KEM (draft-ietf-tls-ecdhe-mlkem §3).
///
/// Shares and the shared secret are the concatenation of both components;
/// X25519MLKEM768 puts the ML-KEM part first, the NIST hybrids put the ECDH
/// part first.
pub(crate) struct Hybrid<Q> {
    classical: &'static dyn SupportedKxGroup,
    classical_share_len: usize,
    pq: Q,
    code_point: u16,
    pq_first: bool,
}

pub(crate) static X25519MLKEM768_GROUP: Hybrid<Pq<mlkem::MlKem768>> = Hybrid {
    classical: &X25519_GROUP,
    classical_share_len: 32,
    pq: Pq(PhantomData),
    code_point: 0x11ec,
    pq_first: true,
};

pub(crate) static SECP256R1MLKEM768_GROUP: Hybrid<Pq<mlkem::MlKem768>> = Hybrid {
    classical: &SECP256R1_GROUP,
    classical_share_len: p256::UNCOMPRESSED_LEN,
    pq: Pq(PhantomData),
    code_point: 0x11eb,
    pq_first: false,
};

pub(crate) static SECP384R1MLKEM1024_GROUP: Hybrid<Pq<mlkem::MlKem1024>> = Hybrid {
    classical: &SECP384R1_GROUP,
    classical_share_len: p384::UNCOMPRESSED_LEN,
    pq: Pq(PhantomData),
    code_point: SECP384R1MLKEM1024_CODEPOINT,
    pq_first: false,
};

impl<Q: PqComponent> Hybrid<Q> {
    /// Splits a peer share of exactly `classical_share_len + pq_len` bytes
    /// into `(pq, classical)`.
    fn split<'a>(&self, share: &'a [u8], pq_len: usize) -> Result<(&'a [u8], &'a [u8]), Error> {
        if share.len() != self.classical_share_len + pq_len {
            return Err(invalid_share());
        }
        Ok(if self.pq_first {
            share.split_at(pq_len)
        } else {
            let (classical, pq) = share.split_at(self.classical_share_len);
            (pq, classical)
        })
    }

    /// Concatenates the two components in this group's order.
    fn concat(&self, pq: &[u8], classical: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(pq.len() + classical.len());
        if self.pq_first {
            out.extend_from_slice(pq);
            out.extend_from_slice(classical);
        } else {
            out.extend_from_slice(classical);
            out.extend_from_slice(pq);
        }
        out
    }
}

impl<Q: PqComponent> SupportedKxGroup for Hybrid<Q> {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = self.classical.start()?;
        let pq = self.pq.group().start()?;
        let pub_key = self.concat(pq.pub_key(), classical.pub_key());
        Ok(Box::new(ActiveHybrid {
            classical,
            pq,
            pub_key,
            name: self.name(),
            classical_share_len: self.classical_share_len,
            server_pq_len: Q::SERVER_SHARE_LEN,
            pq_first: self.pq_first,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (pq_share, classical_share) = self.split(client_share, Q::CLIENT_SHARE_LEN)?;
        let classical = self.classical.start_and_complete(classical_share)?;
        let (ct, pq_secret) = self.pq.encapsulate(pq_share)?;
        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: self.concat(&ct, &classical.pub_key),
            secret: SharedSecret::from(
                self.concat(pq_secret.secret_bytes(), classical.secret.secret_bytes()),
            ),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::from(self.code_point)
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

impl<Q> fmt::Debug for Hybrid<Q> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match NamedGroup::from(self.code_point) {
            NamedGroup::Unknown(_) if self.code_point == SECP384R1MLKEM1024_CODEPOINT => {
                f.write_str("SecP384r1MLKEM1024")
            }
            name => write!(f, "{name:?}"),
        }
    }
}

struct ActiveHybrid {
    classical: Box<dyn ActiveKeyExchange>,
    pq: Box<dyn ActiveKeyExchange>,
    pub_key: Vec<u8>,
    name: NamedGroup,
    classical_share_len: usize,
    server_pq_len: usize,
    pq_first: bool,
}

impl ActiveKeyExchange for ActiveHybrid {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != self.classical_share_len + self.server_pq_len {
            return Err(invalid_share());
        }
        let (first, second) = peer_pub_key.split_at(if self.pq_first {
            self.server_pq_len
        } else {
            self.classical_share_len
        });
        let (pq_share, classical_share) = if self.pq_first {
            (first, second)
        } else {
            (second, first)
        };
        let pq = self.pq.complete(pq_share)?;
        let classical = self.classical.complete(classical_share)?;
        let (a, b) = if self.pq_first {
            (pq.secret_bytes(), classical.secret_bytes())
        } else {
            (classical.secret_bytes(), pq.secret_bytes())
        };
        let mut secret = Vec::with_capacity(a.len() + b.len());
        secret.extend_from_slice(a);
        secret.extend_from_slice(b);
        Ok(SharedSecret::from(secret))
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.classical.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        self.name
    }
}

// ---------------------------------------------------------------------------
// Finite-field groups (RFC 7919)

/// FFDHE over ffdhe2048 (RFC 7919, TLS 1.3 only).
pub static FFDHE2048: &dyn SupportedKxGroup = &FFDHE2048_GROUP;
/// FFDHE over ffdhe3072 (RFC 7919, TLS 1.3 only).
pub static FFDHE3072: &dyn SupportedKxGroup = &FFDHE3072_GROUP;
/// FFDHE over ffdhe4096 (RFC 7919, TLS 1.3 only).
pub static FFDHE4096: &dyn SupportedKxGroup = &FFDHE4096_GROUP;
/// FFDHE over ffdhe6144 (RFC 7919, TLS 1.3 only).
pub static FFDHE6144: &dyn SupportedKxGroup = &FFDHE6144_GROUP;
/// FFDHE over ffdhe8192 (RFC 7919, TLS 1.3 only).
pub static FFDHE8192: &dyn SupportedKxGroup = &FFDHE8192_GROUP;

pub(crate) static FFDHE2048_GROUP: FfdheGroup = FfdheGroup {
    group: ffdhe::Group::Ffdhe2048,
    name: NamedGroup::FFDHE2048,
};
pub(crate) static FFDHE3072_GROUP: FfdheGroup = FfdheGroup {
    group: ffdhe::Group::Ffdhe3072,
    name: NamedGroup::FFDHE3072,
};
pub(crate) static FFDHE4096_GROUP: FfdheGroup = FfdheGroup {
    group: ffdhe::Group::Ffdhe4096,
    name: NamedGroup::FFDHE4096,
};
pub(crate) static FFDHE6144_GROUP: FfdheGroup = FfdheGroup {
    group: ffdhe::Group::Ffdhe6144,
    name: NamedGroup::FFDHE6144,
};
pub(crate) static FFDHE8192_GROUP: FfdheGroup = FfdheGroup {
    group: ffdhe::Group::Ffdhe8192,
    name: NamedGroup::FFDHE8192,
};

/// Finite-field Diffie-Hellman over an RFC 7919 group (RFC 9846 §4.3.8.1,
/// §7.4.1).
///
/// Shares are `Y = 2^x mod p` and the secret is `Z = Y^x mod p`, both
/// left-padded to the length of `p` (256 to 1024 bytes); in TLS 1.3 the
/// secret keeps its leading zeros. Usable for TLS 1.3 only: RFC 10015 §3
/// forbids FFDHE in TLS 1.2 (and this provider has no DHE cipher suites).
pub(crate) struct FfdheGroup {
    group: ffdhe::Group,
    name: NamedGroup,
}

impl FfdheGroup {
    fn generate(&self) -> Result<FfdheKx, Error> {
        let secret = ffdhe::PrivateKey::generate(self.group, &OsRng).map_err(keygen_error)?;
        let mut pub_key = alloc::vec![0u8; self.group.element_len()];
        // Only fails for a wrongly sized buffer.
        secret
            .public_key(&mut pub_key)
            .map_err(|_| Error::general("FFDHE public key computation failed"))?;
        Ok(FfdheKx {
            secret,
            pub_key,
            name: self.name,
        })
    }
}

impl SupportedKxGroup for FfdheGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        Ok(Box::new(self.generate()?))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        // Reject an invalid share before spending an exponentiation on our
        // own key pair.
        self.group
            .validate_public_key(client_share)
            .map_err(|_| invalid_share())?;
        let kx = self.generate()?;
        let secret = kx.agree(client_share)?;
        Ok(CompletedKeyExchange {
            group: self.name,
            pub_key: kx.pub_key,
            secret,
        })
    }

    fn name(&self) -> NamedGroup {
        self.name
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

impl fmt::Debug for FfdheGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.name)
    }
}

/// The private exponent is zeroised on drop by `browntls-crypto`.
struct FfdheKx {
    secret: ffdhe::PrivateKey,
    pub_key: Vec<u8>,
    name: NamedGroup,
}

impl FfdheKx {
    /// Validates `peer` (exact length, `1 < Y < p - 1`) and computes the
    /// left-padded `Z` (RFC 9846 §7.4.1).
    fn agree(&self, peer: &[u8]) -> Result<SharedSecret, Error> {
        let mut secret = alloc::vec![0u8; self.secret.group().element_len()];
        match self.secret.diffie_hellman(peer, &mut secret) {
            Ok(()) => Ok(SharedSecret::from(secret)),
            Err(_) => {
                zeroize_bytes(&mut secret);
                Err(invalid_share())
            }
        }
    }
}

impl ActiveKeyExchange for FfdheKx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        self.agree(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> [&'static dyn SupportedKxGroup; 9] {
        [
            X25519,
            SECP256R1,
            SECP384R1,
            SECP521R1,
            MLKEM768,
            MLKEM1024,
            X25519MLKEM768,
            SECP256R1MLKEM768,
            SECP384R1MLKEM1024,
        ]
    }

    #[test]
    fn all_groups_agree() {
        for group in all() {
            let client = group.start().unwrap();
            assert_eq!(client.group(), group.name());
            let server = group.start_and_complete(client.pub_key()).unwrap();
            assert_eq!(server.group, group.name());
            let client_secret = client.complete(&server.pub_key).unwrap();
            assert_eq!(client_secret.secret_bytes(), server.secret.secret_bytes());
        }
    }

    #[test]
    fn share_and_secret_lengths() {
        let cases: [(&dyn SupportedKxGroup, usize, usize, usize); 9] = [
            (X25519, 32, 32, 32),
            (SECP256R1, 65, 65, 32),
            (SECP384R1, 97, 97, 48),
            (SECP521R1, 133, 133, 66),
            (MLKEM768, 1184, 1088, 32),
            (MLKEM1024, 1568, 1568, 32),
            (X25519MLKEM768, 1216, 1120, 64),
            (SECP256R1MLKEM768, 1249, 1153, 64),
            (SECP384R1MLKEM1024, 1665, 1665, 80),
        ];
        for (group, client_len, server_len, secret_len) in cases {
            let client = group.start().unwrap();
            assert_eq!(client.pub_key().len(), client_len, "{group:?}");
            let server = group.start_and_complete(client.pub_key()).unwrap();
            assert_eq!(server.pub_key.len(), server_len, "{group:?}");
            assert_eq!(server.secret.secret_bytes().len(), secret_len, "{group:?}");
        }
        assert_eq!(
            SECP384R1MLKEM1024.name(),
            NamedGroup::from(SECP384R1MLKEM1024_CODEPOINT)
        );
        assert_eq!(
            alloc::format!("{SECP384R1MLKEM1024:?}"),
            "secp384r1MLKEM1024"
        );
        assert_eq!(SECP384R1MLKEM1024.name(), NamedGroup::secp384r1MLKEM1024);
        assert_eq!(alloc::format!("{X25519MLKEM768:?}"), "X25519MLKEM768");
    }

    #[test]
    fn version_restrictions() {
        for group in [X25519, SECP256R1, SECP384R1, SECP521R1] {
            assert!(group.usable_for_version(ProtocolVersion::TLSv1_2));
        }
        for group in [
            MLKEM768,
            MLKEM1024,
            X25519MLKEM768,
            SECP256R1MLKEM768,
            SECP384R1MLKEM1024,
        ] {
            assert!(!group.usable_for_version(ProtocolVersion::TLSv1_2));
            assert!(group.usable_for_version(ProtocolVersion::TLSv1_3));
        }
    }

    #[test]
    fn hybrid_components() {
        for (hybrid, classical, offset) in [
            (X25519MLKEM768, X25519, 1184),
            (SECP256R1MLKEM768, SECP256R1, 0),
            (SECP384R1MLKEM1024, SECP384R1, 0),
        ] {
            let kx = hybrid.start().unwrap();
            let (group, share) = kx.hybrid_component().unwrap();
            assert_eq!(group, classical.name());
            assert_eq!(share, &kx.pub_key()[offset..offset + share.len()]);
            let server = classical.start_and_complete(share).unwrap();
            let secret = kx.complete_hybrid_component(&server.pub_key).unwrap();
            assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
        }
    }

    #[test]
    fn bad_peer_shares_are_rejected() {
        let invalid = invalid_share();
        let check = |group: &dyn SupportedKxGroup, share: &[u8]| {
            assert_eq!(
                group.start().unwrap().complete(share).unwrap_err(),
                invalid,
                "{group:?} client accepted {} bytes",
                share.len()
            );
        };
        let check_server = |group: &dyn SupportedKxGroup, share: &[u8]| {
            assert_eq!(
                group.start_and_complete(share).unwrap_err(),
                invalid,
                "{group:?} server accepted {} bytes",
                share.len()
            );
        };

        // Wrong lengths, including empty input.
        for group in all() {
            let client = group.start().unwrap();
            let len = group
                .start_and_complete(client.pub_key())
                .unwrap()
                .pub_key
                .len();
            for bad in [0, 1, len - 1, len + 1] {
                check(group, &alloc::vec![4u8; bad]);
            }
            let len = client.pub_key().len();
            for bad in [0, 1, len - 1, len + 1] {
                check_server(group, &alloc::vec![4u8; bad]);
            }
        }

        // X25519: the all-zero point and the other low-order points give an
        // all-zero shared secret.
        let mut order_two = [0u8; 32];
        order_two[0] = 1;
        for point in [[0u8; 32], order_two] {
            check(X25519, &point);
            check_server(X25519, &point);
        }

        // NIST: compressed or hybrid encodings, the point at infinity,
        // coordinates >= p, and points off the curve.
        for (group, len) in [(SECP256R1, 65), (SECP384R1, 97), (SECP521R1, 133)] {
            let good = group.start().unwrap().pub_key().to_vec();
            let mut compressed = good[..(len - 1) / 2 + 1].to_vec();
            compressed[0] = 0x02 | (good[len - 1] & 1);
            check(group, &compressed);
            let mut hybrid_form = good.clone();
            hybrid_form[0] = 0x06 | (good[len - 1] & 1);
            check(group, &hybrid_form);
            let mut infinity = alloc::vec![0u8; len];
            infinity[0] = 0x04;
            check(group, &infinity);
            let mut big = alloc::vec![0xffu8; len];
            big[0] = 0x04;
            check(group, &big);
            let mut off_curve = good.clone();
            off_curve[len - 1] ^= 1;
            check(group, &off_curve);
            check_server(group, &off_curve);
        }

        // Hybrid: an invalid classical half is rejected even when the ML-KEM
        // half is well formed.
        let client = X25519MLKEM768.start().unwrap();
        let mut share = client.pub_key().to_vec();
        share[1184..].fill(0);
        check_server(X25519MLKEM768, &share);
        let server = X25519MLKEM768.start_and_complete(client.pub_key()).unwrap();
        let mut reply = server.pub_key.clone();
        reply[1088..].fill(0);
        assert_eq!(client.complete(&reply).unwrap_err(), invalid);

        let client = SECP256R1MLKEM768.start().unwrap();
        let mut share = client.pub_key().to_vec();
        share[64] ^= 1;
        check_server(SECP256R1MLKEM768, &share);

        // ML-KEM: an encapsulation key with a coefficient >= q fails the
        // FIPS 203 §7.2 modulus check.
        check_server(MLKEM768, &[0xff; 1184]);
        check_server(MLKEM1024, &[0xff; 1568]);
        let mut share = SECP384R1MLKEM1024.start().unwrap().pub_key().to_vec();
        share[97..97 + 12].fill(0xff);
        check_server(SECP384R1MLKEM1024, &share);
    }

    #[test]
    fn mlkem_tampered_ciphertext_gives_different_secret() {
        let client = MLKEM768.start().unwrap();
        let server = MLKEM768.start_and_complete(client.pub_key()).unwrap();
        let mut ct = server.pub_key.clone();
        ct[0] ^= 1;
        let secret = client.complete(&ct).unwrap();
        assert_ne!(secret.secret_bytes(), server.secret.secret_bytes());
    }

    fn ffdhe_groups() -> [(&'static dyn SupportedKxGroup, NamedGroup, usize); 5] {
        [
            (FFDHE2048, NamedGroup::FFDHE2048, 256),
            (FFDHE3072, NamedGroup::FFDHE3072, 384),
            (FFDHE4096, NamedGroup::FFDHE4096, 512),
            (FFDHE6144, NamedGroup::FFDHE6144, 768),
            (FFDHE8192, NamedGroup::FFDHE8192, 1024),
        ]
    }

    #[test]
    fn ffdhe_groups_agree_with_fixed_lengths_in_tls13_only() {
        for (group, name, len) in ffdhe_groups() {
            assert_eq!(group.name(), name);
            assert_eq!(alloc::format!("{group:?}"), alloc::format!("{name:?}"));
            assert!(group.usable_for_version(ProtocolVersion::TLSv1_3));
            assert!(!group.usable_for_version(ProtocolVersion::TLSv1_2));
            let client = group.start().unwrap();
            assert_eq!(client.group(), name);
            assert_eq!(client.pub_key().len(), len);
            assert!(client.hybrid_component().is_none());
            let server = group.start_and_complete(client.pub_key()).unwrap();
            assert_eq!(server.group, name);
            assert_eq!(server.pub_key.len(), len);
            assert_eq!(server.secret.secret_bytes().len(), len);
            let secret = client
                .complete_for_tls_version(&server.pub_key, &crate::versions::TLS13)
                .unwrap();
            assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
        }
    }

    #[test]
    fn ffdhe_tls13_secret_keeps_leading_zeros() {
        // RFC 9846 §7.4.1: Z is left-padded to the size of p, unlike TLS 1.2.
        // About one exchange in 256 has a leading zero byte.
        for _ in 0..4096 {
            let client = FFDHE2048.start().unwrap();
            let server = FFDHE2048.start_and_complete(client.pub_key()).unwrap();
            if server.secret.secret_bytes()[0] != 0 {
                continue;
            }
            let secret = client
                .complete_for_tls_version(&server.pub_key, &crate::versions::TLS13)
                .unwrap();
            assert_eq!(secret.secret_bytes().len(), 256);
            assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
            return;
        }
        panic!("no FFDHE secret with a leading zero byte in 4096 exchanges");
    }

    #[test]
    fn ffdhe_invalid_shares_are_rejected_by_both_sides() {
        let invalid = invalid_share();
        for (group, _, len) in ffdhe_groups() {
            let p = ffdhe::Group::ALL
                .into_iter()
                .find(|g| g.element_len() == len)
                .unwrap()
                .prime_be();
            let mut one = alloc::vec![0u8; len];
            one[len - 1] = 1;
            let mut p_minus_one = p.to_vec();
            p_minus_one[len - 1] -= 1;
            let mut p_plus_one = p.to_vec();
            for b in p_plus_one.iter_mut().rev() {
                let (sum, carry) = b.overflowing_add(1);
                *b = sum;
                if !carry {
                    break;
                }
            }
            let good = group.start().unwrap().pub_key().to_vec();
            let mut long = alloc::vec![0u8];
            long.extend_from_slice(&good);
            let shares: [&[u8]; 9] = [
                &alloc::vec![0u8; len],
                &one,
                &p_minus_one,
                p,
                &p_plus_one,
                &alloc::vec![0xffu8; len],
                &good[1..],
                &long,
                &[],
            ];
            for share in shares {
                assert_eq!(
                    group.start().unwrap().complete(share).unwrap_err(),
                    invalid,
                    "{group:?} client accepted a {}-byte share",
                    share.len()
                );
                assert_eq!(
                    group.start_and_complete(share).unwrap_err(),
                    invalid,
                    "{group:?} server accepted a {}-byte share",
                    share.len()
                );
            }
        }
    }
}
