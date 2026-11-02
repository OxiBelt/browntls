//! Key exchange: X25519, NIST curves, ML-KEM-768 and the hybrid groups of
//! draft-ietf-tls-ecdhe-mlkem.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use ml_kem::{Decapsulate, Encapsulate as _, KeyExport, TryKeyInit as _};

use crate::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use crate::enums::ProtocolVersion;
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::enums::NamedGroup;
use crate::rand::GetRandomFailed;

fn random_bytes(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(buf).map_err(|_| GetRandomFailed.into())
}

// ---------------------------------------------------------------------------
// X25519

/// X25519 (RFC 7748).
pub(crate) struct X25519Group;

static X25519_GROUP: X25519Group = X25519Group;

/// X25519 key exchange.
pub static X25519: &dyn SupportedKxGroup = &X25519_GROUP;

impl SupportedKxGroup for X25519Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut bytes = [0u8; 32];
        random_bytes(&mut bytes)?;
        let secret = x25519_dalek::StaticSecret::from(bytes);
        crate::crypto::zeroize_slice(&mut bytes);
        let pub_key = x25519_dalek::PublicKey::from(&secret).to_bytes();
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

struct X25519Kx {
    secret: x25519_dalek::StaticSecret,
    pub_key: [u8; 32],
}

impl ActiveKeyExchange for X25519Kx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let shared = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        // RFC 8446 §7.4.2: an all-zero shared secret must be rejected.
        if !shared.was_contributory() {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(shared.as_bytes().as_slice()))
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
    ($group:ident, $kx:ident, $static_name:ident, $pub_name:ident, $krate:ident, $named:expr, $field_len:literal) => {
        /// An ECDHE group over a NIST prime curve (RFC 8422).
        pub(crate) struct $group;

        static $static_name: $group = $group;

        /// ECDHE over this curve.
        pub static $pub_name: &dyn SupportedKxGroup = &$static_name;

        impl SupportedKxGroup for $group {
            fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
                let mut bytes = [0u8; $field_len];
                // Rejection-sample a scalar in [1, n-1]. For P-521 the field
                // is 521 bits in 66 bytes, so the top seven bits are cleared
                // first; the acceptance probability is then overwhelming.
                for _ in 0..128 {
                    random_bytes(&mut bytes)?;
                    if $field_len == 66 {
                        bytes[0] &= 0x01;
                    }
                    if let Ok(secret) = $krate::SecretKey::from_slice(&bytes) {
                        use $krate::elliptic_curve::sec1::ToSec1Point;
                        crate::crypto::zeroize_slice(&mut bytes);
                        let pub_key = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
                        return Ok(Box::new($kx { secret, pub_key }));
                    }
                }
                Err(Error::general("could not generate an ECDH key pair"))
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

        struct $kx {
            secret: $krate::SecretKey,
            pub_key: Vec<u8>,
        }

        impl ActiveKeyExchange for $kx {
            fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
                // RFC 8446 §4.2.8.2: only the uncompressed point format is used.
                if peer_pub_key.len() != 2 * $field_len + 1 || peer_pub_key[0] != 0x04 {
                    return Err(PeerMisbehaved::InvalidKeyShare.into());
                }
                let peer = $krate::PublicKey::from_sec1_bytes(peer_pub_key)
                    .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
                let shared =
                    $krate::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
                Ok(SharedSecret::from(shared.raw_secret_bytes().as_slice()))
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
    32
);
nist_group!(
    P384Group,
    P384Kx,
    SECP384R1_GROUP,
    SECP384R1,
    p384,
    NamedGroup::secp384r1,
    48
);
nist_group!(
    P521Group,
    P521Kx,
    SECP521R1_GROUP,
    SECP521R1,
    p521,
    NamedGroup::secp521r1,
    66
);

// ---------------------------------------------------------------------------
// ML-KEM-768

type MlKemDk = ml_kem::ml_kem_768::DecapsulationKey;
type MlKemEk = ml_kem::ml_kem_768::EncapsulationKey;

const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_CT_LEN: usize = 1088;
const MLKEM768_SS_LEN: usize = 32;

/// ML-KEM-768 (FIPS 203) used alone as a key exchange.
pub(crate) struct MlKem768Group;

static MLKEM768_GROUP: MlKem768Group = MlKem768Group;

/// ML-KEM-768 key exchange (TLS 1.3 only).
pub static MLKEM768: &dyn SupportedKxGroup = &MLKEM768_GROUP;

impl SupportedKxGroup for MlKem768Group {
    /// The client role: generate a decapsulation key and offer the
    /// encapsulation key.
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut seed = ml_kem::Seed::default();
        random_bytes(&mut seed)?;
        let dk = MlKemDk::from_seed(seed);
        let pub_key = dk.encapsulation_key().to_bytes().to_vec();
        Ok(Box::new(MlKemKx { dk, pub_key }))
    }

    /// The server role: encapsulate to the client's key.
    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (ct, ss) = mlkem_encapsulate(client_share)?;
        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: ct,
            secret: ss,
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

impl fmt::Debug for MlKem768Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MLKEM768")
    }
}

fn mlkem_encapsulate(client_share: &[u8]) -> Result<(Vec<u8>, SharedSecret), Error> {
    if client_share.len() != MLKEM768_EK_LEN {
        return Err(PeerMisbehaved::InvalidKeyShare.into());
    }
    let ek_bytes: ml_kem::Key<MlKemEk> = client_share
        .try_into()
        .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
    let ek = MlKemEk::new(&ek_bytes).map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
    let mut m = ml_kem::B32::default();
    random_bytes(&mut m)?;
    let (ct, ss) = ek.encapsulate_deterministic(&m);
    crate::crypto::zeroize_slice(&mut m);
    Ok((ct.to_vec(), SharedSecret::from(ss.as_slice())))
}

struct MlKemKx {
    dk: MlKemDk,
    pub_key: Vec<u8>,
}

impl ActiveKeyExchange for MlKemKx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != MLKEM768_CT_LEN {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        let ss = self
            .dk
            .decapsulate_slice(peer_pub_key)
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        Ok(SharedSecret::from(ss.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::MLKEM768
    }
}

// ---------------------------------------------------------------------------
// Hybrid groups

/// How a hybrid share is laid out: the post-quantum part first (X25519MLKEM768)
/// or the classical part first (SecP256r1MLKEM768).
#[derive(Clone, Copy, Debug)]
struct Layout {
    classical_share_len: usize,
    pq_client_share_len: usize,
    pq_server_share_len: usize,
    pq_first: bool,
}

impl Layout {
    fn split<'a>(&self, share: &'a [u8], pq_len: usize) -> Result<(&'a [u8], &'a [u8]), Error> {
        if share.len() != self.classical_share_len + pq_len {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(if self.pq_first {
            share.split_at(pq_len)
        } else {
            let (classical, pq) = share.split_at(self.classical_share_len);
            (pq, classical)
        })
    }

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

/// A classical group combined with ML-KEM-768.
pub(crate) struct Hybrid {
    classical: &'static dyn SupportedKxGroup,
    name: NamedGroup,
    layout: Layout,
}

static X25519MLKEM768_GROUP: Hybrid = Hybrid {
    classical: &X25519_GROUP,
    name: NamedGroup::X25519MLKEM768,
    layout: Layout {
        classical_share_len: 32,
        pq_client_share_len: MLKEM768_EK_LEN,
        pq_server_share_len: MLKEM768_CT_LEN,
        pq_first: true,
    },
};

/// X25519 combined with ML-KEM-768 (TLS 1.3 only).
pub static X25519MLKEM768: &dyn SupportedKxGroup = &X25519MLKEM768_GROUP;

static SECP256R1MLKEM768_GROUP: Hybrid = Hybrid {
    classical: &SECP256R1_GROUP,
    name: NamedGroup::secp256r1MLKEM768,
    layout: Layout {
        classical_share_len: 65,
        pq_client_share_len: MLKEM768_EK_LEN,
        pq_server_share_len: MLKEM768_CT_LEN,
        pq_first: false,
    },
};

/// secp256r1 combined with ML-KEM-768 (TLS 1.3 only).
pub static SECP256R1MLKEM768: &dyn SupportedKxGroup = &SECP256R1MLKEM768_GROUP;

impl SupportedKxGroup for Hybrid {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = self.classical.start()?;
        let pq = MLKEM768_GROUP.start()?;
        let pub_key = self.layout.concat(pq.pub_key(), classical.pub_key());
        Ok(Box::new(ActiveHybrid {
            classical,
            pq,
            pub_key,
            name: self.name,
            layout: self.layout,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (pq_share, classical_share) = self
            .layout
            .split(client_share, self.layout.pq_client_share_len)?;
        let classical = self.classical.start_and_complete(classical_share)?;
        let (ct, pq_secret) = mlkem_encapsulate(pq_share)?;
        let mut secret =
            Vec::with_capacity(MLKEM768_SS_LEN + classical.secret.secret_bytes().len());
        secret.extend_from_slice(pq_secret.secret_bytes());
        secret.extend_from_slice(classical.secret.secret_bytes());
        let secret = if self.layout.pq_first {
            secret
        } else {
            let mut s = Vec::with_capacity(secret.len());
            s.extend_from_slice(classical.secret.secret_bytes());
            s.extend_from_slice(pq_secret.secret_bytes());
            crate::crypto::zeroize_vec(&mut secret);
            s
        };
        Ok(CompletedKeyExchange {
            group: self.name,
            pub_key: self.layout.concat(&ct, &classical.pub_key),
            secret: SharedSecret::from(secret),
        })
    }

    fn name(&self) -> NamedGroup {
        self.name
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

impl fmt::Debug for Hybrid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.name)
    }
}

struct ActiveHybrid {
    classical: Box<dyn ActiveKeyExchange>,
    pq: Box<dyn ActiveKeyExchange>,
    pub_key: Vec<u8>,
    name: NamedGroup,
    layout: Layout,
}

impl ActiveKeyExchange for ActiveHybrid {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let (pq_share, classical_share) = self
            .layout
            .split(peer_pub_key, self.layout.pq_server_share_len)?;
        let classical = self.classical.complete(classical_share)?;
        let pq = self.pq.complete(pq_share)?;
        let secret = self
            .layout
            .concat(pq.secret_bytes(), classical.secret_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(group: &dyn SupportedKxGroup) {
        let client = group.start().unwrap();
        let server = group.start_and_complete(client.pub_key()).unwrap();
        assert_eq!(server.group, group.name());
        let client_secret = client.complete(&server.pub_key).unwrap();
        assert_eq!(client_secret.secret_bytes(), server.secret.secret_bytes());
        assert!(!client_secret.secret_bytes().is_empty());
    }

    #[test]
    fn all_groups_agree() {
        for group in [
            X25519,
            SECP256R1,
            SECP384R1,
            SECP521R1,
            MLKEM768,
            X25519MLKEM768,
            SECP256R1MLKEM768,
        ] {
            exchange(group);
        }
    }

    #[test]
    fn share_lengths() {
        assert_eq!(X25519.start().unwrap().pub_key().len(), 32);
        assert_eq!(SECP256R1.start().unwrap().pub_key().len(), 65);
        assert_eq!(SECP384R1.start().unwrap().pub_key().len(), 97);
        assert_eq!(SECP521R1.start().unwrap().pub_key().len(), 133);
        assert_eq!(MLKEM768.start().unwrap().pub_key().len(), 1184);
        let hybrid = X25519MLKEM768.start().unwrap();
        assert_eq!(hybrid.pub_key().len(), 1184 + 32);
        let (group, classical) = hybrid.hybrid_component().unwrap();
        assert_eq!(group, NamedGroup::X25519);
        assert_eq!(classical, &hybrid.pub_key()[1184..]);
        let hybrid = SECP256R1MLKEM768.start().unwrap();
        assert_eq!(
            hybrid.hybrid_component().unwrap().1,
            &hybrid.pub_key()[..65]
        );
        assert!(!X25519MLKEM768.usable_for_version(ProtocolVersion::TLSv1_2));
        assert!(X25519.usable_for_version(ProtocolVersion::TLSv1_2));
    }

    #[test]
    fn bad_peer_shares_are_rejected() {
        let invalid = Error::from(PeerMisbehaved::InvalidKeyShare);
        assert_eq!(
            X25519.start().unwrap().complete(&[0; 31]).unwrap_err(),
            invalid
        );
        // all-zero X25519 point yields a non-contributory secret
        assert_eq!(
            X25519.start().unwrap().complete(&[0; 32]).unwrap_err(),
            invalid
        );
        assert_eq!(
            SECP256R1
                .start()
                .unwrap()
                .complete(&[0x02; 65])
                .unwrap_err(),
            invalid
        );
        assert_eq!(
            SECP256R1
                .start()
                .unwrap()
                .complete(&[0x04; 64])
                .unwrap_err(),
            invalid
        );
        let mut not_on_curve = [0x04u8; 65];
        not_on_curve[1..].fill(1);
        assert_eq!(
            SECP256R1
                .start()
                .unwrap()
                .complete(&not_on_curve)
                .unwrap_err(),
            invalid
        );
        assert_eq!(
            MLKEM768.start().unwrap().complete(&[0; 10]).unwrap_err(),
            invalid
        );
        assert_eq!(
            MLKEM768.start_and_complete(&[0; 1183]).unwrap_err(),
            invalid
        );
        assert_eq!(
            X25519MLKEM768
                .start()
                .unwrap()
                .complete(&[0; 1120])
                .unwrap_err(),
            invalid
        );
        assert_eq!(
            X25519MLKEM768.start_and_complete(&[0; 1216]).unwrap_err(),
            invalid
        );
    }

    #[test]
    fn hybrid_classical_component_completes() {
        let hybrid = X25519MLKEM768.start().unwrap();
        let (_, classical_pub) = hybrid.hybrid_component().unwrap();
        let server = X25519.start_and_complete(classical_pub).unwrap();
        let secret = hybrid.complete_hybrid_component(&server.pub_key).unwrap();
        assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
    }
}
