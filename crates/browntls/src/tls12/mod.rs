//! TLS 1.2 cipher suites and connection secrets (RFC 5246 §6.3, §8.1; RFC 7627).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use crate::common_state::Side;
use crate::crypto::cipher::{AeadKey, MessageDecrypter, MessageEncrypter, Tls12AeadAlgorithm};
use crate::crypto::tls12::Prf;
use crate::crypto::{ActiveKeyExchange, KeyExchangeAlgorithm, hash};
use crate::enums::SignatureScheme;
use crate::error::Error;
use crate::suites::{CipherSuiteCommon, PartiallyExtractedSecrets};

/// A TLS 1.2 cipher suite.
pub struct Tls12CipherSuite {
    /// The parts shared with TLS 1.3 suites.
    pub common: CipherSuiteCommon,

    /// The PRF with the suite's hash.
    pub prf_provider: &'static dyn Prf,

    /// The key exchange algorithm family.
    pub kx: KeyExchangeAlgorithm,

    /// The signature schemes usable with this suite's authentication algorithm,
    /// in preference order.
    pub sign: &'static [SignatureScheme],

    /// The record protection algorithm.
    pub aead_alg: &'static dyn Tls12AeadAlgorithm,
}

impl Tls12CipherSuite {
    /// Intersects the peer's offered schemes with this suite's, keeping our order.
    pub fn resolve_sig_schemes(&self, offered: &[SignatureScheme]) -> Vec<SignatureScheme> {
        self.sign
            .iter()
            .filter(|pref| offered.contains(pref))
            .copied()
            .collect()
    }

    /// Whether every component claims FIPS validation.
    pub fn fips(&self) -> bool {
        self.common.fips() && self.prf_provider.fips() && self.aead_alg.fips()
    }
}

impl From<&'static Tls12CipherSuite> for crate::suites::SupportedCipherSuite {
    fn from(s: &'static Tls12CipherSuite) -> Self {
        Self::Tls12(s)
    }
}

impl PartialEq for Tls12CipherSuite {
    fn eq(&self, other: &Self) -> bool {
        self.common.suite == other.common.suite
    }
}

impl fmt::Debug for Tls12CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls12CipherSuite")
            .field("suite", &self.common.suite)
            .finish_non_exhaustive()
    }
}

pub(crate) use crate::common_state::ConnectionRandoms;

/// The TLS 1.2 master secret and everything derived from it.
pub(crate) struct ConnectionSecrets {
    pub(crate) randoms: ConnectionRandoms,
    suite: &'static Tls12CipherSuite,
    master_secret: [u8; 48],
}

impl ConnectionSecrets {
    /// Computes the master secret from a key exchange. With `ems_seed` the
    /// extended master secret of RFC 7627 is used; otherwise the classic one.
    pub(crate) fn from_key_exchange(
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        ems_seed: Option<hash::Output>,
        randoms: ConnectionRandoms,
        suite: &'static Tls12CipherSuite,
    ) -> Result<Self, Error> {
        let mut ret = Self {
            randoms,
            suite,
            master_secret: [0u8; 48],
        };
        let (label, seed): (&[u8], Vec<u8>) = match ems_seed {
            Some(seed) => (b"extended master secret", seed.as_ref().to_vec()),
            None => (
                b"master secret",
                join_randoms(&ret.randoms.client, &ret.randoms.server),
            ),
        };
        ret.suite.prf_provider.for_key_exchange(
            &mut ret.master_secret,
            kx,
            peer_pub_key,
            label,
            &seed,
        )?;
        Ok(ret)
    }

    /// Reinstates a resumed session's master secret.
    pub(crate) fn new_resume(
        randoms: ConnectionRandoms,
        suite: &'static Tls12CipherSuite,
        master_secret: &[u8],
    ) -> Self {
        let mut ret = Self {
            randoms,
            suite,
            master_secret: [0u8; 48],
        };
        let n = master_secret.len().min(48);
        ret.master_secret[..n].copy_from_slice(&master_secret[..n]);
        ret
    }

    /// Expands the key block (RFC 5246 §6.3) and builds the record ciphers.
    pub(crate) fn make_cipher_pair(&self, side: Side) -> MessageCipherPair {
        let shape = self.suite.aead_alg.key_block_shape();
        let key_block = self.make_key_block(&shape);
        let (client_key, rest) = key_block.split_at(shape.enc_key_len);
        let (server_key, rest) = rest.split_at(shape.enc_key_len);
        let (client_iv, rest) = rest.split_at(shape.fixed_iv_len);
        let (server_iv, rest) = rest.split_at(shape.fixed_iv_len);
        let (client_extra, rest) = rest.split_at(shape.explicit_nonce_len);
        let (server_extra, _) = rest.split_at(shape.explicit_nonce_len);

        let (write_key, write_iv, write_extra, read_key, read_iv) = match side {
            Side::Client => (client_key, client_iv, client_extra, server_key, server_iv),
            Side::Server => (server_key, server_iv, server_extra, client_key, client_iv),
        };
        let pair = MessageCipherPair {
            enc: self
                .suite
                .aead_alg
                .encrypter(AeadKey::new(write_key), write_iv, write_extra),
            dec: self
                .suite
                .aead_alg
                .decrypter(AeadKey::new(read_key), read_iv),
        };
        let mut key_block = key_block;
        crate::crypto::zeroize_vec(&mut key_block);
        pair
    }

    fn make_key_block(&self, shape: &crate::crypto::cipher::KeyBlockShape) -> Vec<u8> {
        let len = (shape.enc_key_len + shape.fixed_iv_len + shape.explicit_nonce_len) * 2;
        let mut out = alloc::vec![0u8; len];
        // RFC 5246 §6.3: key_block = PRF(master_secret, "key expansion", server_random + client_random)
        let seed = join_randoms(&self.randoms.server, &self.randoms.client);
        self.suite
            .prf_provider
            .for_secret(&mut out, &self.master_secret, b"key expansion", &seed);
        out
    }

    pub(crate) fn suite(&self) -> &'static Tls12CipherSuite {
        self.suite
    }

    pub(crate) fn master_secret(&self) -> &[u8] {
        &self.master_secret
    }

    fn make_verify_data(&self, handshake_hash: &hash::Output, label: &[u8]) -> Vec<u8> {
        let mut out = alloc::vec![0u8; 12];
        self.suite.prf_provider.for_secret(
            &mut out,
            &self.master_secret,
            label,
            handshake_hash.as_ref(),
        );
        out
    }

    pub(crate) fn client_verify_data(&self, handshake_hash: &hash::Output) -> Vec<u8> {
        self.make_verify_data(handshake_hash, b"client finished")
    }

    pub(crate) fn server_verify_data(&self, handshake_hash: &hash::Output) -> Vec<u8> {
        self.make_verify_data(handshake_hash, b"server finished")
    }

    /// RFC 5705 keying material export.
    pub(crate) fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) {
        let mut seed = join_randoms(&self.randoms.client, &self.randoms.server);
        if let Some(context) = context {
            // Context lengths are bounded by callers at u16::MAX.
            seed.extend_from_slice(&(context.len() as u16).to_be_bytes());
            seed.extend_from_slice(context);
        }
        self.suite
            .prf_provider
            .for_secret(output, &self.master_secret, label, &seed);
    }

    pub(crate) fn extract_secrets(&self, side: Side) -> Result<PartiallyExtractedSecrets, Error> {
        let shape = self.suite.aead_alg.key_block_shape();
        let key_block = self.make_key_block(&shape);
        let (client_key, rest) = key_block.split_at(shape.enc_key_len);
        let (server_key, rest) = rest.split_at(shape.enc_key_len);
        let (client_iv, rest) = rest.split_at(shape.fixed_iv_len);
        let (server_iv, rest) = rest.split_at(shape.fixed_iv_len);
        let (client_extra, rest) = rest.split_at(shape.explicit_nonce_len);
        let (server_extra, _) = rest.split_at(shape.explicit_nonce_len);
        let client =
            self.suite
                .aead_alg
                .extract_keys(AeadKey::new(client_key), client_iv, client_extra)?;
        let server =
            self.suite
                .aead_alg
                .extract_keys(AeadKey::new(server_key), server_iv, server_extra)?;
        let mut key_block = key_block;
        crate::crypto::zeroize_vec(&mut key_block);
        Ok(match side {
            Side::Client => PartiallyExtractedSecrets {
                tx: client,
                rx: server,
            },
            Side::Server => PartiallyExtractedSecrets {
                tx: server,
                rx: client,
            },
        })
    }
}

impl Drop for ConnectionSecrets {
    fn drop(&mut self) {
        crate::crypto::zeroize_slice(&mut self.master_secret);
    }
}

impl fmt::Debug for ConnectionSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionSecrets")
            .field("suite", &self.suite.common.suite)
            .finish_non_exhaustive()
    }
}

fn join_randoms(first: &[u8; 32], second: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(first);
    out.extend_from_slice(second);
    out
}

/// A matched encrypter and decrypter.
pub(crate) struct MessageCipherPair {
    pub(crate) enc: Box<dyn MessageEncrypter>,
    pub(crate) dec: Box<dyn MessageDecrypter>,
}

/// The ECDSA/EdDSA schemes acceptable with an ECDHE_ECDSA suite.
#[allow(dead_code)] // consumed by the crypto providers, which are optional
pub(crate) static TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

/// The RSA schemes acceptable with an ECDHE_RSA suite. In TLS 1.2,
/// RSASSA-PSS is used with RSA cipher suites (RFC 9846 §4.3.3), so the
/// `rsa_pss_pss_*` schemes of RSASSA-PSS public keys are included, last.
#[allow(dead_code)] // consumed by the crypto providers, which are optional
pub(crate) static TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PSS_PSS_SHA512,
    SignatureScheme::RSA_PSS_PSS_SHA384,
    SignatureScheme::RSA_PSS_PSS_SHA256,
];
