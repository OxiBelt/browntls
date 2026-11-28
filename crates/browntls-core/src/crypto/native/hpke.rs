//! HPKE suites backed by `browntls_crypto::hpke`.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use browntls_crypto::hpke::{
    Aead, Kdf, Kem, PrivateKey, Psk, PublicKey, RecipientContext, SenderContext, Suite,
};
use browntls_crypto::rand::OsRng;

use crate::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeAead, HpkeKdf, HpkeKem, HpkeModes, HpkeOpenMode, HpkeOpener,
    HpkePrivateKey, HpkePsk, HpkePublicKey, HpkeSealMode, HpkeSealer, HpkeSuite,
    HpkeSymmetricCipherSuite,
};
use crate::error::Error;

/// One native HPKE suite.
#[derive(Debug)]
pub struct NativeHpke(Suite);

const fn suite(kem: Kem, kdf: Kdf, aead: Aead) -> NativeHpke {
    NativeHpke(Suite::new(kem, kdf, aead))
}

macro_rules! kdf_aead {
    ($kem:expr) => {
        [
            suite($kem, Kdf::HkdfSha256, Aead::Aes128Gcm),
            suite($kem, Kdf::HkdfSha256, Aead::Aes256Gcm),
            suite($kem, Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
            suite($kem, Kdf::HkdfSha384, Aead::Aes128Gcm),
            suite($kem, Kdf::HkdfSha384, Aead::Aes256Gcm),
            suite($kem, Kdf::HkdfSha384, Aead::ChaCha20Poly1305),
            suite($kem, Kdf::HkdfSha512, Aead::Aes128Gcm),
            suite($kem, Kdf::HkdfSha512, Aead::Aes256Gcm),
            suite($kem, Kdf::HkdfSha512, Aead::ChaCha20Poly1305),
        ]
    };
}

static X25519: [NativeHpke; 9] = kdf_aead!(Kem::DhX25519HkdfSha256);
static P256: [NativeHpke; 9] = kdf_aead!(Kem::DhP256HkdfSha256);
static P384: [NativeHpke; 9] = kdf_aead!(Kem::DhP384HkdfSha384);
static P521: [NativeHpke; 9] = kdf_aead!(Kem::DhP521HkdfSha512);
static X448: [NativeHpke; 9] = kdf_aead!(Kem::DhX448HkdfSha512);

macro_rules! export_only {
    ($kem:expr) => {
        [
            suite($kem, Kdf::HkdfSha256, Aead::ExportOnly),
            suite($kem, Kdf::HkdfSha384, Aead::ExportOnly),
            suite($kem, Kdf::HkdfSha512, Aead::ExportOnly),
        ]
    };
}

static X25519_EXPORT: [NativeHpke; 3] = export_only!(Kem::DhX25519HkdfSha256);
static P256_EXPORT: [NativeHpke; 3] = export_only!(Kem::DhP256HkdfSha256);
static P384_EXPORT: [NativeHpke; 3] = export_only!(Kem::DhP384HkdfSha384);
static P521_EXPORT: [NativeHpke; 3] = export_only!(Kem::DhP521HkdfSha512);
static X448_EXPORT: [NativeHpke; 3] = export_only!(Kem::DhX448HkdfSha512);

macro_rules! refs {
    ($($arr:ident),*) => {
        &[$(
            &$arr[0], &$arr[1], &$arr[2], &$arr[3], &$arr[4],
            &$arr[5], &$arr[6], &$arr[7], &$arr[8],
        )*]
    };
}

/// DHKEM(X25519, HKDF-SHA256) with HKDF-SHA256 and AES-128-GCM: the suite
/// most ECH deployments publish.
pub static DH_KEM_X25519_HKDF_SHA256_AES_128: &dyn Hpke = &X25519[0];

/// Every suite (excluding export-only AEADs, which cannot seal), X25519
/// first, then P-256, P-384, P-521 and X448; within a KEM, HKDF-SHA256 then
/// SHA-384 then SHA-512, each with AES-128-GCM, AES-256-GCM and
/// ChaCha20-Poly1305.
pub static ALL_SUPPORTED_SUITES: &[&dyn Hpke] = refs!(X25519, P256, P384, P521, X448);

macro_rules! refs_with_export_only {
    ($($arr:ident),*; $($export:ident),*) => {
        &[
            $(
                &$arr[0], &$arr[1], &$arr[2], &$arr[3], &$arr[4],
                &$arr[5], &$arr[6], &$arr[7], &$arr[8],
            )*
            $(&$export[0], &$export[1], &$export[2],)*
        ]
    };
}

/// Every suite, for applications that use the modes of RFC 9180 §5.1: the
/// suites of [`ALL_SUPPORTED_SUITES`] in the same order, then the
/// export-only ones (AEAD `0xFFFF`), which ECH cannot use: X25519, P-256,
/// P-384, P-521 and X448, each with HKDF-SHA256, SHA-384 and SHA-512. An
/// export-only suite's sealer fails every [`HpkeSealer::seal`] and its
/// opener every [`HpkeOpener::open`]; their exports work.
///
/// Read [`HpkeSealMode`] for what each mode authenticates and for the
/// key-compromise impersonation of the Auth modes (RFC 9180 §9.1.1), and
/// [`HpkePsk`] for the entropy a pre-shared key needs (§9.5).
pub static ALL_SUPPORTED_SUITES_WITH_MODES: &[&dyn HpkeModes] = refs_with_export_only!(
    X25519, P256, P384, P521, X448;
    X25519_EXPORT, P256_EXPORT, P384_EXPORT, P521_EXPORT, X448_EXPORT
);

// `HpkePsk::new` enforces the floor of `Psk::new`.
const _: () = assert!(HpkePsk::MIN_KEY_LEN == browntls_crypto::hpke::MIN_PSK_LEN);

fn map_err(_: browntls_crypto::Error) -> Error {
    Error::General("HPKE operation failed".into())
}

impl Hpke for NativeHpke {
    fn suite(&self) -> HpkeSuite {
        HpkeSuite {
            kem: HpkeKem(self.0.kem.id()),
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf(self.0.kdf.id()),
                aead_id: HpkeAead(self.0.aead.id()),
            },
        }
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer>), Error> {
        let pk = PublicKey::from_bytes(self.0.kem, &pub_key.0).map_err(map_err)?;
        let (enc, ctx) = self.0.setup_sender(&pk, info, &OsRng).map_err(map_err)?;
        Ok((
            EncapsulatedSecret(enc.as_bytes().to_vec()),
            Box::new(NativeSealer(ctx)),
        ))
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener>, Error> {
        let sk = PrivateKey::from_bytes(self.0.kem, secret_key.secret_bytes()).map_err(map_err)?;
        let ctx = self.0.setup_recipient(&enc.0, &sk, info).map_err(map_err)?;
        Ok(Box::new(NativeOpener(ctx)))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let sk = self
            .0
            .kem
            .generate_key_pair(&OsRng)
            .map_err(|_| Error::FailedToGetRandomBytes)?;
        let mut bytes = vec![0u8; self.0.kem.private_key_len()];
        sk.write_bytes(&mut bytes).map_err(map_err)?;
        Ok((
            HpkePublicKey(sk.public_key().as_bytes().to_vec()),
            HpkePrivateKey::from(bytes),
        ))
    }

    #[cfg(feature = "key-log")]
    fn kem_secret_capture(&self) -> Option<&dyn crate::crypto::hpke::KemSecretCapture> {
        Some(self)
    }
}

/// The key log's view of a setup: the same operations, with the KEM shared
/// secret copied to the caller's buffer. The intermediate copy is zeroised
/// when it goes out of scope, whatever the outcome.
#[cfg(feature = "key-log")]
impl crate::crypto::hpke::KemSecretCapture for NativeHpke {
    fn setup_sealer(
        &self,
        _authorised: &crate::crypto::hpke::KeyLogAuthorisation,
        info: &[u8],
        pub_key: &HpkePublicKey,
        kem_secret: &mut crate::crypto::hpke::KemSecret,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer>), Error> {
        kem_secret.clear();
        let pk = PublicKey::from_bytes(self.0.kem, &pub_key.0).map_err(map_err)?;
        let mut captured = browntls_crypto::hpke::KemSharedSecret::new();
        let (enc, ctx) = self
            .0
            .setup_sender_with_kem_secret(&pk, info, &OsRng, &mut captured)
            .map_err(map_err)?;
        kem_secret.set(captured.as_bytes());
        Ok((
            EncapsulatedSecret(enc.as_bytes().to_vec()),
            Box::new(NativeSealer(ctx)),
        ))
    }

    fn setup_opener(
        &self,
        _authorised: &crate::crypto::hpke::KeyLogAuthorisation,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
        kem_secret: &mut crate::crypto::hpke::KemSecret,
    ) -> Result<Box<dyn HpkeOpener>, Error> {
        kem_secret.clear();
        let sk = PrivateKey::from_bytes(self.0.kem, secret_key.secret_bytes()).map_err(map_err)?;
        let mut captured = browntls_crypto::hpke::KemSharedSecret::new();
        let ctx = self
            .0
            .setup_recipient_with_kem_secret(&enc.0, &sk, info, &mut captured)
            .map_err(map_err)?;
        kem_secret.set(captured.as_bytes());
        Ok(Box::new(NativeOpener(ctx)))
    }
}

/// The native view of a pre-shared key. [`HpkePsk::new`] checks what
/// `Psk::new` checks, so the conversion does not fail.
fn native_psk(psk: &HpkePsk) -> Result<Psk<'_>, Error> {
    Psk::new(psk.secret_bytes(), psk.id()).map_err(map_err)
}

/// The modes beyond base map one to one onto `Suite`'s setups; base mode is
/// the [`Hpke`] setup itself, so ECH and an application in base mode run
/// the same code.
impl HpkeModes for NativeHpke {
    fn setup_sealer_with_mode(
        &self,
        mode: HpkeSealMode<'_>,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer>), Error> {
        let suite = self.0;
        let sender_key = |sk: &HpkePrivateKey| {
            PrivateKey::from_bytes(suite.kem, sk.secret_bytes()).map_err(map_err)
        };
        if let HpkeSealMode::Base = mode {
            return self.setup_sealer(info, pub_key);
        }
        let pk = PublicKey::from_bytes(suite.kem, &pub_key.0).map_err(map_err)?;
        let (enc, ctx) = match mode {
            HpkeSealMode::Base => return self.setup_sealer(info, pub_key),
            HpkeSealMode::Psk(psk) => suite.setup_sender_psk(&pk, info, &native_psk(psk)?, &OsRng),
            HpkeSealMode::Auth(sk) => suite.setup_sender_auth(&pk, info, &sender_key(sk)?, &OsRng),
            HpkeSealMode::AuthPsk(psk, sk) => {
                let (psk, sk) = (native_psk(psk)?, sender_key(sk)?);
                suite.setup_sender_auth_psk(&pk, info, &psk, &sk, &OsRng)
            }
        }
        .map_err(map_err)?;
        Ok((
            EncapsulatedSecret(enc.as_bytes().to_vec()),
            Box::new(NativeSealer(ctx)),
        ))
    }

    fn setup_opener_with_mode(
        &self,
        mode: HpkeOpenMode<'_>,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener>, Error> {
        let suite = self.0;
        let sender_key =
            |pk: &HpkePublicKey| PublicKey::from_bytes(suite.kem, &pk.0).map_err(map_err);
        if let HpkeOpenMode::Base = mode {
            return self.setup_opener(enc, info, secret_key);
        }
        let sk = PrivateKey::from_bytes(suite.kem, secret_key.secret_bytes()).map_err(map_err)?;
        let ctx = match mode {
            HpkeOpenMode::Base => return self.setup_opener(enc, info, secret_key),
            HpkeOpenMode::Psk(psk) => {
                suite.setup_recipient_psk(&enc.0, &sk, info, &native_psk(psk)?)
            }
            HpkeOpenMode::Auth(pk) => {
                suite.setup_recipient_auth(&enc.0, &sk, info, &sender_key(pk)?)
            }
            HpkeOpenMode::AuthPsk(psk, pk) => {
                let (psk, pk) = (native_psk(psk)?, sender_key(pk)?);
                suite.setup_recipient_auth_psk(&enc.0, &sk, info, &psk, &pk)
            }
        }
        .map_err(map_err)?;
        Ok(Box::new(NativeOpener(ctx)))
    }
}

#[derive(Debug)]
struct NativeSealer(SenderContext);

impl HpkeSealer for NativeSealer {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.seal(aad, plaintext).map_err(map_err)
    }

    fn export(&self, exporter_context: &[u8], out: &mut [u8]) -> Result<(), Error> {
        self.0.export(exporter_context, out).map_err(map_err)
    }
}

#[derive(Debug)]
struct NativeOpener(RecipientContext);

impl HpkeOpener for NativeOpener {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0
            .open(aad, ciphertext)
            .map_err(|_| Error::DecryptError)
    }

    fn export(&self, exporter_context: &[u8], out: &mut [u8]) -> Result<(), Error> {
        self.0.export(exporter_context, out).map_err(map_err)
    }
}
