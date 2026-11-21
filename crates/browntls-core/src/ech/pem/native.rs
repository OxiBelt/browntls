use alloc::vec;

use browntls_crypto::hpke::{Kem, MAX_PKCS8_DER_LEN, PrivateKey};

use super::{EchPemError, EchPkcs8Codec, EchSecretBytes};
use crate::crypto::hpke::{HpkeKem, HpkePrivateKey, HpkePublicKey};

/// The built-in PKCS #8 adapter for the five native DHKEMs.
#[derive(Debug)]
pub struct NativeEchPkcs8Codec;

/// The built-in adapter for native ECH keys.
pub static NATIVE_PKCS8_CODEC: NativeEchPkcs8Codec = NativeEchPkcs8Codec;

impl EchPkcs8Codec for NativeEchPkcs8Codec {
    fn decode_pkcs8(
        &self,
        input: &[u8],
    ) -> Result<(HpkeKem, HpkePrivateKey, HpkePublicKey), EchPemError> {
        let key =
            PrivateKey::from_pkcs8_der_or_ber(input).map_err(|_| EchPemError::InvalidPrivateKey)?;
        let mut encoded = HpkePrivateKey::from(vec![0; key.kem().private_key_len()]);
        encoded.pkcs8_ecdh_oid = key.pkcs8_uses_ecdh_oid();
        key.write_bytes(encoded.secret_bytes_mut())
            .map_err(|_| EchPemError::InvalidPrivateKey)?;
        Ok((
            HpkeKem(key.kem().id()),
            encoded,
            HpkePublicKey(key.public_key().as_bytes().to_vec()),
        ))
    }

    fn encode_pkcs8(
        &self,
        kem: HpkeKem,
        private: &HpkePrivateKey,
    ) -> Result<(EchSecretBytes, HpkePublicKey), EchPemError> {
        let kem = Kem::from_id(kem.0).ok_or(EchPemError::InvalidPrivateKey)?;
        let mut key = PrivateKey::from_bytes(kem, private.secret_bytes())
            .map_err(|_| EchPemError::InvalidPrivateKey)?;
        if private.pkcs8_ecdh_oid {
            key = key.with_pkcs8_ecdh_oid();
        }
        let mut der = EchSecretBytes(vec![0; MAX_PKCS8_DER_LEN]);
        let len = key
            .to_pkcs8_der(&mut der.0)
            .map_err(|_| EchPemError::InvalidPrivateKey)?;
        crate::crypto::zeroize_slice(&mut der.0[len..]);
        der.0.truncate(len);
        Ok((der, HpkePublicKey(key.public_key().as_bytes().to_vec())))
    }
}
