//! Public API coverage for a caller-supplied codec with only the alloc feature.

use browntls_core::crypto::hpke::{HpkeKem, HpkePrivateKey, HpkePublicKey};
use browntls_core::ech::pem::{EchPem, EchPemError, EchPkcs8Codec, EchSecretBytes};

struct Codec([u8; 32]);

impl EchPkcs8Codec for Codec {
    fn decode_pkcs8(
        &self,
        _: &[u8],
    ) -> Result<(HpkeKem, HpkePrivateKey, HpkePublicKey), EchPemError> {
        Ok((
            HpkeKem::DHKEM_X25519_HKDF_SHA256,
            HpkePrivateKey::from(vec![42]),
            HpkePublicKey(self.0.to_vec()),
        ))
    }

    fn encode_pkcs8(
        &self,
        _: HpkeKem,
        private: &HpkePrivateKey,
    ) -> Result<(EchSecretBytes, HpkePublicKey), EchPemError> {
        assert_eq!(private.secret_bytes(), &[42]);
        Ok((vec![0x30, 0].into(), HpkePublicKey(self.0.to_vec())))
    }
}

#[test]
fn parses_and_exports_with_a_caller_supplied_codec() {
    let list = browntls_pki::pem::base64_decode(
        b"AD7+DQA65wAgACA8wVN2BtscOl3vQheUzHeIkVmKIiydUhDCliA4iyQRCwAEAAEAAQALZXhhbXBsZS5jb20AAA==",
    )
    .unwrap();
    let codec = Codec(list[11..43].try_into().unwrap());
    let public = EchPem::from_config_list(&list).unwrap();
    let mut bytes = b"-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----\n".to_vec();
    bytes.extend_from_slice(&public.to_public_pem());
    let private = EchPem::from_pem_slice(&bytes, Some(&codec)).unwrap();
    assert!(private.has_private_key());
    assert_eq!(private.to_private_pem(&codec).unwrap().as_bytes(), bytes);
    assert_eq!(private.ech_config_list(), public.ech_config_list());
}
