use alloc::vec;

use super::*;

const EXAMPLE: &[u8] = b"-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VuBCIEICjd4yGRdsoP9gU7YT7My8DHx1Tjme8GYDXrOMCi8v1V\n\
-----END PRIVATE KEY-----\n\
-----BEGIN ECHCONFIG-----\n\
AD7+DQA65wAgACA8wVN2BtscOl3vQheUzHeIkVmKIiydUhDCliA4iyQRCwAEAAEA\n\
AQALZXhhbXBsZS5jb20AAA==\n\
-----END ECHCONFIG-----\n";

fn public_pem() -> &'static [u8] {
    let marker = b"-----BEGIN ECHCONFIG-----";
    let offset = EXAMPLE
        .windows(marker.len())
        .position(|w| w == marker)
        .unwrap();
    &EXAMPLE[offset..]
}

#[test]
fn public_only_preserves_list_and_stops_at_end_delimiter() {
    let pem = EchPem::from_pem_slice(public_pem(), None).unwrap();
    assert!(!pem.has_private_key());
    assert_eq!(pem.ech_config_list().len(), 64);
    assert_eq!(pem.to_public_pem(), public_pem());

    let mut input = b"example configuration\r\n".to_vec();
    input.extend_from_slice(&public_pem()[..public_pem().len() - 1]);
    input.resize(300 * 1024, 0xff);
    let with_suffix = EchPem::from_pem_slice(&input, None).unwrap();
    assert_eq!(with_suffix.ech_config_list(), pem.ech_config_list());

    let opaque = EchPem::from_config_list(&[0, 4, 0x7a, 0x7a, 0, 0]).unwrap();
    let parsed = EchPem::from_pem_slice(&opaque.to_public_pem(), None).unwrap();
    assert_eq!(parsed.ech_config_list(), opaque.ech_config_list());
}

#[test]
fn rejects_extra_blocks_before_public_and_invalid_public_data() {
    for input in [
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"
            .as_slice(),
        b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
        b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n\
-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
    ] {
        let mut input = input.to_vec();
        input.extend_from_slice(public_pem());
        assert_eq!(
            EchPem::from_pem_slice(&input, None).unwrap_err(),
            EchPemError::InvalidPem
        );
    }
    assert_eq!(
        EchPem::from_pem_slice(&vec![b' '; 256 * 1024], None).unwrap_err(),
        EchPemError::InputTooLarge
    );
    assert_eq!(
        EchPem::from_pem_slice(EXAMPLE, None).unwrap_err(),
        EchPemError::MissingKeyCodec
    );
    assert!(EchPem::from_config_list(&[0, 3, 0, 0, 0]).is_err());
}

struct CustomCodec {
    public: Vec<u8>,
}

impl EchPkcs8Codec for CustomCodec {
    fn decode_pkcs8(
        &self,
        _: &[u8],
    ) -> Result<(HpkeKem, HpkePrivateKey, HpkePublicKey), EchPemError> {
        Ok((
            HpkeKem::DHKEM_X25519_HKDF_SHA256,
            HpkePrivateKey::from(vec![42]),
            HpkePublicKey(self.public.clone()),
        ))
    }

    fn encode_pkcs8(
        &self,
        _: HpkeKem,
        private: &HpkePrivateKey,
    ) -> Result<(EchSecretBytes, HpkePublicKey), EchPemError> {
        assert_eq!(private.secret_bytes(), &[42]);
        Ok((vec![0x30, 0].into(), HpkePublicKey(self.public.clone())))
    }
}

#[test]
fn custom_codec_validates_key_without_native() {
    let list = EchPem::from_pem_slice(public_pem(), None).unwrap();
    let entries = config::read_config_list(list.ech_config_list()).unwrap();
    let public = &entries[0]
        .contents
        .as_ref()
        .unwrap()
        .key_config
        .public_key
        .0;
    let codec = CustomCodec {
        public: public.clone(),
    };
    let pcm = EchPem::from_pem_slice(EXAMPLE, Some(&codec)).unwrap();
    assert!(pcm.has_private_key());
    let encoded = pcm.to_private_pem(&codec).unwrap();
    assert_eq!(alloc::format!("{encoded:?}"), "EchSecretBytes(<redacted>)");
    let reparsed = EchPem::from_pem_slice(encoded.as_bytes(), Some(&codec)).unwrap();
    assert_eq!(reparsed.ech_config_list(), list.ech_config_list());
    let codec = CustomCodec {
        public: vec![1; 32],
    };
    assert_eq!(
        EchPem::from_pem_slice(EXAMPLE, Some(&codec)).unwrap_err(),
        EchPemError::KeyMismatch
    );
    assert_eq!(
        pcm.to_private_pem(&codec).unwrap_err(),
        EchPemError::KeyMismatch
    );
    assert_eq!(
        list.to_private_pem(&codec).unwrap_err(),
        EchPemError::MissingPrivateKey
    );
}

#[cfg(feature = "native")]
#[test]
fn native_pem_preserves_a_restricted_ecdh_oid() {
    use browntls_crypto::hpke::{Kem, MAX_PKCS8_DER_LEN, PrivateKey};

    use crate::crypto::native::hpke::ALL_SUPPORTED_SUITES;

    let key = EchServerKey::generate(3, "public.example", 0, &ALL_SUPPORTED_SUITES[9..18]).unwrap();
    let list = config::encode_config_list(core::iter::once(key.ech_config()));
    let restricted =
        PrivateKey::from_bytes(Kem::DhP256HkdfSha256, key.private_key().secret_bytes())
            .unwrap()
            .with_pkcs8_ecdh_oid();
    let mut der = EchSecretBytes(vec![0; MAX_PKCS8_DER_LEN]);
    let len = restricted.to_pkcs8_der(&mut der.0).unwrap();
    let mut input = EchSecretBytes(Vec::with_capacity(
        framing::encoded_capacity(len) + framing::encoded_capacity(list.len()),
    ));
    framing::encode(b"PRIVATE KEY", &der.as_bytes()[..len], &mut input.0);
    framing::encode(b"ECHCONFIG", &list, &mut input.0);
    let parsed = EchPem::from_pem_slice(input.as_bytes(), Some(&NATIVE_PKCS8_CODEC)).unwrap();
    let exported = parsed.to_private_pem(&NATIVE_PKCS8_CODEC).unwrap();
    assert!(exported.as_bytes() == input.as_bytes());
}

#[cfg(feature = "native")]
#[test]
fn native_pems_round_trip_all_kems() {
    use crate::crypto::native::hpke::ALL_SUPPORTED_SUITES;

    let fixture = EchPem::from_pem_slice(EXAMPLE, Some(&NATIVE_PKCS8_CODEC)).unwrap();
    assert_eq!(fixture.to_public_pem(), public_pem());
    for suites in ALL_SUPPORTED_SUITES.as_chunks::<9>().0 {
        let key = EchServerKey::generate(3, "public.example", 0, suites).unwrap();
        let mut list = config::encode_config_list(core::iter::once(key.ech_config()));
        list.extend_from_slice(&[0x7a, 0x7a, 0, 0]);
        let length = (list.len() - 2) as u16;
        list[..2].copy_from_slice(&length.to_be_bytes());
        let pem = EchPem::from_server_key(&key, &list, &NATIVE_PKCS8_CODEC).unwrap();
        let bytes = pem.to_private_pem(&NATIVE_PKCS8_CODEC).unwrap();
        let recovered =
            EchPem::from_pem_slice(bytes.as_bytes(), Some(&NATIVE_PKCS8_CODEC)).unwrap();
        assert_eq!(recovered.ech_config_list(), list);
        assert_eq!(recovered.key().unwrap().0, key.kem());
        assert_eq!(
            recovered.key().unwrap().1.secret_bytes(),
            key.private_key().secret_bytes()
        );
    }
}

#[cfg(feature = "std")]
#[test]
fn reader_ignores_suffix_and_writer_propagates_errors() {
    struct SingleRead(Option<&'static [u8]>);
    impl std::io::Read for SingleRead {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let data = self.0.take().ok_or(std::io::ErrorKind::BrokenPipe)?;
            buffer[..data.len()].copy_from_slice(data);
            Ok(data.len())
        }
    }
    struct FailedWriter;
    impl std::io::Write for FailedWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let pem = EchPem::from_pem_reader(SingleRead(Some(public_pem())), None).unwrap();
    let mut out = Vec::new();
    pem.write_public_pem(&mut out).unwrap();
    assert_eq!(out, public_pem());
    let error = EchPemError::Io(std::io::ErrorKind::BrokenPipe);
    assert_eq!(pem.write_public_pem(FailedWriter).unwrap_err(), error);
    #[cfg(feature = "native")]
    {
        let private = EchPem::from_pem_slice(EXAMPLE, Some(&NATIVE_PKCS8_CODEC)).unwrap();
        assert_eq!(
            private
                .write_private_pem(FailedWriter, &NATIVE_PKCS8_CODEC)
                .unwrap_err(),
            error,
        );
    }
    assert_eq!(
        EchPem::from_pem_reader(SingleRead(None), None).unwrap_err(),
        EchPemError::Io(std::io::ErrorKind::BrokenPipe)
    );
    assert_eq!(
        EchPem::from_pem_file(std::path::Path::new(""), None).unwrap_err(),
        EchPemError::Io(std::io::ErrorKind::NotFound)
    );
}
