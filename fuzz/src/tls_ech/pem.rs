//! RFC 9934 envelope and key-codec operations.

use std::io::Cursor;

use browntls_core::crypto::native::hpke::ALL_SUPPORTED_SUITES;
use browntls_core::ech::pem::{EchPem, EchPkcs8Codec, NATIVE_PKCS8_CODEC};
use browntls_core::ech::{EchConfig, EchServerConfig, EchServerKey};

use super::{Fields, KEMS, PUBLIC, config_list, fixture};
use crate::input::Input;

pub(super) fn run(input: &mut Input<'_>) {
    match input.choose(3) {
        0 => {
            let input = input.field();
            let parsed = EchPem::from_pem_slice(input, Some(&NATIVE_PKCS8_CODEC));
            let reader = EchPem::from_pem_reader(Cursor::new(input), Some(&NATIVE_PKCS8_CODEC));
            assert_eq!(parsed.is_ok(), reader.is_ok());
            if let Ok(pem) = parsed {
                let bytes = pem.to_public_pem();
                let public = EchPem::from_pem_slice(&bytes, None).unwrap();
                assert_eq!(pem.ech_config_list(), public.ech_config_list());
                assert!(!public.has_private_key());
                if pem.has_private_key() {
                    let encoded = pem.to_private_pem(&NATIVE_PKCS8_CODEC).unwrap();
                    let again =
                        EchPem::from_pem_slice(encoded.as_bytes(), Some(&NATIVE_PKCS8_CODEC))
                            .unwrap();
                    assert_eq!(again.ech_config_list(), pem.ech_config_list());
                    assert!(again.has_private_key());
                }
            }
        }
        1 => {
            if let Ok((kem, private, public)) = NATIVE_PKCS8_CODEC.decode_pkcs8(input.field()) {
                let (der, derived) = NATIVE_PKCS8_CODEC.encode_pkcs8(kem, &private).unwrap();
                assert_eq!(public.0, derived.0);
                let (decoded_kem, decoded_private, _) =
                    NATIVE_PKCS8_CODEC.decode_pkcs8(der.as_bytes()).unwrap();
                assert_eq!(decoded_kem, kem);
                assert_eq!(decoded_private, private);
            }
        }
        _ => {
            let index = input.choose(KEMS.len());
            let (public, private) = &fixture().pairs[index];
            let fields = Fields {
                version: super::ECH_VERSION,
                config_id: input.byte(),
                kem: KEMS[index].0,
                public_key: public.0.clone(),
                suites: vec![(1, 1)],
                maximum_name_length: 0,
                public_name: PUBLIC.as_bytes().to_vec(),
                extensions: Vec::new(),
            };
            let encoded = fields.encode();
            let list = config_list([encoded.as_slice()]);
            let key = EchServerKey::new(&encoded, private.clone(), ALL_SUPPORTED_SUITES).unwrap();
            let pem = EchPem::from_server_key(&key, &list, &NATIVE_PKCS8_CODEC).unwrap();
            let mut bytes = Vec::new();
            pem.write_private_pem(&mut bytes, &NATIVE_PKCS8_CODEC)
                .unwrap();
            let private =
                EchPem::from_pem_reader(Cursor::new(bytes), Some(&NATIVE_PKCS8_CODEC)).unwrap();
            let public = EchPem::from_config_list(private.ech_config_list()).unwrap();
            let mut output = Vec::new();
            public.write_public_pem(&mut output).unwrap();
            assert_eq!(output, pem.to_public_pem());
            let selected = EchConfig::from_pem(&public, ALL_SUPPORTED_SUITES).unwrap();
            assert_eq!(selected.config_id(), key.config_id());
            let server =
                EchServerConfig::from_pems(&[private], &[public], ALL_SUPPORTED_SUITES).unwrap();
            assert_eq!(server.ech_config_list(), &list);
        }
    }
}

#[test]
fn public_pem_path() {
    use std::io::Write as _;

    let parent = std::env::temp_dir();
    let work = parent.join(format!("browntls-fuzz-ech-{}", std::process::id()));
    std::fs::create_dir(&work).unwrap();
    let path = work.join("public.pem");
    let pem = EchPem::from_config_list(&[0, 4, 0x7a, 0x7a, 0, 0]).unwrap();
    let result = (|| {
        let mut file = std::fs::File::create_new(&path)?;
        file.write_all(&pem.to_public_pem())?;
        Ok::<_, std::io::Error>(EchPem::from_pem_file(&path, None))
    })();
    std::fs::remove_dir_all(&work).unwrap();
    assert_eq!(
        result.unwrap().unwrap().ech_config_list(),
        pem.ech_config_list()
    );
}

#[test]
fn tokio_pem_constructors() {
    use std::sync::Arc;

    use browntls_core::{ClientConfig, crypto};
    use browntls_tokio::{TlsAcceptor, TlsConnector, unbuffered};

    let client_config =
        ClientConfig::builder_with_provider(Arc::new(crypto::native::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(fixture().roots.clone())
            .with_no_client_auth();
    let server_config = super::handshake::server_config(None, false);
    let key = EchServerKey::generate(42, PUBLIC, 0, ALL_SUPPORTED_SUITES).unwrap();
    let list = config_list([key.ech_config()]);
    let pem = EchPem::from_server_key(&key, &list, &NATIVE_PKCS8_CODEC).unwrap();
    let public = EchPem::from_config_list(&list).unwrap();
    let connector =
        TlsConnector::from_ech_pem(client_config.clone(), &public, ALL_SUPPORTED_SUITES).unwrap();
    assert!(connector.config().ech_mode.is_some());
    let connector =
        unbuffered::TlsConnector::from_ech_pem(client_config, &public, ALL_SUPPORTED_SUITES)
            .unwrap();
    assert!(connector.config().ech_mode.is_some());
    let keys = [pem];
    let retry = [public];
    let acceptor = TlsAcceptor::from_ech_pem(
        server_config.as_ref().clone(),
        &keys,
        &retry,
        ALL_SUPPORTED_SUITES,
    )
    .unwrap();
    assert!(acceptor.config().ech.is_some());
    let acceptor = unbuffered::TlsAcceptor::from_ech_pem(
        server_config.as_ref().clone(),
        &keys,
        &retry,
        ALL_SUPPORTED_SUITES,
    )
    .unwrap();
    assert!(acceptor.config().ech.is_some());
}
