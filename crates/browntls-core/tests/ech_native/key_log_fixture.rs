//! What a reader of a capture does with the ECH records of a key log file
//! (RFC 9850 §2.3): from the outer ClientHello on the wire and the two
//! lines that name its random, decrypt the inner ClientHello.
//!
//! The decryption here shares no code with the library: the HPKE key
//! schedule (RFC 9180 §5.1) is written out over the RustCrypto `hmac`,
//! `sha2` and `aes-gcm` crates, for the one suite the test configures
//! (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM). It starts from
//! the logged KEM shared secret, so it succeeds only if `ECH_SECRET` is
//! that secret, `ECH_CONFIG` is the configuration the context was bound
//! to, and both are filed under the outer random.
//!
//! Every key and secret is generated for the test and discarded with it.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::aead::{self, AeadInOut};
use browntls_core::KeyLogFile;
use hello_wire::take_flight;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::outer_wire::{OuterHello, outer_hello, u16_at};
use super::*;

static DIRECTORY_ID: AtomicUsize = AtomicUsize::new(0);

/// A directory only this user can enter, removed on drop.
struct PrivateDir(PathBuf);

impl PrivateDir {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        let id = DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!("browntls-ech-key-log-{}-{id}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    /// A key log file in the directory, and its path.
    fn log(&self, name: &str) -> (Arc<KeyLogFile>, PathBuf) {
        let path = self.0.join(name);
        (Arc::new(KeyLogFile::try_from_path(&path).unwrap()), path)
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The records of a key log file as `(label, random, value)`, after
/// checking each line against the format of RFC 9850 §2: three fields
/// separated by single spaces, the random 64 lowercase hexadecimal digits,
/// the value an even number of them, a line feed at the end.
fn read_log(path: &PathBuf) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    let contents = fs::read_to_string(path).unwrap();
    assert!(contents.ends_with('\n'));
    let lower_hex = |s: &str| s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    contents
        .strip_suffix('\n')
        .unwrap()
        .split('\n')
        .map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            let [label, random, value] = fields[..] else {
                panic!("not three fields");
            };
            assert!(
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|b| matches!(b, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
            );
            assert!(random.len() == 64 && lower_hex(random));
            assert!(!value.is_empty() && value.len() % 2 == 0 && lower_hex(value));
            (
                label.to_string(),
                hex::decode(random).unwrap(),
                hex::decode(value).unwrap(),
            )
        })
        .collect()
}

/// The value of the only record with `label` and `random`.
fn only<'a>(records: &'a [(String, Vec<u8>, Vec<u8>)], label: &str, random: &[u8]) -> &'a [u8] {
    let found: Vec<&Vec<u8>> = records
        .iter()
        .filter(|(l, r, _)| l == label && r == random)
        .map(|(.., value)| value)
        .collect();
    assert_eq!(found.len(), 1, "{label}: {} records", found.len());
    found[0]
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// `LabeledExtract` (RFC 9180 §4) with HKDF-SHA256.
fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, &[b"HPKE-v1", suite_id, label, ikm])
}

/// `LabeledExpand` (RFC 9180 §4) with HKDF-SHA256, for at most one block.
fn labeled_expand(suite_id: &[u8], prk: &[u8], label: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    assert!(len <= 32);
    let length = (len as u16).to_be_bytes();
    let block = hmac_sha256(prk, &[&length, b"HPKE-v1", suite_id, label, info, &[1]]);
    block[..len].to_vec()
}

/// Decrypts the ECH payload of `outer` as a reader of the key log does:
/// `KeySchedule` in base mode (RFC 9180 §5.1) from the KEM shared secret
/// and `info = "tls ech" || 0x00 || ECHConfig` (RFC 9849 §6.1), then
/// `Open` with sequence number zero. `None` if the tag does not verify.
fn open_with_log(outer: &OuterHello, kem_secret: &[u8], config: &[u8]) -> Option<Vec<u8>> {
    // ECHConfig: version, length, then HpkeKeyConfig: the configuration
    // identifier and the KEM.
    assert_eq!(&config[..2], [0xfe, 0x0d]);
    assert_eq!(u16_at(config, 2), config.len() - 4);
    let kem = u16_at(config, 5) as u16;
    // DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
    assert_eq!((kem, outer.kdf, outer.aead), (0x0020, 0x0001, 0x0001));
    let mut suite_id = b"HPKE".to_vec();
    for id in [kem, outer.kdf, outer.aead] {
        suite_id.extend_from_slice(&id.to_be_bytes());
    }
    let info = [b"tls ech\0", config].concat();

    let psk_id_hash = labeled_extract(&suite_id, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(&suite_id, b"", b"info_hash", &info);
    let context = [&[0u8][..], &psk_id_hash, &info_hash].concat();
    let secret = labeled_extract(&suite_id, kem_secret, b"secret", b"");
    let key = labeled_expand(&suite_id, &secret, b"key", &context, 16);
    let base_nonce = labeled_expand(&suite_id, &secret, b"base_nonce", &context, 12);

    let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key).unwrap();
    let nonce: aead::Nonce<aes_gcm::Aes128Gcm> = base_nonce[..].try_into().unwrap();
    let (body, tag) = outer.payload.split_at(outer.payload.len() - 16);
    let tag: aead::Tag<aes_gcm::Aes128Gcm> = tag.try_into().unwrap();
    let mut inner = body.to_vec();
    cipher
        .decrypt_inout_detached(&nonce, &outer.aad, InOutBuf::from(&mut inner[..]), &tag)
        .ok()?;
    Some(inner)
}

/// Checks one party's key log file against the capture: its ECH records
/// decrypt the outer ClientHello's payload to the inner ClientHello, whose
/// random is `inner_random` and which names the hidden server.
fn assert_log_decrypts(path: &PathBuf, flight: &[u8], inner_random: &[u8]) {
    let records = read_log(path);
    let outer = outer_hello(flight);
    assert_ne!(outer.random, inner_random);
    let kem_secret = only(&records, "ECH_SECRET", &outer.random);
    let config = only(&records, "ECH_CONFIG", &outer.random);
    // No other ECH record, under any random.
    assert_eq!(
        records.iter().filter(|r| r.0.starts_with("ECH_")).count(),
        2
    );
    // X25519: `Nsecret` is 32 bytes; `enc`, the ephemeral public key, is
    // on the wire and is not what was logged.
    assert_eq!(kem_secret.len(), 32);
    assert_ne!(kem_secret, outer.enc);

    let inner = open_with_log(&outer, kem_secret, config).expect("the logged pair decrypts");
    // EncodedClientHelloInner: version, random, ...
    assert_eq!(&inner[2..34], inner_random);
    let hidden = SECRET.as_bytes();
    assert!(inner.windows(hidden.len()).any(|w| w == hidden));
    assert!(!flight.windows(hidden.len()).any(|w| w == hidden));

    // Nothing else opens it: a secret one bit off, another configuration
    // of the same shape, or any other secret of the file.
    let mut off = kem_secret.to_vec();
    off[0] ^= 1;
    assert!(open_with_log(&outer, &off, config).is_none());
    let mut other_config = config.to_vec();
    *other_config.last_mut().unwrap() ^= 1;
    assert!(open_with_log(&outer, kem_secret, &other_config).is_none());
    for (label, _, value) in &records {
        if !label.starts_with("ECH_") {
            assert!(open_with_log(&outer, value, config).is_none(), "{label}");
        }
    }
}

/// The inner ClientHello's random: what identifies the TLS secrets of a
/// connection that accepted ECH (RFC 9850 §2.1).
fn tls_random(path: &PathBuf) -> Vec<u8> {
    let records = read_log(path);
    let mut randoms: Vec<&Vec<u8>> = records
        .iter()
        .filter(|r| !r.0.starts_with("ECH_"))
        .map(|r| &r.1)
        .collect();
    randoms.dedup();
    assert_eq!(randoms.len(), 1);
    randoms[0].clone()
}

fn x25519_config(config_id: u8) -> Arc<EchServerConfig> {
    let key = EchServerKey::generate(config_id, PUBLIC, 32, &[DH_KEM_X25519_HKDF_SHA256_AES_128])
        .unwrap();
    Arc::new(EchServerConfig::new(vec![key]).unwrap())
}

#[test]
fn key_log_files_of_shared_mode_decrypt_the_captured_inner_hello() {
    init_logging();
    let certs = Certs::new();
    let dir = PrivateDir::new();
    let ech = x25519_config(7);
    let (client_log, client_path) = dir.log("client.log");
    let (server_log, server_path) = dir.log("server.log");
    let mut client_config = client_config(&certs, enable(ech.ech_config_list()));
    client_config.key_log = client_log;
    let mut server_config = server_config(&certs, Some(&ech), None);
    server_config.key_log = server_log;
    let (mut client, mut server) = connect(client_config, server_config);

    let flight = take_flight(&mut client);
    hello_wire::give(&mut server, &flight);
    server.process_new_packets().unwrap();
    assert_accepted(&mut client, &mut server);

    // Either party's file is enough, and both name the same inner random.
    let inner_random = tls_random(&client_path);
    assert_eq!(tls_random(&server_path), inner_random);
    assert_log_decrypts(&client_path, &flight, &inner_random);
    assert_log_decrypts(&server_path, &flight, &inner_random);
    assert_eq!(
        only(&read_log(&client_path), "ECH_CONFIG", &flight[11..43]),
        &ech.ech_config_list()[2..]
    );
}

#[test]
fn key_log_file_of_a_client_facing_server_decrypts_the_captured_inner_hello() {
    init_logging();
    let certs = Certs::new();
    let dir = PrivateDir::new();
    let ech = x25519_config(9);
    let (front_log, front_path) = dir.log("front.log");
    let (backend_log, backend_path) = dir.log("backend.log");
    let mut backend = backend_config(&certs, None);
    backend.key_log = backend_log;
    let mut split = Split::new(
        &certs,
        client_config(&certs, enable(ech.ech_config_list())),
        &ech,
        backend,
    );
    split.front = Some(ClientFacing::new(ech.clone()).with_key_log(front_log));
    let flight = take_flight(&mut split.client);
    split.front.as_mut().unwrap().read_client(&flight).unwrap();
    split.pump();
    split.assert_forwarded();

    // The client-facing server's file holds the two ECH records and
    // nothing else; the back-end server's holds the TLS secrets, under the
    // random that the decrypted inner ClientHello carries.
    assert_eq!(read_log(&front_path).len(), 2);
    let backend_records = read_log(&backend_path);
    assert!(backend_records.iter().all(|r| !r.0.starts_with("ECH_")));
    assert_log_decrypts(&front_path, &flight, &tls_random(&backend_path));
}

#[test]
fn key_log_file_of_a_rejected_offer_is_the_clients_alone() {
    init_logging();
    let certs = Certs::new();
    let dir = PrivateDir::new();
    let offered = x25519_config(7);
    let current = x25519_config(7);
    let (client_log, client_path) = dir.log("client.log");
    let (server_log, server_path) = dir.log("server.log");
    let mut client_config = client_config(&certs, enable(offered.ech_config_list()));
    client_config.key_log = client_log;
    let mut server_config = server_config(&certs, Some(&current), None);
    server_config.key_log = server_log;
    let (mut client, mut server) = connect(client_config, server_config);
    let flight = take_flight(&mut client);
    hello_wire::give(&mut server, &flight);
    server.process_new_packets().unwrap();
    expect_rejected(&mut client, &mut server);

    // The client's records still decrypt what it sent (RFC 9850 §2.3: it
    // logs regardless of acceptance); its TLS secrets are under the outer
    // random, as the server's are.
    let outer = outer_hello(&flight);
    let client_records = read_log(&client_path);
    let inner = open_with_log(
        &outer,
        only(&client_records, "ECH_SECRET", &outer.random),
        only(&client_records, "ECH_CONFIG", &outer.random),
    )
    .expect("the logged pair decrypts");
    assert_ne!(&inner[2..34], &outer.random[..]);
    assert_eq!(tls_random(&client_path), outer.random);
    assert_eq!(tls_random(&server_path), outer.random);
    assert!(
        read_log(&server_path)
            .iter()
            .all(|r| !r.0.starts_with("ECH_"))
    );
}
