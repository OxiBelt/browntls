//! Tests of the wire format and the signed message.

use super::*;

fn sample() -> DelegatedCredential {
    DelegatedCredential {
        credential: Credential {
            valid_time: 0x0102_0304,
            dc_cert_verify_algorithm: SignatureScheme::ECDSA_NISTP256_SHA256,
            public_key: SubjectPublicKeyInfoDer::from(alloc::vec![0x30, 0x01, 0x00]),
        },
        algorithm: SignatureScheme::ED25519,
        signature: alloc::vec![9, 8, 7],
    }
}

#[test]
fn wire_format() {
    let dc = sample();
    let bytes = dc.to_bytes().unwrap();
    assert_eq!(
        bytes,
        [
            1, 2, 3, 4, // valid_time
            0x04, 0x03, // ecdsa_secp256r1_sha256
            0, 0, 3, 0x30, 0x01, 0x00, // ASN1_subjectPublicKeyInfo
            0x08, 0x07, // ed25519
            0, 3, 9, 8, 7, // signature
        ]
    );
    assert_eq!(DelegatedCredential::from_bytes(&bytes).unwrap(), dc);
}

#[test]
fn rejects_malformed() {
    let bytes = sample().to_bytes().unwrap();
    // Truncated anywhere.
    for len in 0..bytes.len() {
        assert!(
            DelegatedCredential::from_bytes(&bytes[..len]).is_err(),
            "{len}"
        );
    }
    // Trailing data.
    let mut long = bytes.clone();
    long.push(0);
    assert!(DelegatedCredential::from_bytes(&long).is_err());
    // Empty public key and empty signature.
    let empty_spki = [1, 2, 3, 4, 4, 3, 0, 0, 0, 8, 7, 0, 1, 1];
    assert_eq!(
        DelegatedCredential::from_bytes(&empty_spki),
        Err(InvalidMessage::IllegalEmptyValue)
    );
    let empty_sig = [1, 2, 3, 4, 4, 3, 0, 0, 1, 0, 8, 7, 0, 0];
    assert_eq!(
        DelegatedCredential::from_bytes(&empty_sig),
        Err(InvalidMessage::IllegalEmptyValue)
    );
    // A public key above the local bound.
    let huge = [1, 2, 3, 4, 4, 3, 0, 0x40, 1];
    assert_eq!(
        DelegatedCredential::from_bytes(&huge),
        Err(InvalidMessage::MessageTooLarge)
    );
}

#[test]
fn encoding_checks_the_enclosing_extension_limit() {
    let mut dc = sample();
    let max_sig = usize::from(u16::MAX)
        - EXTENSION_HEADER_LEN
        - CREDENTIAL_OVERHEAD
        - dc.credential.public_key.as_ref().len();
    dc.signature.resize(max_sig, 1);
    assert_eq!(dc.encoded_extension_len(), Ok(usize::from(u16::MAX)));
    let encoded = dc.to_bytes().unwrap();
    assert_eq!(DelegatedCredential::from_bytes(&encoded), Ok(dc.clone()));
    dc.signature.push(1);
    assert_eq!(
        dc.to_bytes(),
        Err(Error::InvalidDelegatedCredential(
            AttachmentError::InvalidEncoding
        ))
    );
}

#[test]
fn signed_message_layout() {
    let dc = sample();
    let cert = CertificateDer::from_slice(&[0xaa, 0xbb]);
    let msg =
        DelegatedCredential::signed_message(Side::Server, &cert, &dc.credential, dc.algorithm);
    assert!(msg[..64].iter().all(|b| *b == 0x20));
    let rest = &msg[64..];
    assert!(rest.starts_with(b"TLS, server delegated credentials\0\xaa\xbb"));
    let tail = &rest[SERVER_CONTEXT.len() + 3..];
    assert_eq!(&tail[..tail.len() - 2], dc.credential.get_encoding());
    assert_eq!(&tail[tail.len() - 2..], [0x08, 0x07]);
    let client =
        DelegatedCredential::signed_message(Side::Client, &cert, &dc.credential, dc.algorithm);
    assert!(client[64..].starts_with(CLIENT_CONTEXT));
}

#[test]
fn expiry_arithmetic() {
    let nb = UnixTime::since_unix_epoch(Duration::from_secs(1000));
    assert_eq!(expiry_from(nb, 5).as_secs(), 1005);
    assert_eq!(
        expiry_from(UnixTime::since_unix_epoch(Duration::from_secs(u64::MAX)), 5).as_secs(),
        u64::MAX
    );
}
