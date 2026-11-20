use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use browntls_pki::CertificateDer;

use super::*;
use crate::msgs::handshake::CertificateUrlPayload;

/// Not SHA-1: the first 20 bytes, zero-padded. The checks only compare
/// what this returns; the real hashes are tested with the providers.
fn fake_sha1(data: &[u8]) -> [u8; SHA1_LEN] {
    let mut out = [0; SHA1_LEN];
    let n = data.len().min(SHA1_LEN);
    out[..n].copy_from_slice(&data[..n]);
    out
}

fn policy() -> ClientCertificateUrlPolicy {
    ClientCertificateUrlPolicy::new(fake_sha1)
}

// Two tiny DER SEQUENCEs standing in for certificates, and their PkiPath
// in TLS order [A, B]: B first, then A. Checked with
// `openssl asn1parse -inform DER` (SEQUENCE l=10 holding SEQUENCE INTEGER 2
// and SEQUENCE INTEGER 1).
const CERT_A: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x01];
const CERT_B: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x02];
const PKI_PATH_AB: [u8; 12] = [
    0x30, 0x0a, 0x30, 0x03, 0x02, 0x01, 0x02, 0x30, 0x03, 0x02, 0x01, 0x01,
];

fn ab() -> Vec<CertificateDer<'static>> {
    vec![
        CertificateDer::from(CERT_A.to_vec()),
        CertificateDer::from(CERT_B.to_vec()),
    ]
}

#[test]
fn pki_path_encoding_matches_vector() {
    let chain = [
        CertificateDer::from(CERT_A.to_vec()),
        CertificateDer::from(CERT_B.to_vec()),
    ];
    assert_eq!(encode_pki_path(&chain).unwrap(), PKI_PATH_AB);
    assert_eq!(decode_pki_path(&PKI_PATH_AB).unwrap(), chain);
}

#[test]
fn pki_path_with_long_lengths() {
    // A 203-byte element (`30 81 c8` and 200 content bytes) after CERT_A:
    // the outer SEQUENCE is `30 81 d0` (208 bytes), as `openssl asn1parse`
    // shows for the same bytes built with Python.
    let mut big = vec![0x30, 0x81, 200];
    big.extend([0x05, 0x00].repeat(100));
    let chain = [
        CertificateDer::from(big.clone()),
        CertificateDer::from(CERT_A.to_vec()),
    ];
    let der = encode_pki_path(&chain).unwrap();
    assert_eq!(der[..8], [0x30, 0x81, 0xd0, 0x30, 0x03, 0x02, 0x01, 0x01]);
    assert_eq!(der.len(), 3 + 208);
    assert_eq!(decode_pki_path(&der).unwrap(), chain);
}

#[test]
fn pki_path_decoding_is_strict() {
    let malformed = Err(Error::CertificateUrl(CertificateUrlError::MalformedPkiPath));
    let mut trailing = PKI_PATH_AB.to_vec();
    trailing.push(0);
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        // An empty SEQUENCE OF.
        vec![0x30, 0x00],
        // Not a SEQUENCE.
        vec![0x31, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01],
        // An element that is not a SEQUENCE.
        vec![0x30, 0x03, 0x02, 0x01, 0x01],
        // Indefinite length.
        vec![0x30, 0x80, 0x30, 0x03, 0x02, 0x01, 0x01, 0x00, 0x00],
        // Non-minimal lengths, outer and inner.
        vec![0x30, 0x81, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01],
        vec![0x30, 0x06, 0x30, 0x81, 0x03, 0x02, 0x01, 0x01],
        vec![0x30, 0x82, 0x00, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01],
        // An element running past the end.
        vec![0x30, 0x05, 0x30, 0x04, 0x02, 0x01, 0x01],
        // Bytes after the SEQUENCE.
        trailing,
        // Truncated.
        PKI_PATH_AB[..11].to_vec(),
    ];
    for der in cases {
        assert_eq!(decode_pki_path(&der), malformed, "{der:x?}");
    }
    // At most 16 certificates.
    let sixteen = encode_pki_path(&vec![CertificateDer::from(CERT_A.to_vec()); 16]).unwrap();
    assert_eq!(decode_pki_path(&sixteen).unwrap().len(), 16);
    let mut contents = Vec::new();
    for _ in 0..17 {
        contents.extend(CERT_A);
    }
    let seventeen = crate::x509::wrap_in_sequence(&contents);
    assert_eq!(decode_pki_path(&seventeen), malformed);
    assert!(encode_pki_path(&vec![CertificateDer::from(CERT_A.to_vec()); 17]).is_err());
    assert!(encode_pki_path(&[]).is_err());
    assert!(encode_pki_path(&[CertificateDer::from(vec![0x30, 0x00, 0x00])]).is_err());
}

#[test]
fn url_and_hash_validation() {
    assert!(UrlAndHash::new("http://a.example/c.der", [0; 20]).is_ok());
    for bad in ["", "http://a b", "http://\u{e9}", "http://a\n"] {
        assert!(UrlAndHash::new(bad, [0; 20]).is_err(), "{bad:?}");
    }
    assert!(UrlAndHash::new("h".repeat(0x1_0000), [0; 20]).is_err());
    let entry = UrlAndHash::for_object("http://x", &CERT_A, fake_sha1).unwrap();
    assert_eq!(entry.sha1_hash(), &fake_sha1(&CERT_A));
    assert_eq!(entry.url(), "http://x");
}

#[test]
fn certificate_url_construction() {
    let entry = UrlAndHash::new("http://x", [1; 20]).unwrap();
    assert!(CertificateUrl::individual_certs(Vec::new()).is_err());
    let urls = CertificateUrl::individual_certs(vec![entry.clone(), entry.clone()]).unwrap();
    assert_eq!(urls.chain_type(), CertChainType::IndividualCerts);
    assert_eq!(urls.entries().len(), 2);
    let path = CertificateUrl::pkipath(entry).unwrap();
    assert_eq!(path.chain_type(), CertChainType::PkiPath);
    // The list may take at most 65535 bytes.
    let long = UrlAndHash::new("h".repeat(0xffff - 23), [0; 20]).unwrap();
    assert!(CertificateUrl::pkipath(long.clone()).is_ok());
    let longer = UrlAndHash::new("h".repeat(0xffff - 22), [0; 20]).unwrap();
    assert!(CertificateUrl::pkipath(longer).is_err());
    assert!(CertificateUrl::individual_certs(vec![long.clone(), long]).is_err());
}

#[test]
fn policy_checks() {
    assert!(check_policy(None).is_ok());
    assert!(check_policy(Some(&policy())).is_ok());
    for change in [
        |p: &mut ClientCertificateUrlPolicy| p.max_urls = 0,
        |p: &mut ClientCertificateUrlPolicy| p.max_url_len = 0,
        |p: &mut ClientCertificateUrlPolicy| p.max_fetched_len = 0,
        |p: &mut ClientCertificateUrlPolicy| p.allowed_schemes.clear(),
        |p: &mut ClientCertificateUrlPolicy| p.allowed_schemes = vec![String::new()],
        |p: &mut ClientCertificateUrlPolicy| p.allowed_schemes = vec!["ht tp".into()],
    ] {
        let mut p = policy();
        change(&mut p);
        assert!(check_policy(Some(&p)).is_err());
    }
}

#[test]
fn url_policy() {
    let mut p = policy();
    for ok in [
        "http://a.example/c.der",
        "HTTP://a.example",
        "http://a.example:8080/x?y=z",
        "http://[::1]/x",
    ] {
        assert!(!refused_url(&p, ok.as_bytes()), "{ok}");
    }
    let too_long = alloc::format!("http://a/{}", "x".repeat(2048));
    for bad in [
        too_long.as_str(),
        "https://a.example/",
        "ftp://a.example/",
        "a.example/c.der",
        "://a.example/",
        "1http://a/",
        "http:/a/",
        "http:a",
        "http:///x",
        "http://?x",
        "http://user@a.example/",
        "http://user:pw@a.example/",
        "http://a.example/#frag",
        "http://a.example\\@b/",
        "http://a.example/ x",
        "http://a.example/\u{7f}",
    ] {
        assert!(refused_url(&p, bad.as_bytes()), "{bad}");
    }
    assert!(refused_url(&p, b"http://a/\xff"));
    p.allowed_schemes.push("HTTPS".into());
    assert!(!refused_url(&p, b"https://a.example/"));
}

fn payload(chain_type: CertChainType, urls: &[(&str, &[u8])]) -> CertificateUrlPayload {
    let entries = urls
        .iter()
        .map(|(url, object)| UrlAndHash::new(*url, fake_sha1(object)).unwrap())
        .collect::<Vec<_>>();
    let urls = match chain_type {
        CertChainType::IndividualCerts => CertificateUrl::individual_certs(entries),
        CertChainType::PkiPath => CertificateUrl::pkipath(entries[0].clone()),
    };
    CertificateUrlPayload::from(&urls.unwrap())
}

#[test]
fn pending_query_checks() {
    let p = policy();
    let message = payload(
        CertChainType::IndividualCerts,
        &[("http://a/1", &CERT_A), ("http://a/2", &CERT_B)],
    );
    let pending = || PendingCertificateUrl::new(&p, &message).unwrap();
    let query = pending().query().clone();
    assert_eq!(query.entries()[1].url(), "http://a/2");
    assert_ne!(pending().query().id(), query.id());

    let fetched = |objects: &[&[u8]]| {
        ClientCertificateUrlResponse::Fetched(objects.iter().map(|o| o.to_vec()).collect())
    };
    let chain = pending().into_chain(fetched(&[&CERT_A, &CERT_B])).unwrap();
    assert_eq!(chain.0, ab());
    let err = |response| pending().into_chain(response).unwrap_err();
    assert_eq!(
        err(ClientCertificateUrlResponse::Unobtainable),
        CertificateUrlError::Unobtainable
    );
    assert_eq!(
        err(fetched(&[&CERT_A])),
        CertificateUrlError::WrongObjectCount
    );
    assert_eq!(
        err(fetched(&[&CERT_B, &CERT_A])),
        CertificateUrlError::HashMismatch
    );
    let mut small = policy();
    small.max_fetched_len = 9;
    let over = PendingCertificateUrl::new(&small, &message).unwrap();
    assert_eq!(
        over.into_chain(fetched(&[&CERT_A, &CERT_B])).unwrap_err(),
        CertificateUrlError::FetchedTooLarge
    );

    // Too many URLs, or one the policy refuses, make no query.
    let mut one = policy();
    one.max_urls = 1;
    assert_eq!(
        PendingCertificateUrl::new(&one, &message).err(),
        Some(CertificateUrlError::RefusedByPolicy)
    );
    let refused = payload(CertChainType::IndividualCerts, &[("ftp://a/1", &CERT_A)]);
    assert_eq!(
        PendingCertificateUrl::new(&p, &refused).err(),
        Some(CertificateUrlError::RefusedByPolicy)
    );
}

#[test]
fn pending_pki_path() {
    let p = policy();
    let message = payload(CertChainType::PkiPath, &[("http://a/p", &PKI_PATH_AB)]);
    let pending = PendingCertificateUrl::new(&p, &message).unwrap();
    let chain = pending
        .into_chain(ClientCertificateUrlResponse::Fetched(vec![
            PKI_PATH_AB.to_vec(),
        ]))
        .unwrap();
    assert_eq!(chain.0, ab());

    // A malformed object with the right hash.
    let mut bad = PKI_PATH_AB.to_vec();
    bad.push(0);
    let message = payload(CertChainType::PkiPath, &[("http://a/p", &bad)]);
    let pending = PendingCertificateUrl::new(&p, &message).unwrap();
    assert_eq!(
        pending
            .into_chain(ClientCertificateUrlResponse::Fetched(vec![bad]))
            .unwrap_err(),
        CertificateUrlError::MalformedPkiPath
    );
}

#[test]
fn alerts() {
    use crate::enums::AlertDescription;
    for (err, alert) in [
        (CertificateUrlError::RefusedByPolicy, 111),
        (CertificateUrlError::Unobtainable, 111),
        (CertificateUrlError::WrongObjectCount, 111),
        (CertificateUrlError::FetchedTooLarge, 111),
        (CertificateUrlError::HashMismatch, 114),
        (CertificateUrlError::MalformedPkiPath, 42),
    ] {
        assert_eq!(u8::from(AlertDescription::from(err)), alert);
        assert!(!alloc::format!("{}", Error::from(err)).is_empty());
    }
    assert_eq!(
        AlertDescription::from(crate::error::InvalidMessage::IllegalCertificateUrlPadding),
        AlertDescription::IllegalParameter
    );
    assert_eq!(
        AlertDescription::from(crate::error::InvalidMessage::IllegalPkiPathUrlCount),
        AlertDescription::IllegalParameter
    );
    assert_eq!(
        AlertDescription::from(crate::error::InvalidMessage::UnknownCertChainType),
        AlertDescription::DecodeError
    );
}
