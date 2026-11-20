use alloc::vec;

use super::*;

#[derive(Debug)]
struct NoKey;

impl SigningKey for NoKey {
    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        None
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

fn certified_key(chain_len: u8) -> CertifiedKey {
    let chain = (0..chain_len)
        .map(|i| CertificateDer::from(vec![i]))
        .collect();
    CertifiedKey::new(chain, Arc::new(NoKey))
}

#[test]
fn spki_encoding() {
    let spki = public_key_to_spki(&browntls_pki::alg_id::ED25519, [0xaa; 32]);
    let (alg, key) = x509::split_spki(spki.as_ref()).unwrap();
    assert_eq!(alg, browntls_pki::alg_id::ED25519.as_bytes());
    assert_eq!(key, [0xaa; 32]);
}

#[test]
fn ocsp_by_chain_index() {
    let mut key = certified_key(3);
    assert_eq!(key.ocsp_for(0), None);
    assert_eq!(key.ocsp_for(2), None);

    // Index 0 is the public `ocsp` field, in both directions.
    key.set_ocsp_for(0, Some(vec![1])).unwrap();
    assert_eq!(key.ocsp.as_deref(), Some(&[1][..]));
    key.ocsp = Some(vec![2]);
    assert_eq!(key.ocsp_for(0), Some(&[2][..]));

    // A later index does not need the earlier ones.
    key.set_ocsp_for(2, Some(vec![3, 4])).unwrap();
    assert_eq!(key.ocsp_for(1), None);
    assert_eq!(key.ocsp_for(2), Some(&[3, 4][..]));
    key.set_ocsp_for(1, Some(vec![5])).unwrap();
    assert_eq!(key.ocsp_for(1), Some(&[5][..]));
    assert_eq!(key.ocsp_for(2), Some(&[3, 4][..]));
    assert_eq!(key.ocsp.as_deref(), Some(&[2][..]));

    // Removal: `None` or an empty response.
    key.set_ocsp_for(1, None).unwrap();
    assert_eq!(key.ocsp_for(1), None);
    key.set_ocsp_for(2, Some(Vec::new())).unwrap();
    assert_eq!(key.ocsp_for(2), None);
    key.set_ocsp_for(0, Some(Vec::new())).unwrap();
    assert_eq!(key.ocsp, None);
    key.ocsp = Some(Vec::new());
    assert_eq!(key.ocsp_for(0), None);
}

#[test]
fn ocsp_needs_a_certificate() {
    let mut key = certified_key(2);
    assert!(key.set_ocsp_for(2, Some(vec![1])).is_err());
    assert!(key.set_ocsp_for(usize::MAX, Some(vec![1])).is_err());
    assert_eq!(key.ocsp_for(2), None);
    assert_eq!(key.ocsp_for(usize::MAX), None);
    assert!(certified_key(0).set_ocsp_for(0, Some(vec![1])).is_err());

    // A response does not outlive the certificate it was set for.
    key.set_ocsp_for(1, Some(vec![1])).unwrap();
    key.cert.truncate(1);
    assert_eq!(key.ocsp_for(1), None);
}

#[test]
fn ocsp_response_size_limit() {
    let mut key = certified_key(2);
    key.set_ocsp_for(1, Some(vec![0; MAX_OCSP_RESPONSE_LEN]))
        .unwrap();
    assert!(
        key.set_ocsp_for(1, Some(vec![0; MAX_OCSP_RESPONSE_LEN + 1]))
            .is_err()
    );
    // The rejected response did not replace the accepted one.
    assert_eq!(
        key.ocsp_for(1).map(<[u8]>::len),
        Some(MAX_OCSP_RESPONSE_LEN)
    );
}

#[test]
fn sct_list_is_validated() {
    let mut key = certified_key(1);
    assert_eq!(key.sct_list(), None);
    let scts = vec![0, 3, 0, 1, 0xaa];
    key.set_sct_list(Some(scts.clone())).unwrap();
    assert_eq!(key.sct_list(), Some(&scts[..]));

    // Malformed lists are refused and leave the configured one in place.
    for bad in [&[][..], &[0, 0], &[0, 2, 0, 0], &[0, 3, 0, 1], &[0xaa]] {
        assert!(key.set_sct_list(Some(bad.to_vec())).is_err());
        assert_eq!(key.sct_list(), Some(&scts[..]));
    }

    key.set_sct_list(None).unwrap();
    assert_eq!(key.sct_list(), None);
}

#[test]
fn clones_keep_evidence() {
    let mut key = certified_key(2);
    key.set_ocsp_for(1, Some(vec![9])).unwrap();
    key.set_sct_list(Some(vec![0, 3, 0, 1, 0xaa])).unwrap();
    let clone = key.clone();
    assert_eq!(clone.ocsp_for(1), Some(&[9][..]));
    assert_eq!(clone.sct_list(), key.sct_list());
}
