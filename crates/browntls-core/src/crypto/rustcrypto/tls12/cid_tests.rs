//! Negative CID conformance with fixtures sealed by RustCrypto primitives.

use super::*;
use crate::crypto::cipher::dtls12::tests::{fixture_nonce, reject_invalid_records};

fn reject<A: TlsAead>(alg: &dyn Tls12AeadAlgorithm) {
    let explicit_len = alg.key_block_shape().explicit_nonce_len;
    let cipher = A::new_from_slice(&[9; 32][..A::key_size()]).unwrap();
    let nonce = fixture_nonce(explicit_len);
    reject_invalid_records(alg, |inner, aad| {
        let mut text = inner.to_vec();
        let tag = cipher
            .encrypt_inout_detached(&nonce.into(), aad, InOutBuf::from(&mut text[..]))
            .unwrap();
        let mut body = alloc::vec::Vec::new();
        if explicit_len == 8 {
            body.extend_from_slice(&nonce[4..]);
        }
        body.extend_from_slice(&text);
        body.extend_from_slice(&tag);
        body
    });
}

#[test]
fn cid_rejects_nonconforming_records() {
    reject::<aes_gcm::Aes128Gcm>(&AES_128_GCM);
    reject::<aes_gcm::Aes256Gcm>(&AES_256_GCM);
    reject::<chacha20poly1305::ChaCha20Poly1305>(&CHACHA20_POLY1305);
}
