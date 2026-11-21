//! Negative CID conformance with fixtures sealed by native primitives.

use super::*;
use crate::crypto::cipher::dtls12::tests::{fixture_nonce, reject_invalid_records};

fn reject<A: Aead>(alg: &dyn Tls12AeadAlgorithm) {
    let explicit_len = alg.key_block_shape().explicit_nonce_len;
    let cipher = A::new(&[9; 32][..A::KEY_LEN]).unwrap();
    let nonce = fixture_nonce(explicit_len);
    reject_invalid_records(alg, |inner, aad| {
        let mut text = inner.to_vec();
        let tag = cipher.seal_in_place(&nonce, aad, &mut text).unwrap();
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
    reject::<Aes128Gcm>(&AES_128_GCM);
    reject::<Aes256Gcm>(&AES_256_GCM);
    reject::<ChaCha20Poly1305>(&CHACHA20_POLY1305);
}
