//! SHA-2 known-answer and differential tests.
#![allow(clippy::cast_possible_truncation)]

use browntls_crypto::hash::{Digest, Sha256, Sha384, Sha512};

fn check<D: Digest>(input: &[u8], expected: &str) {
    assert_eq!(hex::encode(D::digest(input)), expected);
    // Same input fed in irregular pieces.
    let mut h = D::new();
    for chunk in input.chunks(7) {
        h.update(chunk);
    }
    assert_eq!(hex::encode(h.finalize()), expected);
}

#[test]
fn fips180_examples() {
    check::<Sha256>(
        b"",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    check::<Sha256>(
        b"abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    check::<Sha256>(
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
    check::<Sha384>(
        b"abc",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    );
    check::<Sha512>(
        b"abc",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );
    check::<Sha512>(
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
    );
}

#[test]
fn million_a() {
    let input = vec![b'a'; 1_000_000];
    check::<Sha256>(
        &input,
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    );
}

#[test]
fn differential_lengths() {
    use sha2::Digest as _;
    let data: Vec<u8> = (0..1100u32).map(|i| (i * 31 + 7) as u8).collect();
    for len in 0..data.len() {
        let input = &data[..len];
        assert_eq!(
            Sha256::digest(input).as_slice(),
            sha2::Sha256::digest(input).as_slice()
        );
        assert_eq!(
            Sha384::digest(input).as_slice(),
            sha2::Sha384::digest(input).as_slice()
        );
        assert_eq!(
            Sha512::digest(input).as_slice(),
            sha2::Sha512::digest(input).as_slice()
        );
    }
}
