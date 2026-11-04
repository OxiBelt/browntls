//! Differential tests of the native provider's key exchange groups against
//! the RustCrypto provider (and, for ML-KEM-1024, the `ml-kem` crate), plus
//! rejection of invalid peer key shares.

#![cfg(all(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls::crypto::{SupportedKxGroup, native, rustcrypto};
use browntls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};
use ml_kem::{Decapsulate, KeyExport};

fn invalid() -> Error {
    Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
}

fn random_vec(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    native::SECURE_RANDOM.fill(&mut out).unwrap();
    out
}

/// The groups both providers implement.
fn common_groups() -> Vec<(&'static dyn SupportedKxGroup, &'static dyn SupportedKxGroup)> {
    let pairs: Vec<_> = rustcrypto::ALL_KX_GROUPS
        .iter()
        .map(|r| {
            let n = native::ALL_KX_GROUPS
                .iter()
                .find(|n| n.name() == r.name())
                .expect("native implements every RustCrypto group");
            (*n, *r)
        })
        .collect();
    assert_eq!(pairs.len(), 7);
    pairs
}

/// Runs `client` against `server` and checks both derive the same secret.
fn agree(client: &dyn SupportedKxGroup, server: &dyn SupportedKxGroup) {
    let kx = client.start().unwrap();
    assert_eq!(kx.group(), client.name());
    let completed = server.start_and_complete(kx.pub_key()).unwrap();
    assert_eq!(completed.group, server.name());
    let secret = kx.complete(&completed.pub_key).unwrap();
    assert_eq!(secret.secret_bytes(), completed.secret.secret_bytes());
    assert!(secret.secret_bytes().iter().any(|b| *b != 0));
}

#[test]
fn every_common_group_interoperates_both_ways() {
    for (n, r) in common_groups() {
        assert_eq!(
            n.usable_for_version(ProtocolVersion::TLSv1_2),
            r.usable_for_version(ProtocolVersion::TLSv1_2),
            "{n:?}"
        );
        for _ in 0..8 {
            agree(n, r);
            agree(r, n);
            agree(n, n);
        }
    }
}

#[cfg(feature = "tls12")]
#[test]
fn tls12_completion_matches() {
    // TLS 1.2 ECDHE completion goes through `complete_for_tls_version`.
    for (n, r) in common_groups() {
        if !n.usable_for_version(ProtocolVersion::TLSv1_2) {
            continue;
        }
        let client = n.start().unwrap();
        let server = r.start().unwrap();
        let client_pub = client.pub_key().to_vec();
        let a = client
            .complete_for_tls_version(server.pub_key(), &browntls::version::TLS12)
            .unwrap();
        let b = server.complete(&client_pub).unwrap();
        assert_eq!(a.secret_bytes(), b.secret_bytes());
    }
}

#[test]
fn hybrid_classical_components_interoperate() {
    for (hybrid, classical) in [
        (
            native::kx_group::X25519MLKEM768,
            rustcrypto::kx_group::X25519,
        ),
        (
            native::kx_group::SECP256R1MLKEM768,
            rustcrypto::kx_group::SECP256R1,
        ),
        (
            native::kx_group::SECP384R1MLKEM1024,
            rustcrypto::kx_group::SECP384R1,
        ),
    ] {
        let kx = hybrid.start().unwrap();
        let (group, share) = kx.hybrid_component().unwrap();
        assert_eq!(group, classical.name());
        let server = classical.start_and_complete(share).unwrap();
        let secret = kx.complete_hybrid_component(&server.pub_key).unwrap();
        assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
    }
    // And the other way round: RustCrypto's hybrid offers a classical share
    // the native classical group accepts.
    let kx = rustcrypto::kx_group::X25519MLKEM768.start().unwrap();
    let (_, share) = kx.hybrid_component().unwrap();
    let server = native::kx_group::X25519.start_and_complete(share).unwrap();
    let secret = kx.complete_hybrid_component(&server.pub_key).unwrap();
    assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
}

// ML-KEM-1024 is not offered by the RustCrypto provider; use the `ml-kem`
// crate directly as the oracle.

type Dk1024 = ml_kem::ml_kem_1024::DecapsulationKey;
type Ek1024 = ml_kem::ml_kem_1024::EncapsulationKey;

fn oracle_mlkem1024_client() -> (Dk1024, Vec<u8>) {
    let mut seed = ml_kem::Seed::default();
    native::SECURE_RANDOM.fill(&mut seed).unwrap();
    let dk = Dk1024::from_seed(seed);
    let ek = dk.encapsulation_key().to_bytes().to_vec();
    (dk, ek)
}

fn oracle_mlkem1024_server(client_share: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let ek_bytes: ml_kem::Key<Ek1024> = client_share.try_into().unwrap();
    let ek = Ek1024::new(&ek_bytes).unwrap();
    let mut m = ml_kem::B32::default();
    native::SECURE_RANDOM.fill(&mut m).unwrap();
    let (ct, ss) = ek.encapsulate_deterministic(&m);
    (ct.to_vec(), ss.to_vec())
}

#[test]
fn mlkem1024_interoperates_with_ml_kem_crate() {
    let group = native::kx_group::MLKEM1024;
    assert_eq!(group.name(), NamedGroup::MLKEM1024);
    for _ in 0..8 {
        // native client, oracle server
        let kx = group.start().unwrap();
        let (ct, ss) = oracle_mlkem1024_server(kx.pub_key());
        assert_eq!(kx.complete(&ct).unwrap().secret_bytes(), &ss[..]);

        // oracle client, native server
        let (dk, ek) = oracle_mlkem1024_client();
        let completed = group.start_and_complete(&ek).unwrap();
        let ss = dk.decapsulate_slice(&completed.pub_key).unwrap();
        assert_eq!(completed.secret.secret_bytes(), ss.as_slice());
    }
}

#[test]
fn secp384r1mlkem1024_interoperates_with_composed_oracle() {
    // draft-ietf-tls-ecdhe-mlkem: client share = P-384 point (97) || ML-KEM-1024
    // encapsulation key (1568); server share = P-384 point || ciphertext
    // (1568); secret = ECDH secret (48) || ML-KEM secret (32).
    let group = native::kx_group::SECP384R1MLKEM1024;
    assert_eq!(
        group.name(),
        NamedGroup::from(native::kx_group::SECP384R1MLKEM1024_CODEPOINT)
    );
    for _ in 0..4 {
        // native client, oracle server
        let kx = group.start().unwrap();
        let (ecdh_share, pq_share) = kx.pub_key().split_at(97);
        let ecdh = rustcrypto::kx_group::SECP384R1
            .start_and_complete(ecdh_share)
            .unwrap();
        let (ct, ss) = oracle_mlkem1024_server(pq_share);
        let mut reply = ecdh.pub_key.clone();
        reply.extend_from_slice(&ct);
        let mut expected = ecdh.secret.secret_bytes().to_vec();
        expected.extend_from_slice(&ss);
        assert_eq!(kx.complete(&reply).unwrap().secret_bytes(), &expected[..]);

        // oracle client, native server
        let ecdh_client = rustcrypto::kx_group::SECP384R1.start().unwrap();
        let (dk, ek) = oracle_mlkem1024_client();
        let mut share = ecdh_client.pub_key().to_vec();
        share.extend_from_slice(&ek);
        let completed = group.start_and_complete(&share).unwrap();
        assert_eq!(completed.pub_key.len(), 97 + 1568);
        let (ecdh_reply, ct) = completed.pub_key.split_at(97);
        let mut expected = ecdh_client
            .complete(ecdh_reply)
            .unwrap()
            .secret_bytes()
            .to_vec();
        expected.extend_from_slice(dk.decapsulate_slice(ct).unwrap().as_slice());
        assert_eq!(completed.secret.secret_bytes(), &expected[..]);
    }
}

/// Little-endian u-coordinates of small order (and their non-canonical
/// encodings): X25519 with any clamped scalar yields an all-zero output.
const X25519_LOW_ORDER: &[&str] = &[
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

#[test]
fn x25519_low_order_points_are_rejected_like_rustcrypto() {
    for hex_point in X25519_LOW_ORDER {
        let point = hex::decode(hex_point).unwrap();
        for group in [native::kx_group::X25519, rustcrypto::kx_group::X25519] {
            assert_eq!(
                group.start().unwrap().complete(&point).unwrap_err(),
                invalid(),
                "{group:?} accepted {hex_point}"
            );
            assert_eq!(
                group.start_and_complete(&point).unwrap_err(),
                invalid(),
                "{group:?} accepted {hex_point}"
            );
        }
        // Also inside the hybrid share.
        let client = native::kx_group::X25519MLKEM768.start().unwrap();
        let mut share = client.pub_key().to_vec();
        share[1184..].copy_from_slice(&point);
        assert_eq!(
            native::kx_group::X25519MLKEM768
                .start_and_complete(&share)
                .unwrap_err(),
            invalid()
        );
    }
}

#[test]
fn malformed_shares_are_rejected_by_both_providers() {
    for (n, r) in common_groups() {
        let peer = r.start().unwrap();
        let good_client = peer.pub_key().to_vec();
        let good_server = n.start_and_complete(&good_client).unwrap().pub_key;

        let mut client_cases = vec![
            Vec::new(),
            vec![0u8; 1],
            good_client[..good_client.len() - 1].to_vec(),
            [&good_client[..], &[0]].concat(),
            vec![0u8; good_client.len()],
            vec![0xffu8; good_client.len()],
        ];
        let server_cases = vec![
            Vec::new(),
            good_server[..good_server.len() - 1].to_vec(),
            [&good_server[..], &[0]].concat(),
        ];
        // An all-0xff ML-KEM encapsulation key fails the modulus check; for
        // the ECDH groups it is not a valid point. For pure ML-KEM an all-zero
        // key is valid, so only use it where an ECDH part is present.
        if n.name() == NamedGroup::MLKEM768 {
            client_cases.retain(|c| c.iter().any(|b| *b != 0) || c.is_empty());
        }
        // For X25519 every 32-byte string is a valid u-coordinate (all 0xff
        // decodes to u = 18 after masking bit 255), so drop that case.
        if n.name() == NamedGroup::X25519 {
            client_cases.retain(|c| !(c.len() == 32 && c.iter().all(|b| *b == 0xff)));
        }

        for case in &client_cases {
            for group in [n, r] {
                assert!(
                    group.start_and_complete(case).is_err(),
                    "{group:?} server accepted a {}-byte share",
                    case.len()
                );
            }
        }
        for case in &server_cases {
            for group in [n, r] {
                assert!(
                    group.start().unwrap().complete(case).is_err(),
                    "{group:?} client accepted a {}-byte share",
                    case.len()
                );
            }
        }
    }
}

#[test]
fn nist_point_validation_matches() {
    for (n, r, field) in [
        (
            native::kx_group::SECP256R1,
            rustcrypto::kx_group::SECP256R1,
            32,
        ),
        (
            native::kx_group::SECP384R1,
            rustcrypto::kx_group::SECP384R1,
            48,
        ),
        (
            native::kx_group::SECP521R1,
            rustcrypto::kx_group::SECP521R1,
            66,
        ),
    ] {
        for _ in 0..16 {
            let good = r.start().unwrap().pub_key().to_vec();
            assert_eq!(good.len(), 1 + 2 * field);

            // Off the curve: flip a bit of y.
            let mut off = good.clone();
            off[2 * field] ^= 1;
            // Compressed form, even when the length is padded back.
            let mut compressed = good[..1 + field].to_vec();
            compressed[0] = 0x02 | (good[2 * field] & 1);
            let mut compressed_padded = compressed.clone();
            compressed_padded.resize(good.len(), 0);
            // Hybrid form (0x06/0x07).
            let mut hybrid_form = good.clone();
            hybrid_form[0] = 0x06 | (good[2 * field] & 1);
            // x >= p.
            let mut big_x = good.clone();
            big_x[1..1 + field].fill(0xff);
            // Random bytes with the right prefix: almost never on the curve.
            let mut noise = random_vec(good.len());
            noise[0] = 0x04;

            for case in [&off, &compressed, &compressed_padded, &hybrid_form, &big_x] {
                for group in [n, r] {
                    assert_eq!(
                        group.start().unwrap().complete(case).unwrap_err(),
                        invalid(),
                        "{group:?}"
                    );
                }
            }
            let n_result = n.start().unwrap().complete(&noise).is_ok();
            let r_result = r.start().unwrap().complete(&noise).is_ok();
            assert_eq!(n_result, r_result);
        }
    }
}

#[test]
fn mlkem_ciphertext_handling_matches() {
    let n = native::kx_group::MLKEM768;
    let r = rustcrypto::kx_group::MLKEM768;
    // A tampered ciphertext of the right length gives the implicit-rejection
    // secret in both implementations (identical, since it depends only on
    // the decapsulation key and the ciphertext): check the native client
    // disagrees with the server's secret.
    let kx = n.start().unwrap();
    let completed = r.start_and_complete(kx.pub_key()).unwrap();
    let mut ct = completed.pub_key.clone();
    ct[100] ^= 0x40;
    let secret = kx.complete(&ct).unwrap();
    assert_ne!(secret.secret_bytes(), completed.secret.secret_bytes());

    // Encapsulation keys with an unreduced coefficient (>= q) are rejected by
    // both servers.
    let mut ek = n.start().unwrap().pub_key().to_vec();
    ek[0] = 0xff;
    ek[1] |= 0x0f;
    for group in [n, r] {
        assert_eq!(group.start_and_complete(&ek).unwrap_err(), invalid());
    }
}

#[test]
fn default_and_all_groups() {
    let names: Vec<_> = native::DEFAULT_KX_GROUPS.iter().map(|g| g.name()).collect();
    let pos = |n: NamedGroup| names.iter().position(|x| *x == n).unwrap();
    #[cfg(feature = "prefer-post-quantum")]
    assert_eq!(names[0], NamedGroup::X25519MLKEM768);
    // Without the feature the hybrid follows the classical groups.
    #[cfg(not(feature = "prefer-post-quantum"))]
    assert!(pos(NamedGroup::X25519MLKEM768) > pos(NamedGroup::secp384r1));
    // The optional RFC 9846 groups (X448, then FFDHE) come after every other
    // group.
    assert!(pos(NamedGroup::X25519MLKEM768) < pos(NamedGroup::X448));
    assert!(pos(NamedGroup::X25519) < pos(NamedGroup::X448));
    assert!(pos(NamedGroup::X448) < pos(NamedGroup::FFDHE2048));
    assert_eq!(native::ALL_KX_GROUPS.len(), 15);
}
