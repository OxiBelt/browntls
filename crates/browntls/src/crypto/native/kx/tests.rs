//! Tests of the native key exchange groups.

use super::*;

fn all() -> [&'static dyn SupportedKxGroup; 10] {
    [
        X25519,
        X448,
        SECP256R1,
        SECP384R1,
        SECP521R1,
        MLKEM768,
        MLKEM1024,
        X25519MLKEM768,
        SECP256R1MLKEM768,
        SECP384R1MLKEM1024,
    ]
}

#[test]
fn all_groups_agree() {
    for group in all() {
        let client = group.start().unwrap();
        assert_eq!(client.group(), group.name());
        let server = group.start_and_complete(client.pub_key()).unwrap();
        assert_eq!(server.group, group.name());
        let client_secret = client.complete(&server.pub_key).unwrap();
        assert_eq!(client_secret.secret_bytes(), server.secret.secret_bytes());
    }
}

#[test]
fn share_and_secret_lengths() {
    let cases: [(&dyn SupportedKxGroup, usize, usize, usize); 10] = [
        (X25519, 32, 32, 32),
        (X448, 56, 56, 56),
        (SECP256R1, 65, 65, 32),
        (SECP384R1, 97, 97, 48),
        (SECP521R1, 133, 133, 66),
        (MLKEM768, 1184, 1088, 32),
        (MLKEM1024, 1568, 1568, 32),
        (X25519MLKEM768, 1216, 1120, 64),
        (SECP256R1MLKEM768, 1249, 1153, 64),
        (SECP384R1MLKEM1024, 1665, 1665, 80),
    ];
    for (group, client_len, server_len, secret_len) in cases {
        let client = group.start().unwrap();
        assert_eq!(client.pub_key().len(), client_len, "{group:?}");
        let server = group.start_and_complete(client.pub_key()).unwrap();
        assert_eq!(server.pub_key.len(), server_len, "{group:?}");
        assert_eq!(server.secret.secret_bytes().len(), secret_len, "{group:?}");
    }
    assert_eq!(
        SECP384R1MLKEM1024.name(),
        NamedGroup::from(SECP384R1MLKEM1024_CODEPOINT)
    );
    assert_eq!(
        alloc::format!("{SECP384R1MLKEM1024:?}"),
        "secp384r1MLKEM1024"
    );
    assert_eq!(SECP384R1MLKEM1024.name(), NamedGroup::secp384r1MLKEM1024);
    assert_eq!(alloc::format!("{X25519MLKEM768:?}"), "X25519MLKEM768");
}

#[test]
fn version_restrictions() {
    for group in [X25519, X448, SECP256R1, SECP384R1, SECP521R1] {
        assert!(group.usable_for_version(ProtocolVersion::TLSv1_2));
        assert!(group.usable_for_version(ProtocolVersion::TLSv1_3));
    }
    for group in [
        MLKEM768,
        MLKEM1024,
        X25519MLKEM768,
        SECP256R1MLKEM768,
        SECP384R1MLKEM1024,
    ] {
        assert!(!group.usable_for_version(ProtocolVersion::TLSv1_2));
        assert!(group.usable_for_version(ProtocolVersion::TLSv1_3));
    }
}

#[test]
fn hybrid_components() {
    for (hybrid, classical, offset) in [
        (X25519MLKEM768, X25519, 1184),
        (SECP256R1MLKEM768, SECP256R1, 0),
        (SECP384R1MLKEM1024, SECP384R1, 0),
    ] {
        let kx = hybrid.start().unwrap();
        let (group, share) = kx.hybrid_component().unwrap();
        assert_eq!(group, classical.name());
        assert_eq!(share, &kx.pub_key()[offset..offset + share.len()]);
        let server = classical.start_and_complete(share).unwrap();
        let secret = kx.complete_hybrid_component(&server.pub_key).unwrap();
        assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
    }
}

#[test]
fn bad_peer_shares_are_rejected() {
    let invalid = invalid_share();
    let check = |group: &dyn SupportedKxGroup, share: &[u8]| {
        assert_eq!(
            group.start().unwrap().complete(share).unwrap_err(),
            invalid,
            "{group:?} client accepted {} bytes",
            share.len()
        );
    };
    let check_server = |group: &dyn SupportedKxGroup, share: &[u8]| {
        assert_eq!(
            group.start_and_complete(share).unwrap_err(),
            invalid,
            "{group:?} server accepted {} bytes",
            share.len()
        );
    };

    // Wrong lengths, including empty input.
    for group in all() {
        let client = group.start().unwrap();
        let len = group
            .start_and_complete(client.pub_key())
            .unwrap()
            .pub_key
            .len();
        for bad in [0, 1, len - 1, len + 1] {
            check(group, &alloc::vec![4u8; bad]);
        }
        let len = client.pub_key().len();
        for bad in [0, 1, len - 1, len + 1] {
            check_server(group, &alloc::vec![4u8; bad]);
        }
    }

    // X25519: the all-zero point and the other low-order points give an
    // all-zero shared secret.
    let mut order_two = [0u8; 32];
    order_two[0] = 1;
    for point in [[0u8; 32], order_two] {
        check(X25519, &point);
        check_server(X25519, &point);
    }

    // X448: u = 0, 1, -1 and the non-canonical p and p + 1 have order
    // dividing 4 (on the curve or its twist) and give an all-zero secret.
    let mut p448 = [0xffu8; 56];
    p448[28] = 0xfe;
    let mut minus_one = p448;
    minus_one[0] = 0xfe;
    let mut p448_plus_1 = [0u8; 56];
    p448_plus_1[28..].fill(0xff);
    let mut one = [0u8; 56];
    one[0] = 1;
    for point in [[0u8; 56], one, minus_one, p448, p448_plus_1] {
        check(X448, &point);
        check_server(X448, &point);
    }
    // An X25519-sized share is not an X448 share.
    check(X448, X25519.start().unwrap().pub_key());

    // NIST: compressed or hybrid encodings, the point at infinity,
    // coordinates >= p, and points off the curve.
    for (group, len) in [(SECP256R1, 65), (SECP384R1, 97), (SECP521R1, 133)] {
        let good = group.start().unwrap().pub_key().to_vec();
        let mut compressed = good[..(len - 1) / 2 + 1].to_vec();
        compressed[0] = 0x02 | (good[len - 1] & 1);
        check(group, &compressed);
        let mut hybrid_form = good.clone();
        hybrid_form[0] = 0x06 | (good[len - 1] & 1);
        check(group, &hybrid_form);
        let mut infinity = alloc::vec![0u8; len];
        infinity[0] = 0x04;
        check(group, &infinity);
        let mut big = alloc::vec![0xffu8; len];
        big[0] = 0x04;
        check(group, &big);
        let mut off_curve = good.clone();
        off_curve[len - 1] ^= 1;
        check(group, &off_curve);
        check_server(group, &off_curve);
    }

    // Hybrid: an invalid classical half is rejected even when the ML-KEM
    // half is well formed.
    let client = X25519MLKEM768.start().unwrap();
    let mut share = client.pub_key().to_vec();
    share[1184..].fill(0);
    check_server(X25519MLKEM768, &share);
    let server = X25519MLKEM768.start_and_complete(client.pub_key()).unwrap();
    let mut reply = server.pub_key.clone();
    reply[1088..].fill(0);
    assert_eq!(client.complete(&reply).unwrap_err(), invalid);

    let client = SECP256R1MLKEM768.start().unwrap();
    let mut share = client.pub_key().to_vec();
    share[64] ^= 1;
    check_server(SECP256R1MLKEM768, &share);

    // ML-KEM: an encapsulation key with a coefficient >= q fails the
    // FIPS 203 §7.2 modulus check.
    check_server(MLKEM768, &[0xff; 1184]);
    check_server(MLKEM1024, &[0xff; 1568]);
    let mut share = SECP384R1MLKEM1024.start().unwrap().pub_key().to_vec();
    share[97..97 + 12].fill(0xff);
    check_server(SECP384R1MLKEM1024, &share);
}

#[test]
fn mlkem_tampered_ciphertext_gives_different_secret() {
    let client = MLKEM768.start().unwrap();
    let server = MLKEM768.start_and_complete(client.pub_key()).unwrap();
    let mut ct = server.pub_key.clone();
    ct[0] ^= 1;
    let secret = client.complete(&ct).unwrap();
    assert_ne!(secret.secret_bytes(), server.secret.secret_bytes());
}

fn ffdhe_groups() -> [(&'static dyn SupportedKxGroup, NamedGroup, usize); 5] {
    [
        (FFDHE2048, NamedGroup::FFDHE2048, 256),
        (FFDHE3072, NamedGroup::FFDHE3072, 384),
        (FFDHE4096, NamedGroup::FFDHE4096, 512),
        (FFDHE6144, NamedGroup::FFDHE6144, 768),
        (FFDHE8192, NamedGroup::FFDHE8192, 1024),
    ]
}

#[test]
fn ffdhe_groups_agree_with_fixed_lengths_in_tls13_only() {
    for (group, name, len) in ffdhe_groups() {
        assert_eq!(group.name(), name);
        assert_eq!(alloc::format!("{group:?}"), alloc::format!("{name:?}"));
        assert!(group.usable_for_version(ProtocolVersion::TLSv1_3));
        assert!(!group.usable_for_version(ProtocolVersion::TLSv1_2));
        let client = group.start().unwrap();
        assert_eq!(client.group(), name);
        assert_eq!(client.pub_key().len(), len);
        assert!(client.hybrid_component().is_none());
        let server = group.start_and_complete(client.pub_key()).unwrap();
        assert_eq!(server.group, name);
        assert_eq!(server.pub_key.len(), len);
        assert_eq!(server.secret.secret_bytes().len(), len);
        let secret = client
            .complete_for_tls_version(&server.pub_key, &crate::versions::TLS13)
            .unwrap();
        assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
    }
}

#[test]
fn ffdhe_tls13_secret_keeps_leading_zeros() {
    // RFC 9846 §7.4.1: Z is left-padded to the size of p, unlike TLS 1.2.
    // About one exchange in 256 has a leading zero byte.
    for _ in 0..4096 {
        let client = FFDHE2048.start().unwrap();
        let server = FFDHE2048.start_and_complete(client.pub_key()).unwrap();
        if server.secret.secret_bytes()[0] != 0 {
            continue;
        }
        let secret = client
            .complete_for_tls_version(&server.pub_key, &crate::versions::TLS13)
            .unwrap();
        assert_eq!(secret.secret_bytes().len(), 256);
        assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
        return;
    }
    panic!("no FFDHE secret with a leading zero byte in 4096 exchanges");
}

#[test]
fn ffdhe_invalid_shares_are_rejected_by_both_sides() {
    let invalid = invalid_share();
    for (group, _, len) in ffdhe_groups() {
        let p = ffdhe::Group::ALL
            .into_iter()
            .find(|g| g.element_len() == len)
            .unwrap()
            .prime_be();
        let mut one = alloc::vec![0u8; len];
        one[len - 1] = 1;
        let mut p_minus_one = p.to_vec();
        p_minus_one[len - 1] -= 1;
        let mut p_plus_one = p.to_vec();
        for b in p_plus_one.iter_mut().rev() {
            let (sum, carry) = b.overflowing_add(1);
            *b = sum;
            if !carry {
                break;
            }
        }
        let good = group.start().unwrap().pub_key().to_vec();
        let mut long = alloc::vec![0u8];
        long.extend_from_slice(&good);
        let shares: [&[u8]; 9] = [
            &alloc::vec![0u8; len],
            &one,
            &p_minus_one,
            p,
            &p_plus_one,
            &alloc::vec![0xffu8; len],
            &good[1..],
            &long,
            &[],
        ];
        for share in shares {
            assert_eq!(
                group.start().unwrap().complete(share).unwrap_err(),
                invalid,
                "{group:?} client accepted a {}-byte share",
                share.len()
            );
            assert_eq!(
                group.start_and_complete(share).unwrap_err(),
                invalid,
                "{group:?} server accepted a {}-byte share",
                share.len()
            );
        }
    }
}
