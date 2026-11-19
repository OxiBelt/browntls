//! TLS handshakes and records of the native provider under load-aware
//! backend routing (`native::accel::load`).
//!
//! Routing never changes a result, so a connection must work, and stay
//! interoperable, wherever its operations run. Routing state is process-wide,
//! so everything runs in one test function (each integration test file is a
//! separate process).
#![cfg(all(feature = "native", feature = "std"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

use std::sync::Arc;

use browntls_core::crypto::native::accel::load::{self, Config, Phase};
use browntls_core::crypto::native::accel::{self, Algorithm};
use browntls_core::crypto::native::{self, kx_group};
use browntls_core::crypto::{CryptoProvider, SupportedKxGroup};
use browntls_core::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use common::*;

/// The groups whose key exchange is routed: X25519, the three NIST curves,
/// ML-KEM, and two hybrids of them.
fn groups() -> Vec<&'static dyn SupportedKxGroup> {
    vec![
        kx_group::X25519,
        kx_group::SECP256R1,
        kx_group::SECP384R1,
        kx_group::SECP521R1,
        kx_group::MLKEM768,
        kx_group::X25519MLKEM768,
        kx_group::SECP384R1MLKEM1024,
    ]
}

/// One handshake and a payload in each direction between `client` and
/// `server` providers, restricted to one suite and one group.
fn connect(client: &CryptoProvider, server: &CryptoProvider, key_type: KeyType, what: &str) {
    let chain = server_chain(key_type);
    let versions = [client.cipher_suites[0].version()];
    let client = ClientConfig::builder_with_provider(Arc::new(client.clone()))
        .with_protocol_versions(&versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    let server = ServerConfig::builder_with_provider(Arc::new(server.clone()))
        .with_protocol_versions(&versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    let mut client = ClientConnection::new(Arc::new(client), server_name())
        .unwrap_or_else(|e| panic!("{what}: {e:?}"));
    let mut server =
        ServerConnection::new(Arc::new(server)).unwrap_or_else(|e| panic!("{what}: {e:?}"));
    do_handshake(&mut client, &mut server).unwrap_or_else(|e| panic!("{what}: {e:?}"));

    // Several full-size records each way: long enough to be routed.
    let request: Vec<u8> = (0..70_000u32).map(|i| (i * 7) as u8).collect();
    let got = send_and_receive(&mut client, &mut server, &request);
    assert_eq!(got, request, "{what}");
    let response = vec![0x5a; 40_000];
    let got = send_and_receive(&mut server, &mut client, &response);
    assert_eq!(got, response, "{what}");
}

/// Handshakes between native peers for every default suite, every routed
/// group and every key type.
fn native_handshakes(what: &str) {
    let base = native::default_provider();
    for &suite in native::DEFAULT_CIPHER_SUITES {
        // The suite fixes the key type in TLS 1.2; any key does in TLS 1.3.
        let name = format!("{:?}", suite.suite());
        let key_types: &[KeyType] = if name.contains("_RSA_") {
            &[KeyType::Rsa2048]
        } else if name.contains("_ECDSA_") {
            &[KeyType::EcdsaP256, KeyType::EcdsaP384]
        } else {
            &KeyType::ALL
        };
        for (i, group) in groups().into_iter().enumerate() {
            let mut kx_groups = vec![group];
            if suite.tls13().is_none() {
                // TLS 1.2 has no ML-KEM groups, and its client must also
                // list the curve of an ECDSA certificate (RFC 8422).
                if format!("{:?}", group.name()).contains("MLKEM") {
                    continue;
                }
                kx_groups.extend([kx_group::SECP256R1, kx_group::SECP384R1]);
            }
            let provider = CryptoProvider {
                cipher_suites: vec![suite],
                kx_groups,
                ..base.clone()
            };
            let key_type = key_types[i % key_types.len()];
            let what = format!("{what}: {name}, {:?}, {key_type:?}", group.name());
            connect(&provider, &provider, key_type, &what);
        }
    }
}

/// Handshakes between a native peer and a RustCrypto peer, in both roles:
/// what the native side sends is what an independent implementation expects.
#[cfg(feature = "rustcrypto")]
fn cross_provider_handshakes(what: &str) {
    use browntls_core::crypto::rustcrypto;
    let other = rustcrypto::default_provider();
    for &suite in &other.cipher_suites {
        let Some(&native_suite) = native::DEFAULT_CIPHER_SUITES
            .iter()
            .find(|s| s.suite() == suite.suite())
        else {
            continue;
        };
        let name = format!("{:?}", suite.suite());
        if name.contains("_RSA_") {
            // The RustCrypto provider does not sign with RSA.
            continue;
        }
        for &group in &other.kx_groups {
            let Some(native_group) = groups().into_iter().find(|g| g.name() == group.name()) else {
                continue;
            };
            let (mut ours, mut theirs) = (vec![native_group], vec![group]);
            if suite.tls13().is_none() {
                // As in `native_handshakes`.
                if format!("{:?}", group.name()).contains("MLKEM") {
                    continue;
                }
                ours.push(kx_group::SECP256R1);
                theirs.push(rustcrypto::kx_group::SECP256R1);
            }
            let ours = CryptoProvider {
                cipher_suites: vec![native_suite],
                kx_groups: ours,
                ..native::default_provider()
            };
            let theirs = CryptoProvider {
                cipher_suites: vec![suite],
                kx_groups: theirs,
                ..other.clone()
            };
            let what = format!("{what}: {name}, {:?}", group.name());
            connect(
                &ours,
                &theirs,
                KeyType::EcdsaP256,
                &format!("{what}, native client"),
            );
            connect(
                &theirs,
                &ours,
                KeyType::EcdsaP256,
                &format!("{what}, native server"),
            );
        }
    }
}

#[cfg(not(feature = "rustcrypto"))]
fn cross_provider_handshakes(_what: &str) {}

/// Pins `percent` of every stream of every family on its `alternate`-th
/// alternate (its last one if it has fewer). Returns how many streams have
/// an alternate at all.
fn fix_everywhere(alternate: usize, percent: u8) -> usize {
    let mut fixed = 0;
    for s in load::status_all() {
        if s.alternates > 0 {
            let alternate = alternate.min(s.alternates - 1);
            load::set_fixed(s.algorithm, s.lane, alternate, percent).unwrap();
            fixed += 1;
        }
    }
    fixed
}

#[test]
fn connections_under_load_aware_routing() {
    assert_eq!(load::config(), None);
    native_handshakes("routing disabled");

    // Enabled and steady.
    load::enable(Config::DEFAULT).unwrap();
    native_handshakes("routing enabled");
    cross_provider_handshakes("routing enabled");
    for s in load::status_all() {
        println!("{s}");
        assert_eq!(s.phase, Phase::Steady, "{s}");
    }
    // Every key exchange is timed, so the handshakes above left their costs.
    for alg in [Algorithm::X25519, Algorithm::P256, Algorithm::MlKem] {
        let measured = load::status_all()
            .filter(|s| s.algorithm == alg)
            .any(|s| s.primary_cost.is_some());
        assert!(measured, "{alg}");
    }

    // Every stream pinned on an alternate, entirely and in part: every
    // operation of a connection that can run elsewhere does. The most
    // alternates any family has is the number of rounds needed to visit all.
    let most = load::status_all().map(|s| s.alternates).max().unwrap_or(0);
    for alternate in 0..most {
        for percent in [100, 50] {
            load::disable();
            load::enable(Config::DEFAULT).unwrap();
            let fixed = fix_everywhere(alternate, percent);
            let what = format!("{percent}% on alternate {alternate}");
            native_handshakes(&what);
            cross_provider_handshakes(&what);
            // The key exchanges really ran on the alternates.
            let moved = load::status_all()
                .filter(|s| s.phase == Phase::Fixed && s.alternate_cost.is_some())
                .count();
            println!("{what}: {moved} of {fixed} pinned streams measured on their alternate");
            for alg in [Algorithm::X25519, Algorithm::P256, Algorithm::MlKem] {
                let pinned: Vec<_> = load::status_all()
                    .filter(|s| s.algorithm == alg && s.phase == Phase::Fixed)
                    .collect();
                assert!(
                    pinned.is_empty() || pinned.iter().any(|s| s.alternate_cost.is_some()),
                    "{what}: {alg}"
                );
            }
        }
    }

    // Policies still bound where work goes: with portable code only there
    // is nothing to move, and connections work as before.
    load::disable();
    load::enable(Config::DEFAULT).unwrap();
    accel::set_policy_all(accel::Policy::NONE).unwrap();
    assert_eq!(fix_everywhere(0, 100), 0);
    native_handshakes("portable code only");
    accel::set_policy_all(accel::Policy::PREFERRED).unwrap();

    load::disable();
    native_handshakes("routing disabled again");
}
