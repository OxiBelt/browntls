//! Certificate chains with RSASSA-PSS keys, validated by the web-PKI
//! verifiers.

use super::*;

// ---------------------------------------------------------------------------
// Certificate path validation

/// Chains with RSASSA-PSS keys at every position.
const CHAINS: [ChainSpec; 5] = [
    ChainSpec::direct(UNRESTRICTED, Sha256, UNRESTRICTED),
    ChainSpec::direct(restricted(Sha384), Sha384, restricted(Sha512)),
    ChainSpec::direct(restricted(Sha512), Sha512, RSAE_KEY),
    ChainSpec {
        root: RSAE_KEY,
        root_hash: Sha512,
        intermediate: Some((restricted(Sha256), Sha256)),
        end_entity: RSAE_KEY,
    },
    ChainSpec {
        root: UNRESTRICTED,
        root_hash: Sha384,
        intermediate: Some((UNRESTRICTED, Sha512)),
        end_entity: restricted(Sha256),
    },
];

#[cfg(feature = "zstd")]
#[path = "../common/counting_decompressor.rs"]
mod counting_decompressor;

#[cfg(feature = "zstd")]
#[test]
fn compressed_restricted_pss_mutual_authentication() {
    use browntls_core::compress::ZSTD;
    use counting_decompressor::Counting;

    let server_chain = server_with_key(restricted(Sha384));
    let client_chain = client_with_key(restricted(Sha256));
    let (mut client_config, mut server_config) =
        webpki_configs(ProtocolVersion::TLSv1_3, &server_chain, &client_chain);
    let client_counter = Counting::new(&ZSTD);
    let server_counter = Counting::new(&ZSTD);
    client_config.cert_compressors = vec![&ZSTD];
    client_config.cert_decompressors = vec![client_counter];
    server_config.cert_compressors = vec![&ZSTD];
    server_config.cert_decompressors = vec![server_counter];

    let (mut client, mut server) = connect(client_config, server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client_counter.calls(), 1);
    assert_eq!(server_counter.calls(), 1);
    assert_eq!(client.peer_certificates().unwrap(), server_chain.chain);
    assert_eq!(server.peer_certificates().unwrap(), client_chain.chain);
    round_trip(&mut client, &mut server);
}

#[test]
fn webpki_verifiers_validate_chains_with_pss_keys() {
    init_logging();
    for spec in CHAINS {
        let server_chain = spec.build(Role::Server);
        let client_chain = spec.build(Role::Client);
        for v in VERSIONS {
            let (client_config, server_config) = webpki_configs(v, &server_chain, &client_chain);
            let (mut client, mut server) = connect(client_config, server_config);
            do_handshake(&mut client, &mut server)
                .unwrap_or_else(|e| panic!("{spec:?} {v:?}: {e}"));
            assert_eq!(client.protocol_version(), Some(v));
            assert_eq!(
                client.peer_certificates().unwrap(),
                server_chain.chain.as_slice()
            );
            assert_eq!(
                server.peer_certificates().unwrap(),
                client_chain.chain.as_slice()
            );
            round_trip(&mut client, &mut server);
        }
    }
}

#[test]
fn webpki_verifier_rejects_a_restricted_ca_signing_with_another_hash() {
    init_logging();
    // The root's key is restricted to SHA-256; the end entity's certificate
    // carries SHA-384 parameters, which are not identical to the key's
    // (RFC 9846 §4.3.3, RFC 4055 §3.3).
    for (spec, ok) in [
        (
            ChainSpec::direct(restricted(Sha256), Sha384, UNRESTRICTED),
            false,
        ),
        (
            ChainSpec::direct(restricted(Sha256), Sha256, UNRESTRICTED),
            true,
        ),
        (
            ChainSpec {
                root: RSAE_KEY,
                root_hash: Sha256,
                intermediate: Some((restricted(Sha512), Sha256)),
                end_entity: RSAE_KEY,
            },
            false,
        ),
    ] {
        let server_chain = spec.build(Role::Server);
        let client_chain = ChainSpec::direct(RSAE_KEY, Sha256, RSAE_KEY).build(Role::Client);
        for v in VERSIONS {
            let (client_config, server_config) = webpki_configs(v, &server_chain, &client_chain);
            let (mut client, mut server) = connect(client_config, server_config);
            let (client_res, _) = do_handshake_until_error(&mut client, &mut server);
            if ok {
                client_res.unwrap();
            } else {
                assert_eq!(
                    client_res,
                    Err(Error::InvalidCertificate(
                        CertificateError::UnsupportedSignatureAlgorithm
                    )),
                    "{spec:?} {v:?}"
                );
            }
        }
    }
}
