//! ECH uses HPKE in base mode only (RFC 9849 §6.1): the payload of a real
//! offer opens with a base-mode recipient of the server's key, through
//! `HpkeModes` as through `Hpke`, and with no PSK, Auth or AuthPSK
//! recipient of that same key.

use browntls_core::crypto::hpke::{
    EncapsulatedSecret, HpkeModes, HpkeOpenMode, HpkePsk, HpkePublicKey,
};
use browntls_core::crypto::native::hpke::ALL_SUPPORTED_SUITES_WITH_MODES;
use hello_wire::{give, take_flight};

use super::outer_wire::{outer_hello, u16_at};
use super::*;

/// The public key of an `ECHConfig`: version, length, configuration
/// identifier, KEM, then `opaque public_key<1..2^16-1>`.
fn config_public_key(ech_config: &[u8]) -> HpkePublicKey {
    let len = u16_at(ech_config, 7);
    HpkePublicKey(ech_config[9..9 + len].to_vec())
}

#[test]
fn ech_offers_open_in_base_mode_only() {
    init_logging();
    let certs = Certs::new();
    // One suite of each KEM.
    for (config_id, &suite) in (1u8..).zip(ALL_SUPPORTED_SUITES.iter().step_by(9)) {
        let key = EchServerKey::generate(config_id, PUBLIC, 32, &[suite]).unwrap();
        let ech_config = key.ech_config().to_vec();
        let kem = key.kem();
        let secret_key = key.private_key().clone();
        let ech = Arc::new(EchServerConfig::new(vec![key]).unwrap());
        let (mut client, mut server) = connect(
            client_config(&certs, enable(ech.ech_config_list())),
            server_config(&certs, Some(&ech), None),
        );
        let flight = take_flight(&mut client);
        let outer = outer_hello(&flight);
        let modes: &dyn HpkeModes = *ALL_SUPPORTED_SUITES_WITH_MODES
            .iter()
            .find(|candidate| {
                let found = candidate.suite();
                (found.kem, found.sym.kdf_id.0, found.sym.aead_id.0) == (kem, outer.kdf, outer.aead)
            })
            .unwrap();
        assert_eq!(modes.suite(), suite.suite());
        // RFC 9849 §6.1: `info = "tls ech" || 0x00 || ECHConfig`.
        let info = [b"tls ech\0".as_slice(), &ech_config].concat();
        let enc = EncapsulatedSecret(outer.enc.clone());

        let inner = modes
            .setup_opener_with_mode(HpkeOpenMode::Base, &enc, &info, &secret_key)
            .unwrap()
            .open(&outer.aad, &outer.payload)
            .expect("base mode opens the offer");
        let through_hpke = suite
            .setup_opener(&enc, &info, &secret_key)
            .unwrap()
            .open(&outer.aad, &outer.payload)
            .unwrap();
        assert_eq!(inner, through_hpke);
        // EncodedClientHelloInner: version, random, ...; it names the
        // hidden server, which the outer ClientHello does not.
        assert_ne!(&inner[2..34], &outer.random[..]);
        let hidden = SECRET.as_bytes();
        assert!(inner.windows(hidden.len()).any(|w| w == hidden));
        assert!(!flight.windows(hidden.len()).any(|w| w == hidden));

        // The same server key in the other modes: a PSK, the server's own
        // public key or a fresh one as the sender's, opens nothing.
        let psk = HpkePsk::new(vec![0x5a; 32], b"ech".to_vec()).unwrap();
        let own = config_public_key(&ech_config);
        let (fresh, _) = modes.generate_key_pair().unwrap();
        let mut others = vec![HpkeOpenMode::Psk(&psk)];
        for sender in [&own, &fresh] {
            others.push(HpkeOpenMode::Auth(sender));
            others.push(HpkeOpenMode::AuthPsk(&psk, sender));
        }
        for mode in others {
            let opened = modes
                .setup_opener_with_mode(mode, &enc, &info, &secret_key)
                .unwrap()
                .open(&outer.aad, &outer.payload);
            assert_eq!(opened, Err(Error::DecryptError), "{mode:?}");
        }

        // The library's server takes the same offer.
        give(&mut server, &flight);
        server.process_new_packets().unwrap();
        assert_accepted(&mut client, &mut server);
    }
}
