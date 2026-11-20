//! Codec and handshake-helper tests of RFC 8844.

use alloc::vec;
use alloc::vec::Vec;

use super::handshake::{
    check_client_config, client_check, client_offer, server_answer, server_check, strip_from_outer,
};
use super::*;
use crate::common_state::Side;
use crate::enums::AlertDescription;
use crate::error::{PeerIncompatible, PeerMisbehaved};
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{ClientExtensions, ServerExtensions};

fn session_id(len: usize, fill: u8) -> ExternalSessionId {
    ExternalSessionId::new(&vec![fill; len]).unwrap()
}

/// `len` as a one-byte prefix, then `body_len` bytes.
fn prefixed(len: u8, body_len: usize) -> Vec<u8> {
    let mut out = vec![len];
    out.resize(1 + body_len, 0x5a);
    out
}

#[test]
fn id_hash_length_boundaries() {
    assert_eq!(
        ExternalIdHash::from_extension_data(&[0]).unwrap(),
        ExternalIdHash::EMPTY
    );
    let full = ExternalIdHash::from_extension_data(&prefixed(32, 32)).unwrap();
    assert_eq!(full.as_bytes(), &[0x5a; 32]);
    assert!(!full.is_empty());
    for bad in [1u8, 31, 33, 255] {
        assert_eq!(
            ExternalIdHash::from_extension_data(&prefixed(bad, usize::from(bad))),
            Err(InvalidMessage::InvalidExternalIdHash),
            "length {bad}"
        );
    }
    // Truncated, empty, trailing bytes.
    assert_eq!(
        ExternalIdHash::from_extension_data(&prefixed(32, 31)),
        Err(InvalidMessage::MessageTooShort)
    );
    assert!(ExternalIdHash::from_extension_data(&[]).is_err());
    assert_eq!(
        ExternalIdHash::from_extension_data(&[0, 0]),
        Err(InvalidMessage::TrailingData("read_bytes"))
    );
    assert!(ExternalIdHash::from_extension_data(&prefixed(32, 33)).is_err());
    // Every invalid form is decode_error.
    assert_eq!(
        AlertDescription::from(InvalidMessage::InvalidExternalIdHash),
        AlertDescription::DecodeError
    );
}

#[test]
fn id_hash_round_trip_and_debug() {
    for hash in [ExternalIdHash::EMPTY, ExternalIdHash::from_sha256([7; 32])] {
        let data = hash.to_extension_data();
        assert_eq!(data.len(), 1 + hash.as_bytes().len());
        assert_eq!(ExternalIdHash::from_extension_data(&data).unwrap(), hash);
    }
    assert_eq!(
        alloc::format!("{:?}", ExternalIdHash::EMPTY),
        "ExternalIdHash()"
    );
    assert!(alloc::format!("{:?}", ExternalIdHash::from_sha256([0xab; 32])).contains("abab"));
}

#[test]
fn session_id_length_boundaries() {
    assert_eq!(
        ExternalSessionId::new(&[1; 19]),
        Err(Error::BadExternalSessionIdLength)
    );
    assert_eq!(
        ExternalSessionId::new(&[1; 256]),
        Err(Error::BadExternalSessionIdLength)
    );
    assert_eq!(
        ExternalSessionId::new(&[]),
        Err(Error::BadExternalSessionIdLength)
    );
    for len in [20, 21, 254, 255] {
        let id = session_id(len, 3);
        assert_eq!(id.as_bytes().len(), len);
        let data = id.to_extension_data();
        assert_eq!(data[0] as usize, len);
        assert_eq!(ExternalSessionId::from_extension_data(&data).unwrap(), id);
    }
    for bad in [0u8, 1, 19] {
        assert_eq!(
            ExternalSessionId::from_extension_data(&prefixed(bad, usize::from(bad))),
            Err(InvalidMessage::InvalidExternalSessionId),
            "length {bad}"
        );
    }
    assert_eq!(
        ExternalSessionId::from_extension_data(&prefixed(20, 19)),
        Err(InvalidMessage::MessageTooShort)
    );
    assert_eq!(
        ExternalSessionId::from_extension_data(&prefixed(20, 21)),
        Err(InvalidMessage::TrailingData("read_bytes"))
    );
    assert!(ExternalSessionId::from_extension_data(&[]).is_err());
    assert_eq!(
        AlertDescription::from(InvalidMessage::InvalidExternalSessionId),
        AlertDescription::DecodeError
    );
}

#[test]
fn session_id_debug() {
    let ascii = ExternalSessionId::new(b"abcdefghijklmnopqrstuvwxyz").unwrap();
    assert_eq!(
        alloc::format!("{ascii:?}"),
        "ExternalSessionId(\"abcdefghijklmnopqrstuvwxyz\")"
    );
    let binary = session_id(20, 0);
    assert_eq!(
        alloc::format!("{binary:?}"),
        alloc::format!("ExternalSessionId({})", "00".repeat(20))
    );
}

#[test]
fn hello_extensions_carry_both() {
    let mut ch = ClientExtensions {
        external_id_hash: Some(ExternalIdHash::from_sha256([1; 32])),
        external_session_id: Some(session_id(20, b'a')),
        ..Default::default()
    };
    let back = ClientExtensions::read_bytes(&ch.get_encoding()).unwrap();
    assert_eq!(back, ch);
    let types = ch.present_types();
    assert!(types.contains(&ExtensionType::ExternalIdHash));
    assert!(types.contains(&ExtensionType::ExternalSessionId));
    strip_from_outer(&mut ch);
    assert_eq!(ch, ClientExtensions::default());

    let sh = ServerExtensions {
        external_id_hash: Some(ExternalIdHash::EMPTY),
        external_session_id: Some(session_id(255, b'z')),
        ..Default::default()
    };
    let back = ServerExtensions::read_bytes(&sh.get_encoding()).unwrap();
    assert_eq!(back, sh);
    assert_eq!(
        back.present_types(),
        [
            ExtensionType::ExternalIdHash,
            ExtensionType::ExternalSessionId
        ]
    );
}

#[test]
fn malformed_bodies_fail_the_hello() {
    // external_id_hash (55) with a one-byte hash.
    let block = [0, 6, 0, 55, 0, 2, 1, 0];
    assert_eq!(
        ClientExtensions::read_bytes(&block),
        Err(InvalidMessage::InvalidExternalIdHash)
    );
    assert_eq!(
        ServerExtensions::read_bytes(&block),
        Err(InvalidMessage::InvalidExternalIdHash)
    );
    // external_session_id (56) of 19 bytes.
    let mut block = vec![0, 24, 0, 56, 0, 20, 19];
    block.extend_from_slice(&[0; 19]);
    assert_eq!(
        ClientExtensions::read_bytes(&block),
        Err(InvalidMessage::InvalidExternalSessionId)
    );
    // An empty hash followed by a stray byte inside the extension body.
    let block = [0, 6, 0, 55, 0, 2, 0, 0];
    assert_eq!(
        ClientExtensions::read_bytes(&block),
        Err(InvalidMessage::TrailingData("extension"))
    );
}

#[test]
fn offer_rules() {
    let mut exts = ClientExtensions::default();
    client_offer(None, &mut exts);
    assert_eq!(exts, ClientExtensions::default());

    // A binding without a hash of our own sends the empty one (RFC 8844
    // §3.2), with or without an expectation.
    for peer_id_hash in [None, Some(ExternalIdHash::from_sha256([2; 32]))] {
        let binding = ExternalBinding {
            peer_id_hash,
            ..Default::default()
        };
        let mut exts = ClientExtensions::default();
        client_offer(Some(&binding), &mut exts);
        assert_eq!(exts.external_id_hash, Some(ExternalIdHash::EMPTY));
        assert_eq!(exts.external_session_id, None);
        // A server likewise answers a received hash with the empty one.
        let mut answer = ServerExtensions::default();
        server_answer(Some(&binding), &exts, &mut answer);
        assert_eq!(answer.external_id_hash, Some(ExternalIdHash::EMPTY));
        assert_eq!(answer.external_session_id, None);
    }

    let binding = ExternalBinding {
        id_hash: Some(ExternalIdHash::from_sha256([3; 32])),
        session_id: Some(session_id(30, b's')),
        ..Default::default()
    };
    client_offer(Some(&binding), &mut exts);
    assert_eq!(binding.id_hash, exts.external_id_hash);
    assert_eq!(binding.session_id, exts.external_session_id);

    // The server answers only what the client sent.
    let mut answer = ServerExtensions::default();
    server_answer(Some(&binding), &ClientExtensions::default(), &mut answer);
    assert_eq!(answer, ServerExtensions::default());
    server_answer(None, &exts, &mut answer);
    assert_eq!(answer, ServerExtensions::default());
    server_answer(Some(&binding), &exts, &mut answer);
    assert_eq!(answer.external_id_hash, binding.id_hash);
    assert_eq!(answer.external_session_id, binding.session_id);

    assert_eq!(check_client_config(None), Ok(()));
    assert_eq!(check_client_config(Some(&binding)), Ok(()));
    let inconsistent = ExternalBinding {
        peer_session_id: Some(session_id(20, 1)),
        ..Default::default()
    };
    assert_eq!(
        check_client_config(Some(&inconsistent)),
        Err(Error::InconsistentExternalBinding)
    );
}

#[test]
fn checks() {
    let expected = ExternalBinding {
        peer_id_hash: Some(ExternalIdHash::from_sha256([4; 32])),
        peer_session_id: Some(session_id(20, b'p')),
        ..Default::default()
    };
    let good = ClientExtensions {
        external_id_hash: expected.peer_id_hash,
        external_session_id: expected.peer_session_id.clone(),
        ..Default::default()
    };

    let mut common = CommonState::new(Side::Server);
    server_check(&mut common, Some(&expected), &good, true).unwrap();
    assert_eq!(
        common.peer_external_id_hash(),
        expected.peer_id_hash.as_ref()
    );
    assert_eq!(
        common.peer_external_session_id(),
        expected.peer_session_id.as_ref()
    );
    // The same values again (a second ClientHello) pass; changed ones fail.
    server_check(&mut common, Some(&expected), &good, true).unwrap();
    let mut changed = good.clone();
    changed.external_session_id = None;
    assert_eq!(
        server_check(&mut common, Some(&expected), &changed, true),
        Err(PeerMisbehaved::ExternalBindingChangedOnRetry.into())
    );

    // Mismatches: an empty hash against a full one, another session ID.
    let mut common = CommonState::new(Side::Server);
    let empty_hash = ClientExtensions {
        external_id_hash: Some(ExternalIdHash::EMPTY),
        ..good.clone()
    };
    assert_eq!(
        server_check(&mut common, Some(&expected), &empty_hash, true),
        Err(PeerMisbehaved::ExternalIdHashMismatch.into())
    );
    assert_eq!(common.peer_external_id_hash(), None);
    let mut common = CommonState::new(Side::Client);
    let other_id = ServerExtensions {
        external_id_hash: expected.peer_id_hash,
        external_session_id: Some(session_id(21, b'p')),
        ..Default::default()
    };
    assert_eq!(
        client_check(&mut common, Some(&expected), &other_id, false, false),
        Err(PeerMisbehaved::ExternalSessionIdMismatch.into())
    );

    // Absent: accepted by default, refused when required.
    let mut common = CommonState::new(Side::Client);
    client_check(
        &mut common,
        Some(&expected),
        &ServerExtensions::default(),
        true,
        false,
    )
    .unwrap();
    assert_eq!(common.peer_external_id_hash(), None);
    let required = ExternalBinding {
        require_peer_support: true,
        ..expected.clone()
    };
    for (tls13, sent) in [(true, false), (false, true)] {
        let mut common = CommonState::new(Side::Client);
        let only_hash = ServerExtensions {
            external_id_hash: sent.then_some(expected.peer_id_hash).flatten(),
            ..Default::default()
        };
        let err = client_check(&mut common, Some(&required), &only_hash, tls13, false);
        let why = if sent {
            PeerIncompatible::ExternalSessionIdExtensionRequired
        } else {
            PeerIncompatible::ExternalIdHashExtensionRequired
        };
        assert_eq!(err, Err(why.into()));
    }
    // A client after an ECH rejection, or a server without a binding,
    // checks nothing.
    let mut common = CommonState::new(Side::Client);
    client_check(
        &mut common,
        Some(&required),
        &ServerExtensions::default(),
        true,
        true,
    )
    .unwrap();
    server_check(&mut common, None, &changed, true).unwrap();
    assert_eq!(common.peer_external_id_hash(), None);

    // Without expectations the values are only recorded.
    let mut common = CommonState::new(Side::Server);
    server_check(
        &mut common,
        Some(&ExternalBinding::default()),
        &empty_hash,
        false,
    )
    .unwrap();
    assert_eq!(common.peer_external_id_hash(), Some(&ExternalIdHash::EMPTY));
}

#[test]
fn hash_of_an_assertion() {
    #[cfg(feature = "native")]
    {
        let provider = crate::crypto::native::default_provider();
        let hash = ExternalIdHash::for_assertion(&provider, b"abc").unwrap();
        // FIPS 180-2 B.1.
        assert_eq!(hash.as_bytes()[..4], [0xba, 0x78, 0x16, 0xbf], "{hash:?}");
        let mut no_sha256 = provider.clone();
        no_sha256.cipher_suites.clear();
        assert_eq!(ExternalIdHash::for_assertion(&no_sha256, b"abc"), None);
    }
}
