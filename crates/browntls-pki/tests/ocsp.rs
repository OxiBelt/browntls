//! OCSP requests, and responses signed by the issuing CA at run time.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "common/ocsp.rs"]
mod support;

use support::*;

#[test]
fn sha1_test_vectors() {
    assert_eq!(
        hex::encode(sha1(b"abc")),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        hex::encode(sha1(b"")),
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    );
    assert_eq!(
        hex::encode(sha1(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
}

#[test]
fn time_helpers_agree() {
    assert_eq!(NOW, secs(NOW_SECS));
    assert_eq!(
        UnixTime::since_unix_epoch(Duration::from_secs(NOW_SECS)),
        NOW
    );
    assert_eq!(generalized_time(NOW_SECS), b"\x18\x0f20240601000000Z");
}
// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

#[test]
fn cert_id_and_request() {
    let fx = Fixture::new();
    let ca = fx.ca();
    for (hash, len) in [(CertIdHash::Sha1, 20), (CertIdHash::Sha256, 32)] {
        let id = fx.cert_id(hash);
        let name = tlv(0x30, ca.subject());
        let key = fx.ca_key().public_key_raw();
        let (name_hash, key_hash) = match hash {
            CertIdHash::Sha1 => (sha1(&name).to_vec(), sha1(key).to_vec()),
            _ => (sha256(&name), sha256(key)),
        };
        assert_eq!(id.hash_algorithm(), hash);
        assert_eq!(id.issuer_name_hash(), name_hash);
        assert_eq!(id.issuer_key_hash(), key_hash);
        assert_eq!(id.issuer_key_hash().len(), len);
        assert_eq!(id.serial(), EE_SERIAL);
        // The SPKI contents and the complete SPKI give the same identifier.
        let spki = ca.subject_public_key_info();
        let contents = &spki[2..];
        assert_eq!(CertId::new(hash, &HASHERS, &fx.ee(), contents).unwrap(), id);
        let rebuilt = CertId::from_parts(hash, &name_hash, &key_hash, EE_SERIAL).unwrap();
        assert_eq!(rebuilt, id);

        let algorithm = seq(&[&tlv(0x06, hash.oid()), &[0x05, 0x00]]);
        let cert_id = seq(&[
            &algorithm,
            &tlv(0x04, &name_hash),
            &tlv(0x04, &key_hash),
            &tlv(0x02, EE_SERIAL),
        ]);
        assert_eq!(id.to_der(), cert_id);
        let request = seq(&[&seq(&[&seq(&[&seq(&[&cert_id])])])]);
        assert_eq!(encode_request(&id, None).unwrap(), request);

        let nonce = [0x5a; 16];
        let nonce_ext = extension(oid::NONCE, false, &tlv(0x04, &nonce));
        let tbs = seq(&[
            &seq(&[&seq(&[&cert_id])]),
            &tlv(0xa2, &tlv(0x30, &nonce_ext)),
        ]);
        assert_eq!(encode_request(&id, Some(&nonce)).unwrap(), seq(&[&tbs]));
    }
    assert_eq!(
        CertId::new(CertIdHash::Sha1, &HASHERS, &fx.ee(), &[0x30, 0x00]).err(),
        Some(OcspError::BadIssuerKey(Error::BadDer))
    );
    assert_eq!(
        CertId::new(
            CertIdHash::Sha256,
            &CertIdHashers {
                sha256: None,
                ..HASHERS
            },
            &fx.ee(),
            &ca.subject_public_key_info()
        )
        .err(),
        Some(OcspError::DigestUnavailable(CertIdHash::Sha256))
    );
}

// ---------------------------------------------------------------------------
// Responses signed by the CA
// ---------------------------------------------------------------------------

#[test]
fn good_response_signed_by_ca() {
    let fx = Fixture::new();
    let der = fx.response().signed_by(fx.ca_key());

    let parsed = OcspResponse::from_der(&der).unwrap();
    assert_eq!(parsed.status(), ResponseStatus::Successful);
    let basic = parsed.basic().unwrap();
    assert!(matches!(basic.responder_id(), ResponderId::ByKey(hash) if hash.len() == 20));
    assert_eq!(basic.produced_at(), secs(THIS_UPDATE));
    assert_eq!(basic.certificates().count(), 0);
    assert_eq!(basic.nonce(), None);
    let singles: Vec<_> = basic.responses().collect();
    assert_eq!(singles.len(), 1);
    assert_eq!(singles[0].status(), CertStatus::Good);
    assert_eq!(singles[0].this_update(), secs(THIS_UPDATE));
    assert_eq!(singles[0].next_update(), Some(secs(NEXT_UPDATE)));
    assert_eq!(singles[0].sct_list(), None);
    assert!(fx.cert_id(CertIdHash::Sha1).matches(&singles[0].cert_id()));
    assert_eq!(singles[0].cert_id().serial(), EE_SERIAL);
    // The signature alone verifies with the CA key.
    let ca = fx.ca();
    basic
        .signed_data()
        .verify_signature(ALGS, &ca.subject_public_key_info())
        .unwrap();
    assert!(format!("{parsed:?}").contains("ByKey"));

    for policy in [stapled(), fetched()] {
        let verified = fx.verify(&der, &policy).unwrap();
        assert_eq!(verified.status, CertStatus::Good);
        assert_eq!(verified.this_update, secs(THIS_UPDATE));
        assert_eq!(verified.next_update, Some(secs(NEXT_UPDATE)));
        assert_eq!(verified.produced_at, secs(THIS_UPDATE));
        assert_eq!(verified.expires, secs(NEXT_UPDATE));
        assert_eq!(verified.signer, OcspSigner::Issuer);
        assert_eq!(verified.cert_id_hash, CertIdHash::Sha1);
        assert_eq!(verified.sct_list, None);
        assert!(!verified.nonce_matched);
        assert_eq!(
            parsed.verify(&fx.ee(), &OcspIssuer::from_cert(&ca), &policy),
            Ok(verified)
        );
    }
}

#[test]
fn responder_by_name_and_sha256_cert_id() {
    let fx = Fixture::new();
    let mut response = fx.response();
    response.responder_id = by_name(&fx.ca());
    response.singles = vec![Single::good(&fx.cert_id(CertIdHash::Sha256))];
    let der = response.signed_by(fx.ca_key());
    let verified = fx.verify(&der, &fetched()).unwrap();
    assert_eq!(verified.cert_id_hash, CertIdHash::Sha256);
    assert_eq!(verified.signer, OcspSigner::Issuer);

    // Neither a name nor a SHA-256 identifier needs SHA-1.
    let mut policy = fetched();
    policy.hashers.sha1 = None;
    assert!(fx.verify(&der, &policy).is_ok());
    policy.hashers.sha256 = None;
    assert_eq!(
        fx.verify(&der, &policy),
        Err(OcspError::DigestUnavailable(CertIdHash::Sha256))
    );

    // A key identifier does.
    let mut by_key_response = response.clone();
    by_key_response.responder_id = by_key(fx.ca_key());
    let der = by_key_response.signed_by(fx.ca_key());
    let mut policy = fetched();
    policy.hashers.sha1 = None;
    assert_eq!(
        fx.verify(&der, &policy),
        Err(OcspError::DigestUnavailable(CertIdHash::Sha1))
    );
}

#[test]
fn issuer_as_trust_anchor() {
    let fx = Fixture::new();
    let der = fx.response().signed_by(fx.ca_key());
    let anchor = anchor_from_trusted_cert(&fx.ca_der).unwrap();
    let ee = fx.ee();
    let issuer = OcspIssuer::from_trust_anchor(&anchor);
    assert_eq!(issuer.subject(), fx.ca().subject());
    let verified = verify_response(&der, &ee, &issuer, &fetched()).unwrap();
    assert_eq!(verified.status, CertStatus::Good);

    // The root did not issue the end entity.
    let root_der = fx.chain.root_der();
    let root = Cert::try_from(&root_der).unwrap();
    assert_eq!(
        verify_response(&der, &ee, &OcspIssuer::from_cert(&root), &fetched()),
        Err(OcspError::IssuerMismatch)
    );
    // The right name with a malformed key.
    let bad_key = OcspIssuer::new(fx.ca().subject(), &[0x30, 0x00]);
    assert_eq!(
        verify_response(&der, &ee, &bad_key, &fetched()),
        Err(OcspError::BadIssuerKey(Error::BadDer))
    );
}

#[test]
fn revoked_and_unknown_are_authenticated_answers() {
    let fx = Fixture::new();
    let mut response = fx.response();

    response.singles[0].status = revoked(THIS_UPDATE - DAY, Some(1));
    let der = response.signed_by(fx.ca_key());
    let verified = fx.verify(&der, &stapled()).unwrap();
    assert_eq!(
        verified.status,
        CertStatus::Revoked {
            time: secs(THIS_UPDATE - DAY),
            reason: Some(RevocationReason::KeyCompromise),
        }
    );

    // No reason, and a reason code this crate does not know.
    for reason in [None, Some(7)] {
        response.singles[0].status = revoked(THIS_UPDATE - DAY, reason);
        let der = response.signed_by(fx.ca_key());
        let verified = fx.verify(&der, &fetched()).unwrap();
        assert!(matches!(
            verified.status,
            CertStatus::Revoked { reason: None, .. }
        ));
    }

    response.singles[0].status = UNKNOWN.to_vec();
    let der = response.signed_by(fx.ca_key());
    for policy in [stapled(), fetched()] {
        let verified = fx.verify(&der, &policy).unwrap();
        assert_eq!(verified.status, CertStatus::Unknown);
        assert_eq!(verified.signer, OcspSigner::Issuer);
    }
}

#[test]
fn unsuccessful_responder_is_a_distinct_error() {
    let fx = Fixture::new();
    for (code, status) in [
        (1, ResponseStatus::MalformedRequest),
        (2, ResponseStatus::InternalError),
        (3, ResponseStatus::TryLater),
        (5, ResponseStatus::SigRequired),
        (6, ResponseStatus::Unauthorized),
    ] {
        let der = [0x30, 0x03, 0x0a, 0x01, code];
        for policy in [stapled(), fetched()] {
            let error = fx.verify(&der, &policy).unwrap_err();
            assert_eq!(error, OcspError::ResponderUnsuccessful(status));
            assert!(!error.is_stale());
        }
    }
}

#[test]
fn signature_failures() {
    let fx = Fixture::new();
    let response = fx.response();
    let invalid = Err(OcspError::BadSignature(Error::InvalidSignatureForPublicKey));

    // Signed by a key that is not the CA's, while naming the CA.
    let stranger = key_for(alg());
    let der = response.signed_by(&stranger);
    assert_eq!(fx.verify(&der, &stapled()), invalid);

    // Naming a responder that is neither the CA nor a carried certificate.
    let mut unknown = response.clone();
    unknown.responder_id = by_key(&stranger);
    let der = unknown.signed_by(&stranger);
    assert_eq!(
        fx.verify(&der, &stapled()),
        Err(OcspError::UnknownResponder)
    );

    // No algorithm for the signature.
    let der = response.signed_by(fx.ca_key());
    let ed25519_only: &[&dyn browntls_pki::SignatureVerificationAlgorithm] = &[&ED25519];
    let policy = OcspPolicy::stapled(ed25519_only, HASHERS, NOW);
    assert_eq!(
        fx.verify(&der, &policy),
        Err(OcspError::BadSignature(
            Error::UnsupportedSignatureAlgorithm
        ))
    );

    // Every single-octet change is rejected, and none panics.
    assert!(fx.verify(&der, &stapled()).is_ok());
    for i in 0..der.len() {
        for mask in [0x01, 0x80] {
            let mut changed = der.clone();
            changed[i] ^= mask;
            assert!(
                fx.verify(&changed, &stapled()).is_err(),
                "octet {i} mask {mask:#x}"
            );
        }
    }
    // Every truncation is malformed.
    for len in 0..der.len() {
        assert!(
            matches!(
                OcspResponse::from_der(&der[..len]),
                Err(OcspError::Malformed(_))
            ),
            "length {len}"
        );
    }
    let mut trailing = der.clone();
    trailing.push(0);
    assert_eq!(
        OcspResponse::from_der(&trailing).err(),
        Some(OcspError::Malformed(Error::TrailingData))
    );
}

#[test]
fn selects_the_matching_single_response() {
    let fx = Fixture::new();
    let ee_id = fx.cert_id(CertIdHash::Sha1);
    let other_id = CertId::from_parts(
        CertIdHash::Sha1,
        ee_id.issuer_name_hash(),
        ee_id.issuer_key_hash(),
        OTHER_SERIAL,
    )
    .unwrap();
    let sct = |list: &[u8]| extension(oid::SCT_LIST, false, &tlv(0x04, list));

    let mut other = Single::good(&other_id);
    other.extensions = vec![sct(b"other list")];
    // Another serial under an unknown hash algorithm (SHA-384).
    let mut unknown_hash = Single::good(&ee_id);
    unknown_hash.cert_id = sha384_cert_id(OTHER_SERIAL);
    // The end entity's serial under another issuer.
    let foreign_id =
        CertId::from_parts(CertIdHash::Sha1, &[0x11; 20], &[0x22; 20], EE_SERIAL).unwrap();
    let foreign = Single::good(&foreign_id);
    let mut ee = Single::good(&ee_id);
    ee.status = revoked(THIS_UPDATE, None);
    ee.extensions = vec![
        extension(
            &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x06],
            false,
            &[0x05, 0x00],
        ),
        sct(b"signed timestamps"),
    ];

    let mut response = fx.response();
    response.singles = vec![other.clone(), unknown_hash.clone(), foreign.clone(), ee];
    let der = response.signed_by(fx.ca_key());
    let verified = fx.verify(&der, &stapled()).unwrap();
    assert!(matches!(verified.status, CertStatus::Revoked { .. }));
    assert_eq!(verified.sct_list, Some(&b"signed timestamps"[..]));
    let parsed = OcspResponse::from_der(&der).unwrap();
    let lists: Vec<_> = parsed
        .basic()
        .unwrap()
        .responses()
        .map(|single| single.sct_list())
        .collect();
    assert_eq!(lists[0], Some(&b"other list"[..]));
    assert_eq!(lists[1], None);
    assert_eq!(
        parsed
            .basic()
            .unwrap()
            .responses()
            .nth(1)
            .unwrap()
            .cert_id()
            .hash_algorithm(),
        None
    );

    // Without a response about the end entity.
    response.singles = vec![other, unknown_hash, foreign];
    let der = response.signed_by(fx.ca_key());
    assert_eq!(
        fx.verify(&der, &stapled()),
        Err(OcspError::NoMatchingResponse)
    );
    response.singles = Vec::new();
    let der = response.signed_by(fx.ca_key());
    assert_eq!(
        fx.verify(&der, &stapled()),
        Err(OcspError::NoMatchingResponse)
    );

    // A SHA-1 identifier cannot be matched without SHA-1.
    let mut response = fx.response();
    response.responder_id = by_name(&fx.ca());
    let der = response.signed_by(fx.ca_key());
    let mut policy = stapled();
    policy.hashers.sha1 = None;
    assert_eq!(
        fx.verify(&der, &policy),
        Err(OcspError::DigestUnavailable(CertIdHash::Sha1))
    );
}

/// A `CertID` under SHA-384, which this crate does not know.
fn sha384_cert_id(serial: &[u8]) -> Vec<u8> {
    seq(&[
        &seq(&[&tlv(
            0x06,
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
        )]),
        &tlv(0x04, &[0; 48]),
        &tlv(0x04, &[0; 48]),
        &tlv(0x02, serial),
    ])
}

#[test]
fn ambiguous_single_responses_are_rejected() {
    let fx = Fixture::new();
    let good = |hash| Single::good(&fx.cert_id(hash));
    let revoked_under = |hash| {
        let mut single = good(hash);
        single.status = revoked(THIS_UPDATE, Some(1));
        single
    };
    let verify = |singles: Vec<Single>, policy: &OcspPolicy<'_>| {
        let mut response = fx.response();
        response.responder_id = by_name(&fx.ca());
        response.singles = singles;
        let der = response.signed_by(fx.ca_key());
        // The response is authentic: only the selection is at stake.
        let parsed = OcspResponse::from_der(&der).unwrap();
        let ca = fx.ca();
        parsed
            .basic()
            .unwrap()
            .signed_data()
            .verify_signature(ALGS, &ca.subject_public_key_info())
            .unwrap();
        fx.verify(&der, policy).map(|verified| verified.status)
    };
    let ambiguous = Err(OcspError::AmbiguousResponse);
    let (sha1, sha256) = (CertIdHash::Sha1, CertIdHash::Sha256);

    // Controls: one entry per response.
    assert_eq!(verify(vec![good(sha1)], &stapled()), Ok(CertStatus::Good));
    assert!(matches!(
        verify(vec![revoked_under(sha256)], &stapled()),
        Ok(CertStatus::Revoked { .. })
    ));

    // Two entries for the certificate, in either order, with conflicting
    // or equal statuses, under one hash algorithm or under both.
    for singles in [
        vec![good(sha1), revoked_under(sha1)],
        vec![revoked_under(sha1), good(sha1)],
        vec![good(sha1), good(sha1)],
        vec![good(sha1), revoked_under(sha256)],
        vec![revoked_under(sha256), good(sha1)],
        vec![good(sha256), revoked_under(sha1)],
        vec![good(sha1), good(sha256)],
        vec![good(sha256), revoked_under(sha256)],
    ] {
        for policy in [stapled(), fetched()] {
            assert_eq!(verify(singles.clone(), &policy), ambiguous);
        }
    }
    // Entries about other certificates between or around them do not help.
    let foreign =
        Single::good(&CertId::from_parts(sha1, &[0x11; 20], &[0x22; 20], EE_SERIAL).unwrap());
    assert_eq!(
        verify(
            vec![good(sha1), foreign.clone(), revoked_under(sha1)],
            &stapled()
        ),
        ambiguous
    );
    // The same serial under another issuer alone is not ambiguous.
    assert_eq!(
        verify(vec![foreign.clone(), good(sha1), foreign], &stapled()),
        Ok(CertStatus::Good)
    );

    // An equivalent entry that cannot be evaluated is not ignored: a
    // missing digest function is reported rather than answering `Good`.
    for singles in [
        vec![good(sha1), revoked_under(sha256)],
        vec![revoked_under(sha256), good(sha1)],
    ] {
        let mut policy = stapled();
        policy.hashers.sha256 = None;
        assert_eq!(
            verify(singles, &policy),
            Err(OcspError::DigestUnavailable(sha256))
        );
    }

    // The certificate's serial under an unknown hash algorithm cannot be
    // told from another entry about it.
    let mut unknown = revoked_under(sha1);
    unknown.cert_id = sha384_cert_id(EE_SERIAL);
    assert_eq!(
        verify(vec![good(sha1), unknown.clone()], &stapled()),
        ambiguous
    );
    assert_eq!(
        verify(vec![unknown.clone(), good(sha1)], &stapled()),
        ambiguous
    );
    assert_eq!(
        verify(vec![unknown], &stapled()),
        Err(OcspError::NoMatchingResponse)
    );
}

// ---------------------------------------------------------------------------
// Freshness
// ---------------------------------------------------------------------------

#[test]
fn fetched_responses_need_next_update() {
    let fx = Fixture::new();
    let mut response = fx.response();
    response.singles[0].next_update = None;
    let der = response.signed_by(fx.ca_key());
    assert_eq!(
        fx.verify(&der, &fetched()),
        Err(OcspError::MissingNextUpdate)
    );

    // A staple without nextUpdate is usable for a day after thisUpdate.
    let verified = fx.verify(&der, &stapled()).unwrap();
    assert_eq!(verified.next_update, None);
    assert_eq!(verified.expires, secs(THIS_UPDATE + DAY));
    let late = at_time(stapled(), THIS_UPDATE + DAY + HOUR);
    let error = fx.verify(&der, &late).unwrap_err();
    assert_eq!(
        error,
        OcspError::Expired {
            time: secs(THIS_UPDATE + DAY + HOUR),
            expires: secs(THIS_UPDATE + DAY),
        }
    );
    assert!(error.is_stale());
    let mut longer = late;
    longer.validity_without_next_update = Duration::from_secs(2 * DAY);
    assert_eq!(
        fx.verify(&der, &longer).unwrap().expires,
        secs(THIS_UPDATE + 2 * DAY)
    );
}

#[test]
fn validity_interval_and_clock_skew() {
    let fx = Fixture::new();
    let der = fx.response().signed_by(fx.ca_key());
    let skew = 300;
    for policy in [stapled(), fetched()] {
        // Up to nextUpdate plus the skew allowance.
        assert!(
            fx.verify(&der, &at_time(policy, NEXT_UPDATE + skew))
                .is_ok()
        );
        assert_eq!(
            fx.verify(&der, &at_time(policy, NEXT_UPDATE + skew + 1)),
            Err(OcspError::Expired {
                time: secs(NEXT_UPDATE + skew + 1),
                expires: secs(NEXT_UPDATE),
            })
        );
        // From thisUpdate minus the skew allowance.
        assert!(
            fx.verify(&der, &at_time(policy, THIS_UPDATE - skew))
                .is_ok()
        );
        let early = fx.verify(&der, &at_time(policy, THIS_UPDATE - skew - 1));
        assert_eq!(
            early,
            Err(OcspError::NotYetValid {
                time: secs(THIS_UPDATE - skew - 1),
                not_before: secs(THIS_UPDATE),
            })
        );
        assert!(early.unwrap_err().is_stale());
        let mut strict = at_time(policy, NEXT_UPDATE + 1);
        strict.clock_skew = Duration::ZERO;
        assert!(fx.verify(&der, &strict).unwrap_err().is_stale());
    }

    // producedAt in the future.
    let mut response = fx.response();
    response.produced_at = NOW_SECS + HOUR;
    let der = response.signed_by(fx.ca_key());
    assert_eq!(
        fx.verify(&der, &stapled()),
        Err(OcspError::NotYetValid {
            time: NOW,
            not_before: secs(NOW_SECS + HOUR),
        })
    );

    // nextUpdate before thisUpdate.
    let mut response = fx.response();
    response.singles[0].next_update = Some(THIS_UPDATE - 1);
    let der = response.signed_by(fx.ca_key());
    assert_eq!(
        fx.verify(&der, &stapled()),
        Err(OcspError::InvalidUpdateTimes)
    );
}

#[test]
fn staples_have_a_bounded_age() {
    let fx = Fixture::new();
    let mut response = fx.response();
    // A response claiming a year of validity.
    response.singles[0].next_update = Some(THIS_UPDATE + 365 * DAY);
    let der = response.signed_by(fx.ca_key());

    let verified = fx.verify(&der, &stapled()).unwrap();
    assert_eq!(verified.next_update, Some(secs(THIS_UPDATE + 365 * DAY)));
    assert_eq!(verified.expires, secs(THIS_UPDATE + 10 * DAY));
    let old = THIS_UPDATE + 11 * DAY;
    assert_eq!(
        fx.verify(&der, &at_time(stapled(), old)),
        Err(OcspError::Expired {
            time: secs(old),
            expires: secs(THIS_UPDATE + 10 * DAY),
        })
    );
    // A fetched response is bounded by nextUpdate alone, unless asked.
    let verified = fx.verify(&der, &at_time(fetched(), old)).unwrap();
    assert_eq!(verified.expires, secs(THIS_UPDATE + 365 * DAY));
    let mut bounded = at_time(fetched(), old);
    bounded.max_age = Some(Duration::from_secs(DAY));
    assert!(fx.verify(&der, &bounded).unwrap_err().is_stale());
}

// ---------------------------------------------------------------------------
// Nonces and extensions
// ---------------------------------------------------------------------------

#[test]
fn nonces() {
    let fx = Fixture::new();
    let nonce = [0xa5; 16];
    let plain = fx.response().signed_by(fx.ca_key());
    let mut response = fx.response();
    response.extensions = vec![extension(oid::NONCE, false, &tlv(0x04, &nonce))];
    let wrapped = response.signed_by(fx.ca_key());
    // Some responders put the nonce in the extension value unwrapped.
    response.extensions = vec![extension(oid::NONCE, true, &nonce)];
    let unwrapped = response.signed_by(fx.ca_key());

    let mut policy = fetched();
    assert!(!fx.verify(&wrapped, &policy).unwrap().nonce_matched);
    policy.expected_nonce = Some(&nonce);
    for der in [&wrapped, &unwrapped] {
        let parsed = OcspResponse::from_der(der).unwrap();
        assert_eq!(parsed.basic().unwrap().nonce(), Some(&nonce[..]));
        assert!(fx.verify(der, &policy).unwrap().nonce_matched);
    }
    // A pre-produced response without nonce is accepted unless required.
    assert!(!fx.verify(&plain, &policy).unwrap().nonce_matched);
    policy.require_nonce = true;
    assert_eq!(fx.verify(&plain, &policy), Err(OcspError::NonceMissing));
    assert!(fx.verify(&wrapped, &policy).is_ok());

    let other = [0x5a; 16];
    policy.expected_nonce = Some(&other);
    policy.require_nonce = false;
    assert_eq!(fx.verify(&wrapped, &policy), Err(OcspError::NonceMismatch));

    // A repeated nonce extension.
    let one = extension(oid::NONCE, false, &tlv(0x04, &nonce));
    response.extensions = vec![one.clone(), one];
    let der = response.signed_by(fx.ca_key());
    assert_eq!(
        OcspResponse::from_der(&der).err(),
        Some(OcspError::Malformed(Error::MalformedExtensions))
    );
}

#[test]
fn structure_and_extension_rules() {
    let fx = Fixture::new();
    let key = fx.ca_key();
    let unknown_oid = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x7f, 0x01][..];
    let malformed = |error| Some(OcspError::Malformed(error));

    // Unknown extensions: ignored unless critical.
    let mut response = fx.response();
    response.extensions = vec![extension(unknown_oid, false, &[0x05, 0x00])];
    response.singles[0].extensions = vec![extension(unknown_oid, false, &[0x05, 0x00])];
    assert!(fx.verify(&response.signed_by(key), &stapled()).is_ok());
    response.extensions = vec![extension(unknown_oid, true, &[0x05, 0x00])];
    assert_eq!(
        OcspResponse::from_der(&response.signed_by(key)).err(),
        malformed(Error::UnsupportedCriticalExtension)
    );
    let mut response = fx.response();
    response.singles[0].extensions = vec![extension(unknown_oid, true, &[0x05, 0x00])];
    assert_eq!(
        OcspResponse::from_der(&response.signed_by(key)).err(),
        malformed(Error::UnsupportedCriticalExtension)
    );

    // A timestamp list that is not an OCTET STRING, or is repeated.
    response.singles[0].extensions = vec![extension(oid::SCT_LIST, false, &[0x05, 0x00])];
    assert_eq!(
        OcspResponse::from_der(&response.signed_by(key)).err(),
        malformed(Error::ExtensionValueInvalid)
    );
    let sct = extension(oid::SCT_LIST, false, &tlv(0x04, b"list"));
    response.singles[0].extensions = vec![sct.clone(), sct];
    assert_eq!(
        OcspResponse::from_der(&response.signed_by(key)).err(),
        malformed(Error::MalformedExtensions)
    );

    // Version: an explicit v1 is tolerated, anything else is not.
    let mut response = fx.response();
    response.version = Some(0);
    assert!(fx.verify(&response.signed_by(key), &stapled()).is_ok());
    response.version = Some(1);
    assert_eq!(
        OcspResponse::from_der(&response.signed_by(key)).err(),
        Some(OcspError::UnsupportedVersion)
    );

    // Times must be GeneralizedTime.
    let mut response = fx.response();
    response.singles[0].this_update = tlv(0x17, b"240531230000Z");
    assert_eq!(
        OcspResponse::from_der(&response.signed_by(key)).err(),
        malformed(Error::BadDerTime)
    );

    // A responder key hash of the wrong length, and an unknown choice.
    for responder_id in [tlv(0xa2, &tlv(0x04, &[0; 32])), tlv(0xa3, &[0x05, 0x00])] {
        let mut response = fx.response();
        response.responder_id = responder_id;
        assert_eq!(
            OcspResponse::from_der(&response.signed_by(key)).err(),
            malformed(Error::BadDer)
        );
    }

    // A SHA-1 CertID with SHA-256 sized hashes.
    let mut response = fx.response();
    response.singles[0].cert_id = seq(&[
        &seq(&[&tlv(0x06, oid::SHA1), &[0x05, 0x00]]),
        &tlv(0x04, &[0; 32]),
        &tlv(0x04, &[0; 32]),
        &tlv(0x02, EE_SERIAL),
    ]);
    assert_eq!(
        OcspResponse::from_der(&response.signed_by(key)).err(),
        malformed(Error::BadDer)
    );

    // Carried certificates: unparsable ones are ignored up to the limit.
    let mut response = fx.response();
    response.certs = vec![vec![0x30, 0x00]; MAX_RESPONSE_CERTS];
    let der = response.signed_by(key);
    assert_eq!(
        OcspResponse::from_der(&der)
            .unwrap()
            .basic()
            .unwrap()
            .certificates()
            .count(),
        MAX_RESPONSE_CERTS
    );
    assert!(fx.verify(&der, &stapled()).is_ok());
    response.certs.push(vec![0x30, 0x00]);
    assert_eq!(
        OcspResponse::from_der(&response.signed_by(key)).err(),
        Some(OcspError::TooManyCertificates)
    );
    response.certs = vec![vec![0x04, 0x00]];
    assert_eq!(
        OcspResponse::from_der(&response.signed_by(key)).err(),
        malformed(Error::BadDer)
    );

    // Size limit.
    let mut response = fx.response();
    response.extensions = vec![extension(unknown_oid, false, &vec![0; 70_000])];
    assert_eq!(
        OcspResponse::from_der(&response.signed_by(key)).err(),
        Some(OcspError::ResponseTooLarge)
    );
}
