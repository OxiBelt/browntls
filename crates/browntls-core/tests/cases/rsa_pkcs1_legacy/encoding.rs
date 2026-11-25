// Cases included by `cases/rsa_pkcs1_legacy.rs`, which holds the imports
// and the shared helpers: client CertificateVerify messages under a legacy
// scheme that are not the exact RSASSA-PKCS1-v1_5 encoding RFC 9963 §3
// asks for, and signatures whose scheme does not match their form or the
// certificate's key. The server has opted in, so each scheme named here
// is one its CertificateRequest listed.

/// The `rsa` crate's RSASSA-PKCS1-v1_5 signature is the one this file's
/// `DigestInfo` builder describes, so that each malformed variant below
/// differs from a valid signature in the one way it names.
#[test]
fn digest_info_builder_matches_the_rsa_crate() {
    let key = rsa_key(rsa_client());
    for hash in [Hash::Sha256, Hash::Sha384, Hash::Sha512] {
        let t = digest_info(hash, &hash.digest(b"message"), true);
        assert_eq!(sign_raw(&key, &t), hash.pkcs1(&key, b"message"), "{hash:?}");
        assert_ne!(
            sign_raw(&key, &digest_info(hash, &hash.digest(b"message"), false)),
            hash.pkcs1(&key, b"message")
        );
    }
}

/// Signatures under a legacy scheme that are not RSASSA-PKCS1-v1_5 in the
/// exact encoding of RFC 8017 §8.2 with the scheme's hash, over the
/// CertificateVerify content: each is refused with a bad signature, and
/// the server sends `decrypt_error` (RFC 9846 §4.4.3). The cases run
/// under 0x0420 (SHA-256), and the encoding cases under the other two
/// schemes as well.
#[test]
fn legacy_signatures_must_be_exactly_encoded() {
    let cases = [
        ("no NULL parameters", Sig::NoNull),
        ("BER length", Sig::BerLength),
        ("bare digest", Sig::BareDigest),
        ("wrong hash identifier", Sig::WrongOid),
        ("digest of the wrong hash", Sig::WrongHash),
        ("another message", Sig::OtherMessage),
        ("one byte short", Sig::Short),
        ("one byte long", Sig::Long),
    ];
    for (what, sig) in cases {
        let schemes: &[S] = match sig {
            Sig::NoNull | Sig::BerLength | Sig::WrongOid => &LEGACY,
            _ => &[S::RSA_PKCS1_SHA256_LEGACY],
        };
        for &scheme in schemes {
            let key = TokenKey::choosing(rsa_client(), &[scheme], sig);
            let outcome = authenticate(
                prov::provider_with_rsa_pkcs1_legacy(),
                true,
                rsa_client(),
                key,
            );
            let what = format!("{what} under {scheme:?}");
            outcome.refused(BAD_SIGNATURE, AlertDescription::DecryptError, &what);
            assert_eq!(outcome.verifier.seen(), [scheme], "{what}");
        }
    }
}

/// An RSASSA-PSS signature named as a legacy scheme, and an
/// RSASSA-PKCS1-v1_5 signature named as `rsa_pss_rsae_sha256`: each scheme
/// is one the request listed, the signature is valid in the other form,
/// and the server refuses it as a bad signature with `decrypt_error`.
#[test]
fn signature_form_must_match_the_scheme() {
    let cases = [
        ("PSS as 0x0420", S::RSA_PKCS1_SHA256_LEGACY, Sig::Pss),
        ("PSS as 0x0620", S::RSA_PKCS1_SHA512_LEGACY, Sig::Pss),
        (
            "PKCS #1 v1.5 as rsa_pss_rsae_sha256",
            S::RSA_PSS_SHA256,
            Sig::Pkcs1,
        ),
    ];
    for (what, scheme, sig) in cases {
        let key = TokenKey::choosing(rsa_client(), &[scheme], sig);
        let outcome = authenticate(
            prov::provider_with_rsa_pkcs1_legacy(),
            true,
            rsa_client(),
            key,
        );
        outcome.refused(BAD_SIGNATURE, AlertDescription::DecryptError, what);
        assert_eq!(outcome.verifier.seen(), [scheme], "{what}");
    }
    // The same key signing properly under each scheme is accepted, so the
    // refusals above are about the form alone.
    for scheme in [S::RSA_PKCS1_SHA256_LEGACY, S::RSA_PSS_SHA256] {
        let sig = if is_legacy(&scheme) {
            Sig::Pkcs1
        } else {
            Sig::Pss
        };
        let key = TokenKey::choosing(rsa_client(), &[scheme], sig);
        let mut outcome = authenticate(
            prov::provider_with_rsa_pkcs1_legacy(),
            true,
            rsa_client(),
            key,
        );
        outcome.completed();
        assert_eq!(outcome.verifier.seen(), [scheme]);
    }
}

/// A client whose certificate key is ECDSA P-256 or Ed25519 names
/// `rsa_pkcs1_sha256_legacy` (which the request lists) and signs with its
/// real key: the legacy schemes need an `rsaEncryption` key, so the server
/// refuses the scheme for the certificate's key, with `decrypt_error`.
#[test]
fn legacy_scheme_needs_an_rsa_certificate_key() {
    for (key_type, real_scheme) in [
        (KeyType::EcdsaP256, S::ECDSA_NISTP256_SHA256),
        (KeyType::Ed25519, S::ED25519),
    ] {
        let chain = common::client_chain(key_type);
        let real = prov::provider()
            .key_provider
            .load_private_key(chain.private_key())
            .unwrap();
        let key = Arc::new(ClaimingKey {
            claims: S::RSA_PKCS1_SHA256_LEGACY,
            real,
            real_scheme,
        });
        let outcome = authenticate(prov::provider_with_rsa_pkcs1_legacy(), true, &chain, key);
        let what = format!("{key_type:?}");
        outcome.refused(UNSUPPORTED, AlertDescription::DecryptError, &what);
        assert_eq!(outcome.verifier.seen(), [S::RSA_PKCS1_SHA256_LEGACY]);
    }
}
