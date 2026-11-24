//! CRLs signed with ML-DSA keys, as the verifiers check them during path
//! validation and as `browntls_pki` verifies them with the provider's
//! algorithm lists.

use browntls_core::crypto::native;
use browntls_core::{CertRevocationListError, CertificateError, Error};
use browntls_pki::{CertRevocationList, Error as PkiError, OwnedCertRevocationList};
use sha2::Digest as _;

use crate::ml_dsa::{Key, SETS};
use crate::x509::CrlSpec;
use crate::{
    Chain, Impl, Issuer, MlKey, NOW, Purpose, UNSUPPORTED, build_chain, default_provider,
    opt_in_provider,
};

/// The serial `x509_builder` gives the end entity.
fn ee_serial() -> Vec<u8> {
    sha2::Sha256::digest(b"end entity")[..8].to_vec()
}

/// A CRL of the root, signed by `issuer`, revoking `revoked`.
fn crl(issuer: Issuer<'_>, revoked: &[&[u8]]) -> Vec<u8> {
    let mut spec = CrlSpec::new("root", NOW - 3600, NOW + 30 * 86_400);
    for serial in revoked {
        spec = spec.revoke(serial, NOW - 7200);
    }
    issuer.signed(spec.tbs(issuer.key())).der()
}

/// `crl` with one bit of its signature (which it ends with) flipped.
fn tampered(mut crl: Vec<u8>) -> Vec<u8> {
    let last = crl.len() - 1;
    crl[last] ^= 0x10;
    crl
}

#[test]
fn ml_dsa_signed_crls_through_the_verifiers() {
    let ee = Key::p256();
    let unrelated: &[u8] = &[0x01, 0x02, 0x03];
    for set in SETS {
        let root_key = MlKey::new(set, "root");
        for by in [Impl::Native, Impl::Oracle] {
            let root = Issuer::MlDsa(&root_key, by);
            let chain: Chain = build_chain(root, &[], &ee, Purpose::Server);
            let good = crl(root, &[unrelated]);
            let revoked = crl(root, &[unrelated, &ee_serial()]);
            let what = format!("{set:?} by {by:?}");

            assert_eq!(
                chain.verify_server(opt_in_provider(), std::slice::from_ref(&good)),
                Ok(()),
                "{what}"
            );
            assert_eq!(
                chain.verify_server(opt_in_provider(), std::slice::from_ref(&revoked)),
                Err(Error::InvalidCertificate(CertificateError::Revoked)),
                "{what}"
            );
            assert_eq!(
                chain.verify_server(opt_in_provider(), &[tampered(good.clone())]),
                Err(Error::InvalidCertRevocationList(
                    CertRevocationListError::BadSignature
                )),
                "{what}"
            );
            // A revoked entry in a CRL whose signature does not verify
            // revokes nothing: the CRL is refused as a whole.
            assert_eq!(
                chain.verify_server(opt_in_provider(), &[tampered(revoked.clone())]),
                Err(Error::InvalidCertRevocationList(
                    CertRevocationListError::BadSignature
                )),
                "{what}"
            );
            // With the default table the certificate signature of the same
            // issuer fails first: a CRL's issuer is the certificate's.
            assert_eq!(
                chain.verify_server(default_provider(), &[good]),
                Err(UNSUPPORTED),
                "{what}"
            );
        }
    }
}

#[test]
fn ml_dsa_signed_crls_with_the_provider_lists() {
    for set in SETS {
        let root_key = MlKey::new(set, "root");
        let spki = crate::x509::spki_of(&root_key.oracle);
        for by in [Impl::Native, Impl::Oracle] {
            let der = crl(Issuer::MlDsa(&root_key, by), &[&ee_serial()]);
            // As the verifier builders hold them.
            let list = CertRevocationList::from(OwnedCertRevocationList::from_der(&der).unwrap());
            assert_eq!(
                list.verify_signature(native::SUPPORTED_SIG_ALGS_WITH_ML_DSA.all, &spki),
                Ok(())
            );
            for algs in [
                native::SUPPORTED_SIG_ALGS.all,
                native::ALL_VERIFICATION_ALGS,
            ] {
                assert_eq!(
                    list.verify_signature(algs, &spki),
                    Err(PkiError::UnsupportedCrlSignatureAlgorithm),
                    "{set:?}"
                );
            }
            let bad = CertRevocationList::from(
                OwnedCertRevocationList::from_der(&tampered(der)).unwrap(),
            );
            assert_eq!(
                bad.verify_signature(native::SUPPORTED_SIG_ALGS_WITH_ML_DSA.all, &spki),
                Err(PkiError::InvalidCrlSignatureForPublicKey)
            );
        }
    }
}

#[test]
fn ml_dsa_signed_crl_through_the_client_verifier() {
    let ee = Key::p256();
    let root_key = MlKey::new(crate::ml_dsa::Set::MlDsa65, "root");
    let root = Issuer::MlDsa(&root_key, Impl::Native);
    let chain = build_chain(root, &[], &ee, Purpose::Client);
    let verify = |crl: Vec<u8>| {
        let verifier = browntls_core::server::WebPkiClientVerifier::builder_with_provider(
            chain.roots(),
            opt_in_provider(),
        )
        .with_crls([browntls_core::pki_types::CertificateRevocationListDer::from(crl)])
        .build()
        .unwrap();
        verifier
            .verify_client_cert(
                &browntls_core::pki_types::CertificateDer::from(&chain.ee[..]),
                &[],
                crate::now(),
            )
            .map(|_| ())
    };
    assert_eq!(verify(crl(root, &[])), Ok(()));
    assert_eq!(
        verify(crl(root, &[&ee_serial()])),
        Err(Error::InvalidCertificate(CertificateError::Revoked))
    );
    assert_eq!(
        verify(tampered(crl(root, &[]))),
        Err(Error::InvalidCertRevocationList(
            CertRevocationListError::BadSignature
        ))
    );
}
