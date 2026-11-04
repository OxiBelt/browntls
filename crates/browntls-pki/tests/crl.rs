//! Certificate revocation lists generated at run time.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use browntls_pki::crl::CrlsRequired;
use browntls_pki::{
    BorrowedCertRevocationList, CertRevocationList, CertificateDer, EndEntityCert, Error,
    ExpirationPolicy, KeyUsage, OwnedCertRevocationList, RevocationCheckDepth, RevocationOptions,
    RevocationOptionsBuilder, RevocationReason, UnknownStatusPolicy, anchor_from_trusted_cert,
};
use common::*;
use rcgen::{
    CertificateParams, CertificateRevocationListParams, CertifiedIssuer, CrlDistributionPoint,
    CrlIssuingDistributionPoint, CrlScope, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose,
    RevokedCertParams, SerialNumber, SigningKey,
};

const EE_SERIAL: &[u8] = &[0x7a, 0x01, 0x02, 0x03];
const INT_SERIAL: &[u8] = &[0x7b, 0x04, 0x05, 0x06];
const OTHER_SERIAL: &[u8] = &[0x7c, 0x07];
const CRL_URI: &str = "http://crl.example.com/int.crl";
const OTHER_URI: &str = "http://crl.example.com/other.crl";

/// The validity window used by generated CRLs.
const THIS_UPDATE: u64 = 1_717_000_000;
const NEXT_UPDATE: u64 = 1_718_000_000;

fn alg() -> &'static rcgen::SignatureAlgorithm {
    &rcgen::PKCS_ECDSA_P256_SHA256
}

/// `root -> intermediate -> ee` with fixed serial numbers.
fn chain(int_params: CertificateParams, ee_params_: CertificateParams) -> Chain {
    let mut int_params = int_params;
    int_params.serial_number = Some(SerialNumber::from_slice(INT_SERIAL));
    let mut ee_params_ = ee_params_;
    ee_params_.serial_number = Some(SerialNumber::from_slice(EE_SERIAL));
    Chain::build(alg(), ca_params("root"), vec![int_params], &ee_params_)
}

fn default_chain() -> Chain {
    chain(ca_params("intermediate"), ee_params(&["example.com"]))
}

fn crl_params(
    revoked: &[&[u8]],
    this_update: u64,
    next_update: u64,
    idp: Option<CrlIssuingDistributionPoint>,
) -> CertificateRevocationListParams {
    CertificateRevocationListParams {
        this_update: at(this_update),
        next_update: at(next_update),
        crl_number: SerialNumber::from(42u64),
        issuing_distribution_point: idp,
        revoked_certs: revoked
            .iter()
            .map(|serial| RevokedCertParams {
                serial_number: SerialNumber::from_slice(serial),
                revocation_time: at(this_update - 1000),
                reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                invalidity_date: Some(at(this_update - 2000)),
            })
            .collect(),
        key_identifier_method: KeyIdMethod::Sha256,
    }
}

fn crl_der(
    issuer: &Issuer<'_, impl SigningKey>,
    params: &CertificateRevocationListParams,
) -> Vec<u8> {
    params.signed_by(issuer).unwrap().der().to_vec()
}

fn simple_crl(issuer: &Issuer<'_, impl SigningKey>, revoked: &[&[u8]]) -> Vec<u8> {
    crl_der(issuer, &crl_params(revoked, THIS_UPDATE, NEXT_UPDATE, None))
}

fn borrowed(der: &[u8]) -> CertRevocationList<'_> {
    CertRevocationList::from(BorrowedCertRevocationList::from_der(der).unwrap())
}

fn owned(der: &[u8]) -> CertRevocationList<'static> {
    CertRevocationList::from(OwnedCertRevocationList::from_der(der).unwrap())
}

fn options<'a>(
    crls: &'a [&'a CertRevocationList<'a>],
    depth: RevocationCheckDepth,
    status: UnknownStatusPolicy,
    expiration: ExpirationPolicy,
) -> RevocationOptions<'a> {
    RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(depth)
        .with_status_policy(status)
        .with_expiration_policy(expiration)
        .build()
}

/// Chain depth, deny unknown status, enforce expiration.
fn strict<'a>(crls: &'a [&'a CertRevocationList<'a>]) -> RevocationOptions<'a> {
    options(
        crls,
        RevocationCheckDepth::Chain,
        UnknownStatusPolicy::Deny,
        ExpirationPolicy::Enforce,
    )
}

fn verify_chain(chain: &Chain, revocation: Option<RevocationOptions<'_>>) -> Result<(), Error> {
    chain.verify_with(ALGS, NOW, KeyUsage::server_auth(), revocation)
}

#[test]
fn builder_defaults_and_requirements() {
    assert_eq!(RevocationOptionsBuilder::new(&[]).err(), Some(CrlsRequired));
    let chain = default_chain();
    let crl = simple_crl(&chain.intermediates[0], &[]);
    let crl = borrowed(&crl);
    let crls = [&crl];
    let opts = RevocationOptionsBuilder::new(&crls).unwrap().build();
    assert_eq!(opts.depth, RevocationCheckDepth::Chain);
    assert_eq!(opts.status_policy, UnknownStatusPolicy::Deny);
    assert_eq!(opts.expiration_policy, ExpirationPolicy::Ignore);
    assert_eq!(opts.crls.len(), 1);
}

#[test]
fn not_revoked_and_revoked() {
    let chain = default_chain();
    let int_crl = simple_crl(&chain.intermediates[0], &[OTHER_SERIAL]);
    let root_crl = simple_crl(&chain.root, &[OTHER_SERIAL]);
    let (int_crl, root_crl) = (borrowed(&int_crl), borrowed(&root_crl));

    // Chain depth needs a CRL for every certificate.
    let both = [&int_crl, &root_crl];
    assert_eq!(verify_chain(&chain, Some(strict(&both))), Ok(()));
    let only_int = [&int_crl];
    assert_eq!(
        verify_chain(&chain, Some(strict(&only_int))),
        Err(Error::UnknownRevocationStatus)
    );
    assert_eq!(
        verify_chain(
            &chain,
            Some(options(
                &only_int,
                RevocationCheckDepth::Chain,
                UnknownStatusPolicy::Allow,
                ExpirationPolicy::Enforce,
            ))
        ),
        Ok(())
    );
    assert_eq!(
        verify_chain(
            &chain,
            Some(options(
                &only_int,
                RevocationCheckDepth::EndEntity,
                UnknownStatusPolicy::Deny,
                ExpirationPolicy::Enforce,
            ))
        ),
        Ok(())
    );
    let only_root = [&root_crl];
    assert_eq!(
        verify_chain(
            &chain,
            Some(options(
                &only_root,
                RevocationCheckDepth::EndEntity,
                UnknownStatusPolicy::Deny,
                ExpirationPolicy::Enforce,
            ))
        ),
        Err(Error::UnknownRevocationStatus)
    );

    // Revoked end entity, in borrowed and owned form.
    let revoked_ee = simple_crl(&chain.intermediates[0], &[OTHER_SERIAL, EE_SERIAL]);
    for crl in [borrowed(&revoked_ee), owned(&revoked_ee)] {
        let crls = [&crl, &root_crl];
        assert_eq!(
            verify_chain(&chain, Some(strict(&crls))),
            Err(Error::CertRevoked)
        );
        assert_eq!(
            verify_chain(
                &chain,
                Some(options(
                    &crls,
                    RevocationCheckDepth::EndEntity,
                    UnknownStatusPolicy::Allow,
                    ExpirationPolicy::Ignore,
                ))
            ),
            Err(Error::CertRevoked)
        );
    }

    // Revoked intermediate: only matters at chain depth.
    let revoked_int = simple_crl(&chain.root, &[INT_SERIAL]);
    let revoked_int = borrowed(&revoked_int);
    let crls = [&int_crl, &revoked_int];
    assert_eq!(
        verify_chain(&chain, Some(strict(&crls))),
        Err(Error::CertRevoked)
    );
    assert_eq!(
        verify_chain(
            &chain,
            Some(options(
                &crls,
                RevocationCheckDepth::EndEntity,
                UnknownStatusPolicy::Deny,
                ExpirationPolicy::Enforce,
            ))
        ),
        Ok(())
    );
}

#[test]
fn any_applicable_crl_can_revoke() {
    let chain = default_chain();
    let clean = simple_crl(&chain.intermediates[0], &[]);
    let revoking = simple_crl(&chain.intermediates[0], &[EE_SERIAL]);
    let (clean, revoking) = (borrowed(&clean), borrowed(&revoking));
    for crls in [[&clean, &revoking], [&revoking, &clean]] {
        assert_eq!(
            verify_chain(
                &chain,
                Some(options(
                    &crls,
                    RevocationCheckDepth::EndEntity,
                    UnknownStatusPolicy::Deny,
                    ExpirationPolicy::Enforce,
                ))
            ),
            Err(Error::CertRevoked)
        );
    }
}

#[test]
fn expiration_policy() {
    let chain = default_chain();
    let expired = crl_der(
        &chain.intermediates[0],
        &crl_params(&[EE_SERIAL], THIS_UPDATE - 10_000, NOW.as_secs(), None),
    );
    let expired = borrowed(&expired);
    let crls = [&expired];
    // nextUpdate equal to the validation time counts as expired.
    assert_eq!(
        verify_chain(
            &chain,
            Some(options(
                &crls,
                RevocationCheckDepth::EndEntity,
                UnknownStatusPolicy::Deny,
                ExpirationPolicy::Enforce,
            ))
        ),
        Err(Error::CrlExpired {
            time: NOW,
            next_update: NOW,
        })
    );
    assert_eq!(
        verify_chain(
            &chain,
            Some(options(
                &crls,
                RevocationCheckDepth::EndEntity,
                UnknownStatusPolicy::Deny,
                ExpirationPolicy::Ignore,
            ))
        ),
        Err(Error::CertRevoked)
    );
    // An expired CRL does not hide a current one.
    let current = simple_crl(&chain.intermediates[0], &[]);
    let current = borrowed(&current);
    let crls = [&expired, &current];
    assert_eq!(
        verify_chain(
            &chain,
            Some(options(
                &crls,
                RevocationCheckDepth::EndEntity,
                UnknownStatusPolicy::Deny,
                ExpirationPolicy::Enforce,
            ))
        ),
        Ok(())
    );
    // Ignoring expiration, the newer revocation still counts.
    assert_eq!(
        verify_chain(
            &chain,
            Some(options(
                &crls,
                RevocationCheckDepth::EndEntity,
                UnknownStatusPolicy::Deny,
                ExpirationPolicy::Ignore,
            ))
        ),
        Err(Error::CertRevoked)
    );
}

#[test]
fn crl_signature_and_issuer_key_usage() {
    let chain = default_chain();
    // Signed by an impostor with the intermediate's subject.
    let impostor = CertifiedIssuer::self_signed(ca_params("intermediate"), key_for(alg())).unwrap();
    let forged = simple_crl(&impostor, &[EE_SERIAL]);
    let forged = borrowed(&forged);
    let crls = [&forged];
    assert_eq!(
        verify_chain(
            &chain,
            Some(options(
                &crls,
                RevocationCheckDepth::EndEntity,
                UnknownStatusPolicy::Deny,
                ExpirationPolicy::Enforce,
            ))
        ),
        Err(Error::InvalidCrlSignatureForPublicKey)
    );
    // The standalone signature check accepts both SPKI forms.
    let int_der: CertificateDer<'_> = chain.intermediates[0].der().to_vec().into();
    let int_anchor = anchor_from_trusted_cert(&int_der).unwrap();
    let int_cert = EndEntityCert::try_from(&int_der);
    assert_eq!(int_cert.err(), None);
    let genuine = simple_crl(&chain.intermediates[0], &[EE_SERIAL]);
    let genuine = borrowed(&genuine);
    assert_eq!(
        genuine.verify_signature(ALGS, int_anchor.subject_public_key_info.as_ref()),
        Ok(())
    );
    let int_cert = EndEntityCert::try_from(&int_der).unwrap();
    assert_eq!(
        genuine.verify_signature(ALGS, int_cert.subject_public_key_info().as_ref()),
        Ok(())
    );
    assert_eq!(
        forged.verify_signature(ALGS, int_anchor.subject_public_key_info.as_ref()),
        Err(Error::InvalidCrlSignatureForPublicKey)
    );
    assert_eq!(
        genuine.verify_signature(&[&ED25519], int_anchor.subject_public_key_info.as_ref()),
        Err(Error::UnsupportedCrlSignatureAlgorithm)
    );
    assert_eq!(
        genuine.verify_signature(
            &[&ECDSA_P384_SHA256],
            int_anchor.subject_public_key_info.as_ref()
        ),
        Err(Error::UnsupportedCrlSignatureAlgorithmForPublicKey)
    );

    // An issuer whose KeyUsage lacks cRLSign may not revoke; absent
    // KeyUsage permits it.
    for (usages, expected) in [
        (
            vec![KeyUsagePurpose::KeyCertSign],
            Err(Error::IssuerNotCrlSigner),
        ),
        (vec![], Err(Error::CertRevoked)),
    ] {
        let mut params = ca_params("intermediate");
        params.key_usages = usages;
        let chain = chain_with_int(params.clone());
        // Sign the CRL with the intermediate's key while declaring cRLSign
        // to rcgen, which otherwise refuses.
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let signer: Issuer<'_, &KeyPair> = Issuer::new(params, chain.intermediates[0].key());
        let crl = simple_crl(&signer, &[EE_SERIAL]);
        let crl = borrowed(&crl);
        let crls = [&crl];
        assert_eq!(
            verify_chain(
                &chain,
                Some(options(
                    &crls,
                    RevocationCheckDepth::EndEntity,
                    UnknownStatusPolicy::Deny,
                    ExpirationPolicy::Enforce,
                ))
            ),
            expected
        );
    }
}

fn chain_with_int(int_params: CertificateParams) -> Chain {
    chain(int_params, ee_params(&["example.com"]))
}

fn idp(uri: &str, scope: Option<CrlScope>) -> CrlIssuingDistributionPoint {
    CrlIssuingDistributionPoint {
        distribution_point: CrlDistributionPoint {
            uris: vec![uri.to_string()],
        },
        scope,
    }
}

#[test]
fn issuing_distribution_point_scope() {
    let chain = default_chain();
    let check = |idp: CrlIssuingDistributionPoint, depth| {
        let crl = crl_der(
            &chain.intermediates[0],
            &crl_params(&[EE_SERIAL], THIS_UPDATE, NEXT_UPDATE, Some(idp)),
        );
        let crl = borrowed(&crl);
        assert!(crl.issuing_distribution_point().is_some());
        let crls = [&crl];
        verify_chain(
            &chain,
            Some(options(
                &crls,
                depth,
                UnknownStatusPolicy::Deny,
                ExpirationPolicy::Enforce,
            )),
        )
    };
    // No scope restriction: applies to the (DP-less) end entity.
    assert_eq!(
        check(idp(CRL_URI, None), RevocationCheckDepth::EndEntity),
        Err(Error::CertRevoked)
    );
    assert_eq!(
        check(
            idp(CRL_URI, Some(CrlScope::UserCertsOnly)),
            RevocationCheckDepth::EndEntity
        ),
        Err(Error::CertRevoked)
    );
    // A CA-only CRL is not authoritative for the end entity.
    assert_eq!(
        check(
            idp(CRL_URI, Some(CrlScope::CaCertsOnly)),
            RevocationCheckDepth::EndEntity
        ),
        Err(Error::UnknownRevocationStatus)
    );
}

#[test]
fn distribution_point_uri_matching() {
    let mut ee = ee_params(&["example.com"]);
    ee.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![OTHER_URI.to_string(), CRL_URI.to_string()],
    }];
    let chain = chain(ca_params("intermediate"), ee);
    let check = |idp: Option<CrlIssuingDistributionPoint>| {
        let crl = crl_der(
            &chain.intermediates[0],
            &crl_params(&[EE_SERIAL], THIS_UPDATE, NEXT_UPDATE, idp),
        );
        let crl = owned(&crl);
        let crls = [&crl];
        verify_chain(
            &chain,
            Some(options(
                &crls,
                RevocationCheckDepth::EndEntity,
                UnknownStatusPolicy::Deny,
                ExpirationPolicy::Enforce,
            )),
        )
    };
    // No IDP: the CRL covers everything the issuer signed.
    assert_eq!(check(None), Err(Error::CertRevoked));
    // IDP naming one of the certificate's DP URIs.
    assert_eq!(check(Some(idp(CRL_URI, None))), Err(Error::CertRevoked));
    // IDP naming an unrelated URI.
    assert_eq!(
        check(Some(idp("http://crl.example.com/unrelated.crl", None))),
        Err(Error::UnknownRevocationStatus)
    );
}

#[test]
fn lookup_and_entries() {
    let chain = default_chain();
    let der = simple_crl(&chain.intermediates[0], &[EE_SERIAL, OTHER_SERIAL]);
    let borrowed_crl = BorrowedCertRevocationList::from_der(&der).unwrap();
    assert_eq!(borrowed_crl.into_iter().count(), 2);
    let owned_crl = borrowed_crl.to_owned().unwrap();
    assert_eq!(owned_crl.revoked_certs().count(), 2);
    for crl in [
        CertRevocationList::from(borrowed_crl),
        CertRevocationList::from(owned_crl),
    ] {
        let int_der: CertificateDer<'_> = chain.intermediates[0].der().to_vec().into();
        let int_anchor = anchor_from_trusted_cert(&int_der).unwrap();
        assert_eq!(crl.issuer(), int_anchor.subject.as_ref());
        assert_eq!(crl.this_update(), secs(THIS_UPDATE));
        assert_eq!(crl.next_update(), secs(NEXT_UPDATE));
        assert!(crl.issuing_distribution_point().is_none());
        let entry = crl.find_serial(EE_SERIAL).unwrap().unwrap();
        assert_eq!(entry.serial_number, EE_SERIAL);
        assert_eq!(entry.reason_code, Some(RevocationReason::KeyCompromise));
        assert_eq!(entry.revocation_date, secs(THIS_UPDATE - 1000));
        assert_eq!(entry.invalidity_date, Some(secs(THIS_UPDATE - 2000)));
        assert_eq!(entry.to_owned().borrow(), entry);
        assert!(crl.find_serial(INT_SERIAL).unwrap().is_none());
        assert!(crl.find_serial(&[]).unwrap().is_none());
    }
}

#[test]
fn revocation_errors_rank_above_unknown_issuer() {
    // With two candidate anchors, a revocation found on one path is the
    // reported error even if another path fails for a lesser reason.
    let chain = default_chain();
    let revoking = simple_crl(&chain.intermediates[0], &[EE_SERIAL]);
    let revoking = borrowed(&revoking);
    let crls = [&revoking];
    let revocation = options(
        &crls,
        RevocationCheckDepth::EndEntity,
        UnknownStatusPolicy::Deny,
        ExpirationPolicy::Enforce,
    );
    let other = Chain::simple(alg(), 0);
    let roots = [other.root_der(), chain.root_der()];
    assert_eq!(
        verify(
            &chain.ee_der(),
            &chain.intermediate_ders(),
            &anchors(&roots),
            ALGS,
            NOW,
            KeyUsage::server_auth(),
            Some(revocation),
            None,
        ),
        Err(Error::CertRevoked)
    );
}
