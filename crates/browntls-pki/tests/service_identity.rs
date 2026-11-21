//! RFC 9525 service identity verification regressions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::boxed::Box;
use std::hash::{Hash, Hasher};

use browntls_pki::{
    CertificateDer, DnsName, EndEntityCert, Error, ReferenceIdentifier, ServiceIdentity, SrvId,
    UriId, WildcardPolicy,
};
use common::*;
use rcgen::SanType;

fn cert_with_sans(sans: Vec<SanType>) -> EndEntityCert<'static> {
    let mut params = ee_params(&[]);
    params.subject_alt_names = sans;
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![],
        &params,
    );
    let der: &'static CertificateDer<'static> = Box::leak(Box::new(chain.ee_der()));
    EndEntityCert::try_from(der).unwrap()
}

fn dns_name(name: &str) -> DnsName<'static> {
    DnsName::try_from(name.to_owned()).unwrap()
}

fn identity(reference: ReferenceIdentifier) -> ServiceIdentity {
    ServiceIdentity::new(vec![reference]).unwrap()
}

fn hash<T: Hash>(value: &T) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn strict_ascii_dns_and_reference_normalization() {
    assert!(DnsName::try_from_ascii("xn--bcher-kva.example").is_ok());
    assert!(DnsName::try_from_ascii("bücher.example").is_err());
    assert!(DnsName::try_from_ascii("_service.example").is_err());
    assert!(DnsName::try_from_ascii("xn--invalid-.example").is_err());

    let lower = identity(ReferenceIdentifier::Dns(dns_name("example.com")));
    let upper = identity(ReferenceIdentifier::Dns(dns_name("EXAMPLE.COM.")));
    assert_eq!(lower, upper);
    assert_eq!(hash(&lower), hash(&upper));
    assert!(ServiceIdentity::new(vec![]).is_err());
    assert!(
        ServiceIdentity::new(
            (0..33)
                .map(|_| ReferenceIdentifier::Dns(dns_name("example.com")))
                .collect()
        )
        .is_err()
    );
}

#[test]
fn dns_wildcard_policy_and_dns_only_matching() {
    let cert = cert_with_sans(vec![
        SanType::DnsName("*.example.com".try_into().unwrap()),
        SanType::URI("https://example.com/".try_into().unwrap()),
        SanType::IpAddress("192.0.2.1".parse().unwrap()),
    ]);
    let reference = identity(ReferenceIdentifier::Dns(dns_name("www.example.com")));
    assert!(cert.verify_service_identity(&reference).is_ok());
    let denied = reference.with_wildcard_policy(WildcardPolicy::Deny);
    assert_eq!(
        cert.verify_service_identity(&denied),
        Err(Error::CertNotValidForName)
    );

    let no_dns = identity(ReferenceIdentifier::Dns(dns_name("example.com")));
    assert!(cert.verify_service_identity(&no_dns).is_err());
    let ip = identity(ReferenceIdentifier::Ip(
        "192.0.2.1".parse::<std::net::IpAddr>().unwrap().into(),
    ));
    assert!(cert.verify_service_identity(&ip).is_ok());
}

#[test]
fn uri_scheme_and_dns_host_are_both_required() {
    let cert = cert_with_sans(vec![SanType::URI(
        "HTTPS://user@example.com:8443/path".try_into().unwrap(),
    )]);
    let good = identity(ReferenceIdentifier::Uri(
        UriId::new("https", dns_name("EXAMPLE.COM.")).unwrap(),
    ));
    assert!(cert.verify_service_identity(&good).is_ok());

    let other_scheme = identity(ReferenceIdentifier::Uri(
        UriId::new("http", dns_name("example.com")).unwrap(),
    ));
    assert!(cert.verify_service_identity(&other_scheme).is_err());
    let other_host = identity(ReferenceIdentifier::Uri(
        UriId::new("https", dns_name("other.example")).unwrap(),
    ));
    assert!(cert.verify_service_identity(&other_host).is_err());
    assert!(UriId::try_from("https://192.0.2.1/").is_err());
    assert!(UriId::try_from("https://bücher.example/").is_err());
}

#[test]
fn srv_identifier_requires_explicit_service_type() {
    assert!(SrvId::try_from("_xmpp-client.example.com").is_ok());
    assert!(SrvId::try_from("example.com").is_err());
    assert!(SrvId::try_from("_bad_label.example.com").is_err());
}

#[test]
fn sip_uri_id_uses_the_host_instead_of_userinfo() {
    let cert = cert_with_sans(vec![SanType::URI(
        "sip:alice@EXAMPLE.COM;transport=tcp".try_into().unwrap(),
    )]);
    let reference = identity(ReferenceIdentifier::Uri(
        UriId::try_from("sip:bob@example.com").unwrap(),
    ));
    assert_eq!(
        cert.verify_service_identity(&reference),
        Ok(&reference.references()[0])
    );

    let wrong = identity(ReferenceIdentifier::Uri(
        UriId::try_from("sip:alice@wrong.example").unwrap(),
    ));
    assert_eq!(
        cert.verify_service_identity(&wrong),
        Err(Error::CertNotValidForName)
    );
}
