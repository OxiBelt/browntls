//! Server name matching and name constraints.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use browntls_pki::{CertificateDer, EndEntityCert, Error, ServerName, anchor_from_trusted_cert};
use common::*;
use rcgen::{
    CertificateParams, CertifiedIssuer, CidrSubnet, CustomExtension, DistinguishedName, DnType,
    GeneralSubtree, NameConstraints, SanType,
};

fn ee_with_sans(sans: Vec<SanType>) -> EndEntityCert<'static> {
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

fn dns(name: &str) -> SanType {
    SanType::DnsName(name.try_into().unwrap())
}

fn check(cert: &EndEntityCert<'_>, name: &str) -> Result<(), Error> {
    cert.verify_is_valid_for_subject_name(&ServerName::try_from(name).unwrap())
}

#[test]
fn dns_names() {
    let cert = ee_with_sans(vec![dns("example.com"), dns("*.wild.example.com")]);
    for ok in [
        "example.com",
        "EXAMPLE.COM",
        "example.com.",
        "a.wild.example.com",
        "A.Wild.Example.COM.",
        "a-b_c.wild.example.com",
    ] {
        assert_eq!(check(&cert, ok), Ok(()), "{ok}");
    }
    for bad in [
        "www.example.com",
        "wild.example.com",
        "a.b.wild.example.com",
        "example.org",
        "xample.com",
        "example.com.evil.net",
    ] {
        assert_eq!(check(&cert, bad), Err(Error::CertNotValidForName), "{bad}");
    }
}

#[test]
fn wildcard_edge_cases() {
    // A wildcard needs at least two labels after it, must be the whole
    // left-most label, and matches exactly one label.
    let cert = ee_with_sans(vec![
        dns("*.com"),
        dns("w*.example.net"),
        dns("*.*.example.org"),
    ]);
    for bad in ["foo.com", "www.example.net", "a.b.example.org"] {
        assert_eq!(check(&cert, bad), Err(Error::CertNotValidForName), "{bad}");
    }
    let cert = ee_with_sans(vec![dns("*.example.com")]);
    assert_eq!(check(&cert, "example.com"), Err(Error::CertNotValidForName));
    assert_eq!(check(&cert, "www.example.com"), Ok(()));
}

#[test]
fn ip_addresses() {
    let cert = ee_with_sans(vec![
        SanType::IpAddress("192.0.2.1".parse().unwrap()),
        SanType::IpAddress("2001:db8::1".parse().unwrap()),
        dns("example.com"),
    ]);
    assert_eq!(check(&cert, "192.0.2.1"), Ok(()));
    assert_eq!(check(&cert, "2001:db8::1"), Ok(()));
    assert_eq!(check(&cert, "2001:DB8:0:0:0:0:0:1"), Ok(()));
    assert_eq!(check(&cert, "192.0.2.2"), Err(Error::CertNotValidForName));
    assert_eq!(
        check(&cert, "::ffff:192.0.2.1"),
        Err(Error::CertNotValidForName)
    );
    assert_eq!(check(&cert, "example.com"), Ok(()));
}

#[test]
fn subject_common_name_is_never_used() {
    let mut params = ee_params(&[]);
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "example.com");
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![],
        &params,
    );
    let der = chain.ee_der();
    let cert = EndEntityCert::try_from(&der).unwrap();
    assert_eq!(check(&cert, "example.com"), Err(Error::CertNotValidForName));
    // Other SAN types do not help either.
    let cert = ee_with_sans(vec![SanType::Rfc822Name(
        "a@example.com".try_into().unwrap(),
    )]);
    assert_eq!(check(&cert, "example.com"), Err(Error::CertNotValidForName));
}

/// Builds `root (constraints) -> intermediate -> ee (sans)` and verifies it.
fn constrained(
    constraints: Option<NameConstraints>,
    intermediate_sans: Vec<SanType>,
    sans: Vec<SanType>,
) -> Result<(), Error> {
    let mut root = ca_params("root");
    root.name_constraints = constraints;
    let mut intermediate = ca_params("intermediate");
    intermediate.subject_alt_names = intermediate_sans;
    let mut ee = ee_params(&[]);
    ee.subject_alt_names = sans;
    Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        root,
        vec![intermediate],
        &ee,
    )
    .verify_at(NOW)
}

fn permitted(subtrees: Vec<GeneralSubtree>) -> Option<NameConstraints> {
    Some(NameConstraints {
        permitted_subtrees: subtrees,
        excluded_subtrees: vec![],
    })
}

fn excluded(subtrees: Vec<GeneralSubtree>) -> Option<NameConstraints> {
    Some(NameConstraints {
        permitted_subtrees: vec![],
        excluded_subtrees: subtrees,
    })
}

#[test]
fn dns_name_constraints() {
    let example = || GeneralSubtree::DnsName("example.com".to_string());
    let dot_example = || GeneralSubtree::DnsName(".example.com".to_string());
    let ok = |nc, sans| assert_eq!(constrained(nc, vec![], sans), Ok(()));
    let violation = |nc, sans| {
        assert_eq!(
            constrained(nc, vec![], sans),
            Err(Error::NameConstraintViolation)
        )
    };

    ok(None, vec![dns("anything.net")]);
    ok(
        permitted(vec![example()]),
        vec![dns("example.com"), dns("a.b.example.com")],
    );
    violation(permitted(vec![example()]), vec![dns("example.org")]);
    violation(permitted(vec![example()]), vec![dns("badexample.com")]);
    violation(
        permitted(vec![example()]),
        vec![dns("www.example.com"), dns("www.example.org")],
    );
    // Leading dot: subdomains only.
    ok(permitted(vec![dot_example()]), vec![dns("www.example.com")]);
    violation(permitted(vec![dot_example()]), vec![dns("example.com")]);
    // Excluded.
    violation(excluded(vec![example()]), vec![dns("www.example.com")]);
    ok(excluded(vec![example()]), vec![dns("example.org")]);
    ok(excluded(vec![dot_example()]), vec![dns("example.com")]);
    // Both: permitted example.com, excluded a subtree of it.
    let both = Some(NameConstraints {
        permitted_subtrees: vec![example()],
        excluded_subtrees: vec![GeneralSubtree::DnsName("internal.example.com".to_string())],
    });
    ok(both.clone(), vec![dns("www.example.com")]);
    violation(both, vec![dns("www.internal.example.com")]);
    // Several permitted subtrees: one match suffices.
    ok(
        permitted(vec![
            example(),
            GeneralSubtree::DnsName("example.org".to_string()),
        ]),
        vec![dns("www.example.org")],
    );
    // A constraint of a different name form does not apply to DNS names.
    ok(
        permitted(vec![GeneralSubtree::Rfc822Name("example.com".to_string())]),
        vec![dns("example.net")],
    );
    violation(
        permitted(vec![GeneralSubtree::Rfc822Name("example.com".to_string())]),
        vec![SanType::Rfc822Name("joe@example.com".try_into().unwrap())],
    );
}

#[test]
fn wildcard_sans_against_constraints() {
    let wildcard = || vec![dns("*.example.com")];
    assert_eq!(
        constrained(
            permitted(vec![GeneralSubtree::DnsName("example.com".to_string())]),
            vec![],
            wildcard()
        ),
        Ok(())
    );
    assert_eq!(
        constrained(
            permitted(vec![GeneralSubtree::DnsName("foo.example.com".to_string())]),
            vec![],
            wildcard()
        ),
        Err(Error::NameConstraintViolation)
    );
    assert_eq!(
        constrained(
            excluded(vec![GeneralSubtree::DnsName("example.com".to_string())]),
            vec![],
            wildcard()
        ),
        Err(Error::NameConstraintViolation)
    );
    assert_eq!(
        constrained(
            excluded(vec![GeneralSubtree::DnsName(
                "evil.example.com".to_string()
            )]),
            vec![],
            wildcard()
        ),
        Err(Error::NameConstraintViolation)
    );
    assert_eq!(
        constrained(
            excluded(vec![GeneralSubtree::DnsName(
                "evil.example.org".to_string()
            )]),
            vec![],
            wildcard()
        ),
        Ok(())
    );
}

#[test]
fn ip_address_constraints() {
    let v4 = |s: &str| SanType::IpAddress(s.parse().unwrap());
    let net = || GeneralSubtree::IpAddress(CidrSubnet::V4([12, 34, 56, 0], [255, 255, 255, 0]));
    assert_eq!(
        constrained(permitted(vec![net()]), vec![], vec![v4("12.34.56.78")]),
        Ok(())
    );
    assert_eq!(
        constrained(permitted(vec![net()]), vec![], vec![v4("12.34.57.78")]),
        Err(Error::NameConstraintViolation)
    );
    assert_eq!(
        constrained(excluded(vec![net()]), vec![], vec![v4("12.34.56.78")]),
        Err(Error::NameConstraintViolation)
    );
    assert_eq!(
        constrained(excluded(vec![net()]), vec![], vec![v4("12.34.57.78")]),
        Ok(())
    );
    // A non-contiguous mask is malformed.
    let sparse = GeneralSubtree::IpAddress(CidrSubnet::V4([12, 34, 56, 0], [255, 255, 0, 255]));
    assert_eq!(
        constrained(excluded(vec![sparse]), vec![], vec![v4("12.34.56.79")]),
        Err(Error::InvalidNetworkMaskConstraint)
    );
    // IPv6 and mixed families.
    let net6 = || {
        GeneralSubtree::IpAddress(CidrSubnet::from_v6_prefix(
            "2001:db8::".parse::<std::net::Ipv6Addr>().unwrap().octets(),
            32,
        ))
    };
    assert_eq!(
        constrained(permitted(vec![net6()]), vec![], vec![v4("2001:db8::1")]),
        Ok(())
    );
    assert_eq!(
        constrained(permitted(vec![net6()]), vec![], vec![v4("2001:db9::1")]),
        Err(Error::NameConstraintViolation)
    );
    // Permitted subtrees of one family still constrain the iPAddress form as
    // a whole: a v4 address matches no v6 subtree and is rejected.
    assert_eq!(
        constrained(permitted(vec![net6()]), vec![], vec![v4("12.34.56.78")]),
        Err(Error::NameConstraintViolation)
    );
    // Excluded subtrees of the other family never match.
    assert_eq!(
        constrained(excluded(vec![net6()]), vec![], vec![v4("12.34.56.78")]),
        Ok(())
    );
    assert_eq!(
        constrained(
            permitted(vec![net(), net6()]),
            vec![],
            vec![v4("12.34.56.78"), v4("2001:db8::1")]
        ),
        Ok(())
    );
    // IP constraints do not affect DNS names.
    assert_eq!(
        constrained(excluded(vec![net()]), vec![], vec![dns("example.com")]),
        Ok(())
    );
}

#[test]
fn directory_name_constraints_fail_closed() {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "XX");
    assert_eq!(
        constrained(
            permitted(vec![GeneralSubtree::DirectoryName(dn.clone())]),
            vec![],
            vec![dns("example.com")]
        ),
        Err(Error::NameConstraintViolation)
    );
    assert_eq!(
        constrained(
            excluded(vec![GeneralSubtree::DirectoryName(dn)]),
            vec![],
            vec![]
        ),
        Err(Error::NameConstraintViolation)
    );
}

#[test]
fn constraints_apply_to_every_subordinate_certificate() {
    // The root's constraints cover the intermediate's own SANs.
    assert_eq!(
        constrained(
            permitted(vec![GeneralSubtree::DnsName("example.com".to_string())]),
            vec![dns("ca.example.org")],
            vec![dns("www.example.com")]
        ),
        Err(Error::NameConstraintViolation)
    );
    // Constraints on an intermediate cover the end entity.
    let mut intermediate = ca_params("intermediate");
    intermediate.name_constraints =
        permitted(vec![GeneralSubtree::DnsName("example.com".to_string())]);
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![intermediate.clone()],
        &ee_params(&["www.example.org"]),
    );
    assert_eq!(chain.verify_at(NOW), Err(Error::NameConstraintViolation));
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![intermediate],
        &ee_params(&["www.example.com"]),
    );
    assert_eq!(chain.verify_at(NOW), Ok(()));
}

#[test]
fn malformed_name_constraints() {
    let nc_ext = |content: Vec<u8>| {
        let mut ext = CustomExtension::from_oid_content(&[2, 5, 29, 30], content);
        ext.set_criticality(true);
        ext
    };
    // Neither subtree list, an empty permitted list, and a subtree with a
    // minimum field are all malformed.
    for content in [
        b"\x30\x00".to_vec(),
        b"\x30\x02\xa0\x00".to_vec(),
        b"\x30\x14\xa0\x12\x30\x10\x82\x0bexample.com\x80\x01\x00".to_vec(),
    ] {
        let mut root = ca_params("root");
        root.custom_extensions.push(nc_ext(content.clone()));
        let root =
            CertifiedIssuer::self_signed(root, key_for(&rcgen::PKCS_ECDSA_P256_SHA256)).unwrap();
        let der: CertificateDer<'_> = root.der().to_vec().into();
        assert_eq!(
            anchor_from_trusted_cert(&der).err(),
            Some(Error::MalformedNameConstraint)
        );

        let mut intermediate = ca_params("intermediate");
        intermediate.custom_extensions.push(nc_ext(content));
        let chain = Chain::build(
            &rcgen::PKCS_ECDSA_P256_SHA256,
            ca_params("root"),
            vec![intermediate],
            &ee_params(&["example.com"]),
        );
        assert_eq!(chain.verify_at(NOW), Err(Error::MalformedNameConstraint));
    }
}

#[test]
fn name_constraint_comparison_budget() {
    // 500 SANs against 501 permitted subtrees exceeds 250 000 comparisons.
    let subtrees = (0..501)
        .map(|i| GeneralSubtree::DnsName(format!("permitted{i}.example")))
        .collect();
    let sans = (0..500)
        .map(|i| dns(&format!("host{i}.permitted0.example")))
        .collect();
    assert_eq!(
        constrained(permitted(subtrees), vec![], sans),
        Err(Error::MaximumNameConstraintComparisonsExceeded)
    );
    // Well within the budget: 100 SANs x 101 subtrees.
    let subtrees = (0..101)
        .map(|i| GeneralSubtree::DnsName(format!("permitted{i}.example")))
        .collect();
    let sans = (0..100)
        .map(|i| dns(&format!("host{i}.permitted0.example")))
        .collect();
    assert_eq!(constrained(permitted(subtrees), vec![], sans), Ok(()));
}

#[test]
fn reference_name_types() {
    let cert = ee_with_sans(vec![dns("example.com")]);
    let owned = ServerName::try_from("EXAMPLE.com".to_string()).unwrap();
    assert_eq!(cert.verify_is_valid_for_subject_name(&owned), Ok(()));
    assert_eq!(
        cert.verify_is_valid_for_subject_name(&ServerName::try_from(&b"example.com"[..]).unwrap()),
        Ok(())
    );
    let _ = CertificateParams::default();
}
