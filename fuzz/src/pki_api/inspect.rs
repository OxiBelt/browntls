//! Certificate inspection (`Cert`, its extensions and subject alternative
//! names) over the fixture certificates and certificates generated here
//! with every extension and name form the crate decodes, possibly
//! corrupted, against an independent reading of the DER.

use std::sync::OnceLock;

use browntls_pki::extensions::{
    DistributionPointName, KeyUsageBit, NameConstraints, oid as ext_oid,
};
use browntls_pki::{Cert, CertificateDer, EndEntityCert, GeneralName, Name, ServerName};

use super::chains::{corrupt, fixture_cert};
use super::{der, tlv, x500};
use crate::input::Input;
use crate::tls_config::verifiers::server_name;

/// Certificates generated once per process: a CA with name constraints,
/// CRL distribution points and identifiers; an end entity with every
/// subject alternative name, key usage and purpose rcgen writes; and one
/// with hand-written alternative names, distribution points and authority
/// key identifier covering the remaining forms.
pub(super) struct Rich {
    pub(super) ca: CertificateDer<'static>,
    pub(super) end_entities: [CertificateDer<'static>; 2],
}

/// 1.3.6.1.4.1.55555.1: a private extension and purpose.
const PRIVATE_ARCS: &[u64] = &[1, 3, 6, 1, 4, 1, 55555, 1];

fn rich_dn(cn: &str) -> rcgen::DistinguishedName {
    use rcgen::string::{BmpString, Ia5String, PrintableString, TeletexString, UniversalString};
    use rcgen::{DnType, DnValue};
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(
        DnType::CountryName,
        DnValue::PrintableString(PrintableString::try_from("FI").unwrap()),
    );
    dn.push(DnType::StateOrProvinceName, "Uusimaa é");
    dn.push(
        DnType::LocalityName,
        DnValue::UniversalString(UniversalString::try_from("Espoo").unwrap()),
    );
    dn.push(
        DnType::OrganizationName,
        DnValue::TeletexString(TeletexString::try_from("browntls").unwrap()),
    );
    dn.push(
        DnType::OrganizationalUnitName,
        DnValue::BmpString(BmpString::try_from("fuzz").unwrap()),
    );
    dn.push(
        DnType::CustomDnType(vec![0, 9, 2342, 19_200_300, 100, 1, 25]),
        DnValue::Ia5String(Ia5String::try_from("example").unwrap()),
    );
    dn.push(DnType::CommonName, cn);
    dn
}

fn generate() -> Rich {
    use rcgen::{
        BasicConstraints, CidrSubnet, CrlDistributionPoint, CustomExtension,
        ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, KeyUsagePurpose, OtherNameValue, SanType,
    };
    let ca_params = || {
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name = rich_dn("rich root");
        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        p.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let mut dir = rcgen::DistinguishedName::new();
        dir.push(rcgen::DnType::OrganizationName, "browntls");
        p.name_constraints = Some(rcgen::NameConstraints {
            permitted_subtrees: vec![
                GeneralSubtree::DnsName("example".into()),
                GeneralSubtree::IpAddress(CidrSubnet::V4([10, 0, 0, 0], [255, 0, 0, 0])),
                GeneralSubtree::DirectoryName(dir),
                GeneralSubtree::Rfc822Name("example".into()),
            ],
            excluded_subtrees: vec![
                GeneralSubtree::DnsName("bad.example".into()),
                GeneralSubtree::IpAddress(CidrSubnet::V6(
                    [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    [0xff, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                )),
            ],
        });
        p.crl_distribution_points = vec![CrlDistributionPoint {
            uris: vec![
                "http://crl.example/a.crl".into(),
                "ldap://crl.example/b".into(),
            ],
        }];
        p.use_authority_key_identifier_extension = true;
        p.custom_extensions = vec![CustomExtension::from_oid_content(
            PRIVATE_ARCS,
            vec![0x05, 0x00],
        )];
        p
    };
    let ca_key = rcgen::KeyPair::generate().expect("rich CA key");
    let ca = ca_params().self_signed(&ca_key).expect("rich CA");
    let issuer = rcgen::Issuer::new(ca_params(), ca_key);

    let dns = |s: &str| SanType::DnsName(s.try_into().unwrap());
    let mut ee = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ee.distinguished_name = rich_dn("rich end entity");
    ee.is_ca = IsCa::ExplicitNoCa;
    ee.subject_alt_names = vec![
        dns("localhost"),
        dns("*.wild.example"),
        dns("Mixed.Example"),
        dns("bad..example"),
        dns("*.example"),
        dns("absolute.example."),
        SanType::URI("https://example/p".try_into().unwrap()),
        SanType::IpAddress([10, 1, 2, 3].into()),
        SanType::IpAddress("2001:db8::1".parse().unwrap()),
        SanType::Rfc822Name("user@example".try_into().unwrap()),
        SanType::OtherName((
            vec![1, 3, 6, 1, 4, 1, 311, 20, 2, 3],
            OtherNameValue::Utf8String("upn@example".into()),
        )),
    ];
    ee.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::ContentCommitment,
        KeyUsagePurpose::KeyEncipherment,
        KeyUsagePurpose::DataEncipherment,
        KeyUsagePurpose::KeyAgreement,
        KeyUsagePurpose::EncipherOnly,
        KeyUsagePurpose::DecipherOnly,
    ];
    ee.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::CodeSigning,
        ExtendedKeyUsagePurpose::EmailProtection,
        ExtendedKeyUsagePurpose::TimeStamping,
        ExtendedKeyUsagePurpose::OcspSigning,
        ExtendedKeyUsagePurpose::Other(PRIVATE_ARCS.to_vec()),
    ];
    ee.use_authority_key_identifier_extension = true;
    let ee_key = rcgen::KeyPair::generate().expect("rich EE key");
    let ee1 = ee.signed_by(&ee_key, &issuer).expect("rich EE");

    // Hand-written: a directoryName with a multi-valued RDN, x400Address,
    // ediPartyName, registeredID, dNSNames; CRL distribution points with a
    // relative name, reasons and a CRL issuer; an authority key identifier
    // with all three fields.
    let dir = x500::encode(&[vec![
        (vec![0x55, 0x04, 0x03], 0x0c, b"multi".to_vec()),
        (vec![0x55, 0x04, 0x0a], 0x13, b"Org".to_vec()),
    ]]);
    let mut sans = der(0xa4, &der(0x30, &dir));
    sans.extend(der(0xa3, &[0x30, 0x00]));
    sans.extend(der(0xa5, &der(0xa1, &der(0x0c, b"party"))));
    sans.extend(der(0x88, &[0x2a, 0x03, 0x04]));
    sans.extend(der(0x82, b"x.example"));
    sans.extend(der(0x82, b"-bad.example"));
    sans.extend(der(0x86, b"urn:x"));
    let rdn = x500::encode_rdn(&[(vec![0x55, 0x04, 0x03], 0x0c, b"crl".to_vec())]);
    let mut relative = der(0xa0, &der(0xa1, &rdn));
    relative.extend(der(0x81, &[0x05, 0x60]));
    relative.extend(der(0xa2, &der(0x86, b"urn:issuer")));
    let mut points = der(0x30, &relative);
    points.extend(der(0x30, &der(0xa0, &der(0xa0, &der(0x86, b"urn:crl")))));
    let mut aki = der(0x80, &[1, 2, 3, 4]);
    aki.extend(der(0xa1, &der(0xa4, &der(0x30, &dir))));
    aki.extend(der(0x82, &[0x7b]));
    let mut ee = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ee.distinguished_name = rich_dn("hand-written");
    ee.custom_extensions = vec![
        CustomExtension::from_oid_content(&[2, 5, 29, 17], der(0x30, &sans)),
        CustomExtension::from_oid_content(&[2, 5, 29, 31], der(0x30, &points)),
        CustomExtension::from_oid_content(&[2, 5, 29, 35], der(0x30, &aki)),
    ];
    let ee2 = ee.signed_by(&ee_key, &issuer).expect("hand-written EE");

    let owned = |c: &rcgen::Certificate| CertificateDer::from(c.der().to_vec());
    Rich {
        ca: owned(&ca),
        end_entities: [owned(&ee1), owned(&ee2)],
    }
}

pub(super) fn rich() -> &'static Rich {
    static RICH: OnceLock<Rich> = OnceLock::new();
    RICH.get_or_init(generate)
}

/// The certificates [`cert_inspect_op`] chooses from: the six fixture
/// certificates, then the three generated here.
pub(super) const CERT_COUNT: usize = 9;

pub(super) fn cert(which: usize) -> &'static CertificateDer<'static> {
    match which {
        0..6 => fixture_cert(which),
        6 => &rich().ca,
        _ => &rich().end_entities[(which - 7) % 2],
    }
}

/// One extension as read by the model.
#[derive(Debug, PartialEq)]
struct ModelExt<'a> {
    id: &'a [u8],
    critical: bool,
    value: &'a [u8],
}

/// The extensions of a well-formed certificate, read with [`tlv`] alone.
fn model_extensions(cert: &[u8]) -> Vec<ModelExt<'_>> {
    let (_, cert, _) = tlv(cert).unwrap();
    let (_, mut tbs, _) = tlv(cert).unwrap();
    let mut out = Vec::new();
    while let Some((tag, contents, rest)) = tlv(tbs) {
        tbs = rest;
        if tag != 0xa3 {
            continue;
        }
        let (_, mut list, _) = tlv(contents).unwrap();
        while let Some((_, ext, rest)) = tlv(list) {
            list = rest;
            let (_, id, ext) = tlv(ext).unwrap();
            let (critical, ext) = match tlv(ext).unwrap() {
                (0x01, b, rest) => (b == [0xff], rest),
                _ => (false, ext),
            };
            let (_, value, _) = tlv(ext).unwrap();
            out.push(ModelExt {
                id,
                critical,
                value,
            });
        }
    }
    out
}

/// The elements of a `SEQUENCE` (or other constructed) contents.
fn elements(mut contents: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    while let Some((tag, value, rest)) = tlv(contents) {
        out.push((tag, value));
        contents = rest;
    }
    out
}

/// The tag and contents a `GeneralName` was read from.
fn general_name_tlv(name: &GeneralName<'_>) -> (u8, Vec<u8>) {
    match *name {
        GeneralName::Rfc822Name(v) => (0x81, v.to_vec()),
        GeneralName::DnsName(v) => (0x82, v.to_vec()),
        GeneralName::DirectoryName(v) => (0xa4, v.to_vec()),
        GeneralName::UniformResourceIdentifier(v) => (0x86, v.to_vec()),
        GeneralName::IpAddress(v) => (0x87, v.to_vec()),
        GeneralName::Other { tag, value } => {
            assert!(matches!(tag, 0 | 3 | 5 | 8));
            (if tag == 8 { 0x88 } else { 0xa0 | tag }, value.to_vec())
        }
        _ => unreachable!("every choice is covered"),
    }
}

/// Whether reference identifier `reference` matches presented identifier
/// `presented`, a valid one: equal ignoring ASCII case, or a wildcard
/// standing for one non-empty label. A reference may end with a dot.
fn dns_model(presented: &str, reference: &str) -> bool {
    let reference = reference.strip_suffix('.').unwrap_or(reference);
    match presented.strip_prefix("*.") {
        Some(rest) => reference
            .split_once('.')
            .is_some_and(|(label, tail)| !label.is_empty() && tail.eq_ignore_ascii_case(rest)),
        None => presented.eq_ignore_ascii_case(reference),
    }
}

/// A certificate, possibly corrupted: every accessor of `Cert`, and of its
/// extensions and names, against the model.
pub(super) fn cert_inspect_op(input: &mut Input<'_>) {
    let which = input.choose(CERT_COUNT);
    let mut bytes = cert(which).to_vec();
    let corrupted = input.bool();
    if corrupted {
        corrupt(input, &mut bytes);
    }
    let name = server_name(input);
    let lookup: &[u8] = match input.choose(4) {
        0 => ext_oid::SUBJECT_ALT_NAME,
        1 => ext_oid::DELEGATION_USAGE,
        2 => &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xb2, 0x03, 0x01],
        _ => input.short_field(),
    };
    let der = CertificateDer::from(bytes);
    let parsed = Cert::try_from(&der);
    let ee = EndEntityCert::try_from(&der);
    assert_eq!(parsed.is_ok(), ee.is_ok());
    let (Ok(cert), Ok(ee)) = (parsed, ee) else {
        assert!(corrupted);
        return;
    };
    assert_eq!(format!("{cert:?}"), format!("{:?}", *ee));
    assert_eq!(cert.der(), der);

    // Generic extensions against the model.
    let model = model_extensions(&der);
    let exts: Vec<_> = cert
        .extensions()
        .map(|e| ModelExt {
            id: e.extn_id(),
            critical: e.is_critical(),
            value: e.extn_value(),
        })
        .collect();
    assert_eq!(exts, model);
    let find = |id: &[u8]| model.iter().find(|e| e.id == id);
    let looked_up = cert.extension(lookup);
    assert_eq!(
        looked_up.map(|e| e.extn_value()),
        find(lookup).map(|e| e.value)
    );
    let _ = format!("{looked_up:?}");
    let value_of = |id: &[u8]| find(id).map(|e| tlv(e.value).unwrap().1);

    // basicConstraints.
    let bc = cert.basic_constraints();
    assert_eq!(bc.is_some(), find(ext_oid::BASIC_CONSTRAINTS).is_some());
    if let (Some(bc), Some(v)) = (bc, value_of(ext_oid::BASIC_CONSTRAINTS)) {
        let fields = elements(v);
        let ca = fields.iter().any(|(t, b)| *t == 0x01 && *b == [0xff]);
        let len = fields
            .iter()
            .find(|(t, _)| *t == 0x02)
            .map(|(_, b)| *b.last().unwrap());
        assert_eq!((bc.ca, bc.path_len_constraint), (ca, len));
    }
    // keyUsage.
    let ku = cert.key_usage();
    assert_eq!(ku.is_some(), find(ext_oid::KEY_USAGE).is_some());
    if let (Some(ku), Some(ext)) = (ku, find(ext_oid::KEY_USAGE)) {
        let (_, bits, _) = tlv(ext.value).unwrap();
        for (n, bit) in KeyUsageBit::ALL.into_iter().enumerate() {
            let set = bits
                .get(1 + n / 8)
                .is_some_and(|b| b >> (7 - n % 8) & 1 == 1);
            assert_eq!(ku.contains(bit), set, "{bit:?}");
        }
        let _ = format!("{ku:?}");
    }
    // extKeyUsage.
    let eku = cert.extended_key_usage();
    assert_eq!(
        eku.clone().map(|e| e.collect::<Vec<_>>()),
        value_of(ext_oid::EXT_KEY_USAGE).map(|v| elements(v).into_iter().map(|(_, o)| o).collect())
    );
    // Key identifiers.
    assert_eq!(
        cert.subject_key_identifier(),
        value_of(ext_oid::SUBJECT_KEY_IDENTIFIER)
    );
    let aki = cert.authority_key_identifier();
    assert_eq!(
        aki.is_some(),
        find(ext_oid::AUTHORITY_KEY_IDENTIFIER).is_some()
    );
    if let (Some(aki), Some(v)) = (aki, value_of(ext_oid::AUTHORITY_KEY_IDENTIFIER)) {
        let fields = elements(v);
        let field = |t: u8| fields.iter().find(|(tag, _)| *tag == t).map(|(_, b)| *b);
        assert_eq!(aki.key_identifier(), field(0x80));
        assert_eq!(aki.authority_cert_serial_number(), field(0x82));
        match (aki.authority_cert_issuer(), field(0xa1)) {
            (Some(names), Some(contents)) => check_general_names(names, contents),
            (None, None) => {}
            other => panic!("authorityCertIssuer {other:?}"),
        }
        let _ = format!("{aki:?}");
    }

    // subjectAltName.
    let san = value_of(ext_oid::SUBJECT_ALT_NAME);
    match (cert.subject_alt_names(), san) {
        (Some(names), Some(contents)) => check_general_names(names, contents),
        (None, None) => {}
        other => panic!("subjectAltName {other:?}"),
    }
    let dns: Vec<&str> = cert.valid_dns_names().collect();
    let uris: Vec<&str> = cert.valid_uri_names().collect();
    let san_entries = san.map(elements).unwrap_or_default();
    let model_uris: Vec<&str> = san_entries
        .iter()
        .filter(|(t, _)| *t == 0x86)
        .filter_map(|(_, v)| std::str::from_utf8(v).ok())
        .collect();
    assert_eq!(uris, model_uris);
    for valid in &dns {
        assert!(
            san_entries
                .iter()
                .any(|(t, v)| *t == 0x82 && *v == valid.as_bytes())
        );
        // Every valid name matches itself (a wildcard, one label).
        let reference = match valid.strip_prefix('*') {
            Some(rest) => format!("a{rest}"),
            None => (*valid).to_string(),
        };
        if let Ok(reference) = ServerName::try_from(reference.as_str()) {
            assert_eq!(
                ee.verify_is_valid_for_subject_name(&reference),
                Ok(()),
                "{valid}"
            );
        }
    }
    if let Some(name) = &name {
        let verified = ee.verify_is_valid_for_subject_name(name).is_ok();
        match name {
            ServerName::DnsName(reference) => {
                // Name verification never accepts what the valid names do
                // not predict.
                assert!(!verified || dns.iter().any(|v| dns_model(v, reference.as_ref())));
            }
            ServerName::IpAddress(ip) => {
                let listed = san_entries
                    .iter()
                    .any(|(t, v)| *t == 0x87 && *v == ip.as_bytes());
                assert_eq!(verified, listed);
            }
            _ => {}
        }
    }

    // cRLDistributionPoints.
    match (
        cert.crl_distribution_points(),
        value_of(ext_oid::CRL_DISTRIBUTION_POINTS),
    ) {
        (Some(points), Some(contents)) => {
            let count = elements(contents).len();
            let mut seen = 0;
            for point in points {
                seen += 1;
                let Ok(point) = point else {
                    break;
                };
                match point.distribution_point() {
                    Some(DistributionPointName::FullName(names)) => {
                        assert!(names.count() > 0);
                    }
                    Some(DistributionPointName::NameRelativeToCrlIssuer(rdn)) => {
                        assert!(rdn.iter().count() > 0);
                    }
                    None => assert!(point.crl_issuer().is_some()),
                }
                if let Some(issuer) = point.crl_issuer() {
                    assert!(issuer.clone().count() > 0 && issuer.clone().all(|n| n.is_ok()));
                }
                let _ = (point.reasons(), format!("{point:?}"));
            }
            assert!(seen <= count);
        }
        (None, None) => {}
        other => panic!("cRLDistributionPoints {other:?}"),
    }

    // nameConstraints, also parsed from the extension value.
    match (cert.name_constraints(), value_of(ext_oid::NAME_CONSTRAINTS)) {
        (Some(nc), Some(contents)) => {
            let again = NameConstraints::from_contents(contents).unwrap();
            assert_eq!(format!("{nc:?}"), format!("{again:?}"));
            check_name_constraints(&nc, contents);
        }
        (None, None) => {}
        other => panic!("nameConstraints {other:?}"),
    }
    // Fuzzed constraints: accepted ones read as the model does.
    let fuzzed = input.short_field();
    if let Ok(nc) = NameConstraints::from_contents(fuzzed) {
        check_name_constraints(&nc, fuzzed);
    }

    // Names: the issuer and subject round-trip; the signed parts are the
    // whole certificate's.
    for name in [cert.issuer(), cert.subject()] {
        x500::check_contents(name);
    }
    let signed = cert.signed_data();
    let (_, outer, _) = tlv(&der).unwrap();
    let (_, _, rest) = tlv(outer).unwrap();
    assert_eq!(signed.message().len() + rest.len(), outer.len());
    assert_eq!(
        (cert.serial(), cert.not_before(), cert.not_after()),
        (ee.serial(), ee.not_before(), ee.not_after())
    );
    assert_eq!(cert.subject_public_key_info(), ee.subject_public_key_info());
}

/// The subtrees of accepted name constraints against the model: the lists
/// present, and each subtree's base and nothing else.
fn check_name_constraints(nc: &NameConstraints<'_>, contents: &[u8]) {
    let lists = elements(contents);
    assert!(!lists.is_empty() && lists.len() <= 2);
    for (tag, subtrees) in [
        (0xa0, nc.permitted_subtrees()),
        (0xa1, nc.excluded_subtrees()),
    ] {
        let model = lists
            .iter()
            .find(|(t, _)| *t == tag)
            .map(|(_, l)| elements(l));
        let bases: Option<Vec<_>> = subtrees.map(|s| s.map(|b| general_name_tlv(&b)).collect());
        let model_bases: Option<Vec<_>> = model.map(|subtrees| {
            subtrees
                .into_iter()
                .map(|(t, subtree)| {
                    assert_eq!(t, 0x30);
                    let (tag, value, rest) = tlv(subtree).unwrap();
                    assert!(rest.is_empty(), "no minimum or maximum");
                    (tag, value.to_vec())
                })
                .collect()
        });
        assert!(model_bases.as_ref().is_none_or(|b| !b.is_empty()));
        assert_eq!(bases, model_bases);
    }
}

/// The entries of a `GeneralNames` iterator against the contents it reads.
fn check_general_names(names: browntls_pki::name::GeneralNames<'_>, contents: &[u8]) {
    let model = elements(contents);
    let mut read = 0;
    for (name, (tag, value)) in names.zip(&model) {
        let Ok(name) = name else {
            // A malformed entry ends the iteration (only where the parser
            // defers the check).
            break;
        };
        assert_eq!(general_name_tlv(&name), (*tag, value.to_vec()));
        if let GeneralName::DirectoryName(dir) = name {
            let parsed = Name::from_der(dir);
            match tlv(dir) {
                Some((0x30, contents, [])) => {
                    // The model does not check length minimality.
                    assert!(parsed.is_err() || Name::from_contents(contents).is_ok());
                    x500::check_contents(contents);
                }
                _ => assert!(parsed.is_err()),
            }
        }
        let _ = format!("{name:?}");
        read += 1;
    }
    assert!(read <= model.len());
}
