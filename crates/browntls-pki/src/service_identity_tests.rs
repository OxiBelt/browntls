use super::{DnsName, SrvId, WildcardPolicy, verify_dns, verify_srv};
use crate::name::service::uri_dns_components;

#[test]
fn dns_san_matching_is_ascii_and_policy_aware() {
    let reference = DnsName::try_from_ascii("www.example.com").unwrap();
    assert_eq!(
        verify_dns(
            &reference,
            Some(b"\x82\x0d*.example.com"),
            WildcardPolicy::Allow
        ),
        Ok(true)
    );
    assert_eq!(
        verify_dns(
            &reference,
            Some(b"\x82\x0d*.example.com"),
            WildcardPolicy::Deny
        ),
        Ok(false)
    );
    let san = b"\x82\x0fb\xc3\xbccher.example\x82\x0bexample.com";
    let ascii_reference = DnsName::try_from_ascii("example.com").unwrap();
    assert_eq!(
        verify_dns(&ascii_reference, Some(san), WildcardPolicy::Allow),
        Ok(true)
    );
}

#[test]
fn uri_host_normalization_is_bounded_and_syntax_limited() {
    let host = |uri| uri_dns_components(uri, false).map(|(_, host)| host);
    assert_eq!(
        host(b"https://%65XAMPLE.com/path").as_deref(),
        Some("eXAMPLE.com")
    );
    assert_eq!(
        host(b"https://example%2ecom/").as_deref(),
        Some("example.com")
    );
    assert!(host(b"https://example%40evil.com/").is_none());
    assert!(host(b"https://%c3%bc.example/").is_none());
    assert!(host(b"https://example.com:abc/").is_none());
    assert_eq!(
        host(b"https://example.com:65536/").as_deref(),
        Some("example.com")
    );
    assert_eq!(
        uri_dns_components(b"sip:user@example.com", true),
        Some(("sip", alloc::borrow::Cow::Borrowed("example.com")))
    );
    assert_eq!(
        uri_dns_components(
            b"SIP:user;with?chars:password@example.com;transport=tcp",
            true
        ),
        Some(("SIP", alloc::borrow::Cow::Borrowed("example.com")))
    );
    assert!(uri_dns_components(b"sip:@example.com", true).is_none());
    assert!(uri_dns_components(b"sip:user@wrong.example@example.com", true).is_none());
    assert!(uri_dns_components(b"sip:user:bad?pass@example.com", true).is_none());
    assert!(uri_dns_components(b"sip:example.com:5060;transport=tcp", true).is_some());
    assert!(uri_dns_components(b"sip:example.com:bad", true).is_none());
    assert!(uri_dns_components(&alloc::vec![b'a'; 65_536], false).is_none());
}

#[test]
fn srv_name_uses_service_and_dns_domain() {
    let srv =
        b"\xa0\x26\x06\x08\x2b\x06\x01\x05\x05\x07\x08\x07\xa0\x1a\x16\x18_xmpp-client.example.com";
    let reference = SrvId::try_from("_XMPP-client.EXAMPLE.COM").unwrap();
    assert!(verify_srv(&reference, Some(srv)));
    let wrong_service = SrvId::try_from("_imap.example.com").unwrap();
    assert!(!verify_srv(&wrong_service, Some(srv)));
    let wrong_domain = SrvId::try_from("_xmpp-client.other.example").unwrap();
    assert!(!verify_srv(&wrong_domain, Some(srv)));
}
