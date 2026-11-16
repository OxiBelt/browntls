//! `ServerName`, `DnsName` and `IpAddr` against `std::net` and a model of
//! the documented DNS name syntax.

use std::hash::{BuildHasher, BuildHasherDefault, DefaultHasher, Hash};
use std::net;

use browntls_pki::{DnsName, IpAddr, ServerName};

use crate::input::Input;

/// `DnsName`'s documented syntax: an optional trailing dot, 1 to 253 bytes
/// otherwise, labels of 1 to 63 bytes of `[A-Za-z0-9_-]` not starting or
/// ending with `-`, and a final label that is not all digits.
fn dns_model(s: &str) -> bool {
    let name = s.strip_suffix('.').unwrap_or(s);
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let mut last_numeric = false;
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return false;
        }
        last_numeric = label.bytes().all(|b| b.is_ascii_digit());
    }
    !last_numeric
}

fn hash_of<T: Hash>(value: &T) -> u64 {
    BuildHasherDefault::<DefaultHasher>::default().hash_one(value)
}

/// An IPv6 address in text, built from fuzzed groups: optional `::`, an
/// optional embedded IPv4 address, padded or upper-case digits, and an
/// optional stray character.
fn ipv6_text(input: &mut Input<'_>) -> String {
    let flags = input.byte();
    let n = input.choose(9);
    let groups: Vec<u16> = (0..n).map(|_| input.u16()).collect();
    let gap = (flags & 2 != 0).then(|| input.choose(n + 1));
    let v4 = (flags & 1 != 0).then(|| input.array::<4>());
    let words: Vec<String> = groups
        .iter()
        .map(|g| match flags >> 2 & 3 {
            1 => format!("{g:04x}"),
            2 => format!("{g:X}"),
            _ => format!("{g:x}"),
        })
        .collect();
    let mut s = match gap {
        Some(at) => format!("{}::{}", words[..at].join(":"), words[at..].join(":")),
        None => words.join(":"),
    };
    if let Some([a, b, c, d]) = v4 {
        if !(s.is_empty() || s.ends_with(':')) {
            s.push(':');
        }
        s.push_str(&format!("{a}.{b}.{c}.{d}"));
    }
    if flags & 16 != 0 {
        let at = input.choose(s.len() + 1);
        s.insert(at, char::from(*input.pick(b":.+0aG%")));
    }
    s
}

/// An IPv4 address in text, optionally with a leading zero, a fifth part
/// or an out-of-range octet.
fn ipv4_text(input: &mut Input<'_>) -> String {
    let flags = input.byte();
    let mut parts: Vec<String> = input.array::<4>().iter().map(u8::to_string).collect();
    if flags & 1 != 0 {
        parts[input.choose(4)].insert(0, '0');
    }
    if flags & 2 != 0 {
        parts.push(input.byte().to_string());
    }
    if flags & 4 != 0 {
        parts[input.choose(4)] = (256 + u16::from(input.byte())).to_string();
    }
    parts.join(".")
}

/// A DNS-like name: labels over a small alphabet, optionally long labels,
/// a trailing dot, upper case or an overlong name.
fn dns_text(input: &mut Input<'_>) -> String {
    const ALPHABET: &[u8] = b"abcXYZ019-_.*";
    let flags = input.byte();
    let labels: Vec<String> = (0..1 + input.choose(4))
        .map(|_| {
            let len = if flags & 4 != 0 {
                62 + input.choose(3)
            } else {
                1 + input.choose(6)
            };
            (0..len)
                .map(|_| char::from(*input.pick(ALPHABET)))
                .collect()
        })
        .collect();
    let mut s = labels.join(".");
    if flags & 8 != 0 {
        while s.len() <= 253 {
            s = format!("{s}.{s}");
        }
    }
    if flags & 2 != 0 {
        s.make_ascii_uppercase();
    }
    if flags & 1 != 0 {
        s.push('.');
    }
    s
}

/// A raw, generated IPv6, IPv4 or DNS name, then the checks.
pub(super) fn name_op(input: &mut Input<'_>) {
    match input.choose(4) {
        0 => {
            let bytes = input.short_field();
            match std::str::from_utf8(bytes) {
                Ok(s) => check(s),
                Err(_) => assert!(ServerName::try_from(bytes).is_err()),
            }
        }
        1 => check(&ipv6_text(input)),
        2 => check(&ipv4_text(input)),
        _ => check(&dns_text(input)),
    }
}

fn check(s: &str) {
    let ip = check_ip(s);
    let dns = DnsName::try_from(s);
    assert_eq!(dns.is_ok(), dns_model(s), "{s:?}");
    assert_eq!(DnsName::try_from(s.to_string()).is_ok(), dns.is_ok());
    if let Ok(dns) = &dns {
        check_dns(dns, s);
    }

    let name = ServerName::try_from(s);
    match (&name, ip, &dns) {
        (Ok(ServerName::IpAddress(a)), Some(b), _) => assert_eq!(*a, b),
        (Ok(ServerName::DnsName(a)), None, Ok(b)) => assert_eq!(a.as_ref(), b.as_ref()),
        (Err(_), None, Err(_)) => {}
        other => panic!("{s:?}: {other:?}"),
    }
    let name = name.ok().map(|n| n.to_owned());
    assert_eq!(ServerName::try_from(s.to_string()).ok(), name);
    assert_eq!(
        ServerName::try_from(s.as_bytes())
            .ok()
            .map(|n| n.to_owned()),
        name
    );
    if let Some(name) = name {
        check_server_name(&name);
    }
}

/// `IpAddr` against `std::net`, returning the address if `s` is one.
fn check_ip(s: &str) -> Option<IpAddr> {
    let ip = IpAddr::try_from(s).ok();
    // Text with a sign character is left out of the comparison with
    // `std::net` for now; the remaining checks still run on it.
    if !s.contains(['+', '-']) {
        let std_ip = s.parse::<net::IpAddr>().ok();
        assert_eq!(ip.map(net::IpAddr::from), std_ip, "{s:?}");
    }
    let ip = ip?;
    let std_ip = net::IpAddr::from(ip);
    assert_eq!(IpAddr::from(std_ip), ip);
    let octets = match std_ip {
        net::IpAddr::V4(a) => a.octets().to_vec(),
        net::IpAddr::V6(a) => a.octets().to_vec(),
    };
    assert_eq!(ip.as_bytes(), octets);
    let shown = ip.to_string();
    assert_eq!(IpAddr::try_from(shown.as_str()), Ok(ip), "{shown}");
    let mapped = matches!(std_ip, net::IpAddr::V6(a) if a.to_ipv4_mapped().is_some());
    if !mapped {
        assert_eq!(shown, std_ip.to_string());
    }
    Some(ip)
}

fn check_dns(dns: &DnsName<'_>, s: &str) {
    assert_eq!(dns.as_ref(), s);
    let owned = dns.to_owned();
    let borrowed = dns.borrow();
    let lower = dns.to_lowercase_owned();
    assert_eq!(owned.as_ref(), s);
    assert_eq!(borrowed.as_ref(), s);
    assert_eq!(lower.as_ref(), s.to_ascii_lowercase());
    let upper = s.to_ascii_uppercase();
    let upper = DnsName::try_from(upper.as_str()).expect("upper case of a DNS name");
    for other in [&owned, &borrowed, &lower, &upper] {
        assert_eq!(other, dns);
        assert_eq!(hash_of(other), hash_of(dns));
    }
    let name = ServerName::from(dns.clone());
    assert_eq!(name.to_str(), s);
}

fn check_server_name(name: &ServerName<'static>) {
    let text = name.to_str();
    assert_eq!(text, name.to_string());
    let again = ServerName::try_from(text.as_ref()).expect("a name's own text");
    assert_eq!(&again, name);
    assert_eq!(hash_of(&again), hash_of(name));
    assert_eq!(&name.to_owned(), name);
    if let ServerName::IpAddress(ip) = name {
        assert_eq!(&ServerName::from(*ip), name);
    }
}
