//! TLS server names: DNS names (RFC 1035 / RFC 5890 A-labels) and IP addresses.

use alloc::borrow::Cow;
use alloc::string::String;
use core::fmt;

/// The name a TLS client uses to identify the server.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ServerName<'a> {
    /// A DNS name; sent in the SNI extension and matched against `dNSName`
    /// subject alternative names.
    DnsName(DnsName<'a>),
    /// An IP address; not sent in SNI, matched against `iPAddress` SANs.
    IpAddress(IpAddr),
}

impl ServerName<'_> {
    /// Converts into an owned value with a `'static` lifetime.
    #[must_use]
    pub fn to_owned(&self) -> ServerName<'static> {
        match self {
            Self::DnsName(d) => ServerName::DnsName(d.to_owned()),
            Self::IpAddress(ip) => ServerName::IpAddress(*ip),
        }
    }

    /// Returns a string form of the name.
    #[must_use]
    pub fn to_str(&self) -> Cow<'_, str> {
        match self {
            Self::DnsName(d) => Cow::Borrowed(d.as_ref()),
            Self::IpAddress(ip) => Cow::Owned(alloc::format!("{ip}")),
        }
    }
}

impl fmt::Display for ServerName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DnsName(d) => f.write_str(d.as_ref()),
            Self::IpAddress(ip) => write!(f, "{ip}"),
        }
    }
}

/// Error for strings that are neither valid DNS names nor IP addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidDnsNameError;

impl fmt::Display for InvalidDnsNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid DNS name")
    }
}

impl core::error::Error for InvalidDnsNameError {}

impl<'a> TryFrom<&'a str> for ServerName<'a> {
    type Error = InvalidDnsNameError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        if let Ok(ip) = IpAddr::try_from(s) {
            return Ok(Self::IpAddress(ip));
        }
        DnsName::try_from(s).map(Self::DnsName)
    }
}

impl TryFrom<String> for ServerName<'static> {
    type Error = InvalidDnsNameError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if let Ok(ip) = IpAddr::try_from(s.as_str()) {
            return Ok(Self::IpAddress(ip));
        }
        DnsName::try_from(s).map(Self::DnsName)
    }
}

impl<'a> TryFrom<&'a [u8]> for ServerName<'a> {
    type Error = InvalidDnsNameError;

    fn try_from(b: &'a [u8]) -> Result<Self, Self::Error> {
        core::str::from_utf8(b)
            .map_err(|_| InvalidDnsNameError)
            .and_then(Self::try_from)
    }
}

impl From<IpAddr> for ServerName<'_> {
    fn from(ip: IpAddr) -> Self {
        Self::IpAddress(ip)
    }
}

impl<'a> From<DnsName<'a>> for ServerName<'a> {
    fn from(d: DnsName<'a>) -> Self {
        Self::DnsName(d)
    }
}

/// A syntactically valid DNS name in A-label (ASCII) form.
///
/// Validation follows RFC 1035 label syntax relaxed to permit underscores (as
/// seen in practice), with these rules: total length 1..=253 (an optional
/// trailing dot is accepted and preserved), labels 1..=63 bytes of
/// `[A-Za-z0-9_-]` not starting or ending with `-`, and the final label not
/// entirely numeric (so dotted-quad strings are never DNS names). Comparison
/// is ASCII case-insensitive.
#[derive(Clone, Debug)]
pub struct DnsName<'a>(Cow<'a, str>);

impl DnsName<'_> {
    /// Converts into an owned value with a `'static` lifetime.
    #[must_use]
    pub fn to_owned(&self) -> DnsName<'static> {
        DnsName(Cow::Owned(String::from(self.0.as_ref())))
    }

    /// Returns the name in lower case.
    #[must_use]
    pub fn to_lowercase_owned(&self) -> DnsName<'static> {
        DnsName(Cow::Owned(self.0.to_ascii_lowercase()))
    }

    /// Borrows the name.
    #[must_use]
    pub fn borrow(&self) -> DnsName<'_> {
        DnsName(Cow::Borrowed(self.0.as_ref()))
    }
}

impl AsRef<str> for DnsName<'_> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq for DnsName<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for DnsName<'_> {}

impl core::hash::Hash for DnsName<'_> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        for b in self.0.bytes() {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}

impl<'a> TryFrom<&'a str> for DnsName<'a> {
    type Error = InvalidDnsNameError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        validate_dns_name(s.as_bytes())?;
        Ok(Self(Cow::Borrowed(s)))
    }
}

impl TryFrom<String> for DnsName<'static> {
    type Error = InvalidDnsNameError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        validate_dns_name(s.as_bytes())?;
        Ok(Self(Cow::Owned(s)))
    }
}

fn validate_dns_name(name: &[u8]) -> Result<(), InvalidDnsNameError> {
    let name = name.strip_suffix(b".").unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return Err(InvalidDnsNameError);
    }
    let mut last_all_numeric = false;
    for label in name.split(|&b| b == b'.') {
        if label.is_empty() || label.len() > 63 {
            return Err(InvalidDnsNameError);
        }
        if label[0] == b'-' || label[label.len() - 1] == b'-' {
            return Err(InvalidDnsNameError);
        }
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        {
            return Err(InvalidDnsNameError);
        }
        last_all_numeric = label.iter().all(u8::is_ascii_digit);
    }
    if last_all_numeric {
        return Err(InvalidDnsNameError);
    }
    Ok(())
}

/// An IPv4 or IPv6 address (no dependency on `std::net`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpAddr {
    /// IPv4.
    V4([u8; 4]),
    /// IPv6.
    V6([u8; 16]),
}

impl IpAddr {
    /// Returns the address octets in network byte order.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::V4(a) => a,
            Self::V6(a) => a,
        }
    }
}

/// Error for strings that are not IP addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddrParseError;

impl TryFrom<&str> for IpAddr {
    type Error = AddrParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if let Some(v4) = parse_v4(s) {
            return Ok(Self::V4(v4));
        }
        parse_v6(s).map(Self::V6).ok_or(AddrParseError)
    }
}

fn parse_v4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = s.split('.');
    for o in &mut out {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // Reject leading zeros (ambiguous octal notation).
        if p.len() > 1 && p.starts_with('0') {
            return None;
        }
        *o = p.parse::<u8>().ok()?;
    }
    parts.next().is_none().then_some(out)
}

fn parse_v6(s: &str) -> Option<[u8; 16]> {
    let (head, tail) = match s.find("::") {
        Some(i) => (&s[..i], Some(&s[i + 2..])),
        None => (s, None),
    };
    let mut groups = [0u16; 8];
    let mut n_head = 0usize;
    let mut v4_tail: Option<[u8; 4]> = None;

    let parse_groups = |part: &str, out: &mut [u16], v4: &mut Option<[u8; 4]>| -> Option<usize> {
        if part.is_empty() {
            return Some(0);
        }
        let mut n = 0usize;
        let pieces: alloc::vec::Vec<&str> = part.split(':').collect();
        for (i, g) in pieces.iter().enumerate() {
            if i == pieces.len() - 1 && g.contains('.') {
                *v4 = Some(parse_v4(g)?);
                if n + 2 > out.len() {
                    return None;
                }
                return Some(n + 2);
            }
            if g.is_empty() || g.len() > 4 || n >= out.len() {
                return None;
            }
            out[n] = u16::from_str_radix(g, 16).ok()?;
            n += 1;
        }
        Some(n)
    };

    match tail {
        None => {
            let n = parse_groups(head, &mut groups, &mut v4_tail)?;
            if n != 8 {
                return None;
            }
        }
        Some(tail) => {
            if tail.contains("::") {
                return None;
            }
            let mut tmp_v4 = None;
            n_head = parse_groups(head, &mut groups, &mut tmp_v4)?;
            if tmp_v4.is_some() {
                return None; // embedded IPv4 only allowed at the end
            }
            let mut tail_groups = [0u16; 8];
            let n_tail = parse_groups(tail, &mut tail_groups, &mut v4_tail)?;
            if n_head + n_tail > 7 {
                return None;
            }
            let v4_groups = usize::from(v4_tail.is_some()) * 2;
            let words = n_tail - v4_groups;
            groups[8 - n_tail..8 - v4_groups].copy_from_slice(&tail_groups[..words]);
        }
    }
    let mut out = [0u8; 16];
    for (i, g) in groups.iter().enumerate() {
        out[2 * i..2 * i + 2].copy_from_slice(&g.to_be_bytes());
    }
    if let Some(v4) = v4_tail {
        out[12..].copy_from_slice(&v4);
    }
    let _ = n_head;
    Some(out)
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(a) => write!(f, "{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
            Self::V6(a) => {
                // RFC 5952 canonical form.
                let mut g = [0u16; 8];
                for (i, w) in g.iter_mut().enumerate() {
                    *w = u16::from_be_bytes([a[2 * i], a[2 * i + 1]]);
                }
                let (mut best_start, mut best_len) = (8usize, 0usize);
                let mut i = 0;
                while i < 8 {
                    if g[i] == 0 {
                        let start = i;
                        while i < 8 && g[i] == 0 {
                            i += 1;
                        }
                        if i - start > best_len && i - start >= 2 {
                            best_start = start;
                            best_len = i - start;
                        }
                    } else {
                        i += 1;
                    }
                }
                let mut i = 0;
                while i < 8 {
                    if i == best_start {
                        f.write_str("::")?;
                        i += best_len;
                        continue;
                    }
                    if i > 0 && i != best_start + best_len {
                        f.write_str(":")?;
                    }
                    write!(f, "{:x}", g[i])?;
                    i += 1;
                }
                Ok(())
            }
        }
    }
}

#[cfg(feature = "std")]
impl From<std::net::IpAddr> for IpAddr {
    fn from(ip: std::net::IpAddr) -> Self {
        match ip {
            std::net::IpAddr::V4(v4) => Self::V4(v4.octets()),
            std::net::IpAddr::V6(v6) => Self::V6(v6.octets()),
        }
    }
}

#[cfg(feature = "std")]
impl From<IpAddr> for std::net::IpAddr {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(a) => Self::V4(a.into()),
            IpAddr::V6(a) => Self::V6(a.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn dns_names() {
        for ok in [
            "example.com",
            "a",
            "EXAMPLE.com.",
            "_srv.x-y.example",
            "xn--bcher-kva.de",
        ] {
            assert!(DnsName::try_from(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            ".",
            "-a.com",
            "a-.com",
            "a..com",
            "1.2.3.4",
            "exa mple.com",
            "*.example.com",
        ] {
            assert!(DnsName::try_from(bad).is_err(), "{bad}");
        }
        assert_eq!(
            DnsName::try_from("Example.COM").unwrap(),
            DnsName::try_from("example.com").unwrap()
        );
    }

    #[test]
    fn ip_addresses() {
        assert_eq!(
            IpAddr::try_from("192.0.2.1"),
            Ok(IpAddr::V4([192, 0, 2, 1]))
        );
        assert!(IpAddr::try_from("192.0.2.01").is_err());
        assert!(IpAddr::try_from("256.0.0.1").is_err());
        let v6 = IpAddr::try_from("2001:db8::1").unwrap();
        assert_eq!(v6.to_string(), "2001:db8::1");
        assert_eq!(IpAddr::try_from("::").unwrap().to_string(), "::");
        assert_eq!(IpAddr::try_from("::1").unwrap().to_string(), "::1");
        assert_eq!(
            IpAddr::try_from("::ffff:192.0.2.1").unwrap().as_bytes(),
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1]
        );
        assert_eq!(
            IpAddr::try_from("1:2:3:4:5:6:7:8").unwrap().to_string(),
            "1:2:3:4:5:6:7:8"
        );
        assert!(IpAddr::try_from("1:2:3:4:5:6:7:8:9").is_err());
        assert!(IpAddr::try_from("1::2::3").is_err());
        assert!(IpAddr::try_from("12345::").is_err());
        #[cfg(feature = "std")]
        for s in ["2001:db8::", "fe80::1:2", "1:0:0:2::3", "::ffff:1.2.3.4"] {
            let ours = IpAddr::try_from(s).unwrap();
            let std: std::net::IpAddr = s.parse().unwrap();
            assert_eq!(ours, IpAddr::from(std), "{s}");
        }
    }

    #[test]
    fn server_name() {
        assert!(matches!(
            ServerName::try_from("10.0.0.1"),
            Ok(ServerName::IpAddress(_))
        ));
        assert!(matches!(
            ServerName::try_from("example.com"),
            Ok(ServerName::DnsName(_))
        ));
        assert!(ServerName::try_from("not a name").is_err());
    }
}
