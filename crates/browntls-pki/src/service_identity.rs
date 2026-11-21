//! RFC 9525 service identity reference identifiers and certificate matching.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::hash::{Hash, Hasher};

use fluent_uri::component::Scheme;

use crate::error::Error;
use crate::name::{self, GeneralName, GeneralNames};
use crate::{DnsName, EndEntityCert, IpAddr};

pub(crate) use crate::name::service::valid_srv_service;

const MAX_REFERENCES: usize = 32;

/// A reference identifier supplied by the application for a TLS service.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ReferenceIdentifier {
    /// A DNS-ID, compared with `dNSName` subject alternative names.
    Dns(DnsName<'static>),
    /// An IP-ID, compared with `iPAddress` subject alternative names.
    Ip(IpAddr),
    /// A URI-ID, matched by scheme and DNS host.
    Uri(UriId),
    /// An SRV-ID, matched by service name and DNS domain.
    Srv(SrvId),
}

impl PartialEq for ReferenceIdentifier {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Dns(a), Self::Dns(b)) => dns_eq(a.as_ref(), b.as_ref()),
            (Self::Ip(a), Self::Ip(b)) => a == b,
            (Self::Uri(a), Self::Uri(b)) => a == b,
            (Self::Srv(a), Self::Srv(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for ReferenceIdentifier {}

impl Hash for ReferenceIdentifier {
    fn hash<H: Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Self::Dns(dns) => hash_dns(dns.as_ref(), state),
            Self::Ip(ip) => ip.hash(state),
            Self::Uri(uri) => uri.hash(state),
            Self::Srv(srv) => srv.hash(state),
        }
    }
}

/// URI-ID scheme and DNS host for RFC 9525 service identity matching.
///
/// Protocols can specify a narrower URI certificate profile. For example,
/// RFC 5922 excludes SIP certificate URIs that contain a user part.
#[derive(Clone, Debug)]
pub struct UriId {
    scheme: String,
    domain: DnsName<'static>,
}

impl UriId {
    /// Creates a URI-ID from a URI scheme and DNS domain.
    pub fn new(scheme: &str, domain: DnsName<'_>) -> Result<Self, InvalidServiceIdentity> {
        let scheme = Scheme::new(scheme).ok_or(InvalidServiceIdentity)?;
        let domain = strict_owned_domain(domain.as_ref())?;
        Ok(Self {
            scheme: scheme.as_str().to_ascii_lowercase(),
            domain,
        })
    }

    /// Returns the normalized URI scheme.
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Returns the normalized DNS domain.
    #[must_use]
    pub fn domain(&self) -> &DnsName<'static> {
        &self.domain
    }
}

impl PartialEq for UriId {
    fn eq(&self, other: &Self) -> bool {
        self.scheme.eq_ignore_ascii_case(&other.scheme)
            && dns_eq(self.domain.as_ref(), other.domain.as_ref())
    }
}

impl Eq for UriId {}

impl Hash for UriId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.scheme.to_ascii_lowercase().hash(state);
        hash_dns(self.domain.as_ref(), state);
    }
}

/// Parses a serialized ASCII URI-ID.
///
/// Absolute URIs with an authority require a DNS reg-name host. `sip:` and
/// `sips:` also accept the deliberately narrow bare form `scheme:host[:port]`;
/// userinfo, parameters, queries, fragments, and routing syntax are rejected.
impl TryFrom<&str> for UriId {
    type Error = InvalidServiceIdentity;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let (scheme, host) = name::service::uri_dns_components(value.as_bytes(), true)
            .ok_or(InvalidServiceIdentity)?;
        Self::new(
            scheme,
            DnsName::try_from_ascii(&host).map_err(|_| InvalidServiceIdentity)?,
        )
    }
}

/// SRV-ID components used for service identity matching.
#[derive(Clone, Debug)]
pub struct SrvId {
    service: String,
    domain: DnsName<'static>,
}

impl SrvId {
    /// Creates an SRV-ID from its underscore-prefixed service and DNS domain.
    pub fn new(service: &str, domain: DnsName<'_>) -> Result<Self, InvalidServiceIdentity> {
        if !valid_srv_service(service) {
            return Err(InvalidServiceIdentity);
        }
        Ok(Self {
            service: service.to_ascii_lowercase(),
            domain: strict_owned_domain(domain.as_ref())?,
        })
    }

    /// Returns the normalized underscore-prefixed service label.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Returns the normalized DNS domain.
    #[must_use]
    pub fn domain(&self) -> &DnsName<'static> {
        &self.domain
    }
}

impl PartialEq for SrvId {
    fn eq(&self, other: &Self) -> bool {
        self.service.eq_ignore_ascii_case(&other.service)
            && dns_eq(self.domain.as_ref(), other.domain.as_ref())
    }
}

impl Eq for SrvId {}

impl Hash for SrvId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.service.to_ascii_lowercase().hash(state);
        hash_dns(self.domain.as_ref(), state);
    }
}

impl TryFrom<&str> for SrvId {
    type Error = InvalidServiceIdentity;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let (service, domain) = value.split_once('.').ok_or(InvalidServiceIdentity)?;
        if domain.ends_with('.') {
            return Err(InvalidServiceIdentity);
        }
        Self::new(
            service,
            DnsName::try_from_ascii(domain).map_err(|_| InvalidServiceIdentity)?,
        )
    }
}

/// Policy for wildcard labels in presented DNS identifiers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum WildcardPolicy {
    /// Accept a complete left-most wildcard label that matches one DNS label.
    #[default]
    Allow,
    /// Ignore wildcard DNS identifiers.
    Deny,
}

/// An ordered set of 1 to 32 acceptable reference identifiers.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ServiceIdentity {
    references: Vec<ReferenceIdentifier>,
    wildcard_policy: WildcardPolicy,
}

impl ServiceIdentity {
    /// Creates an identity from 1 to 32 ordered reference identifiers.
    pub fn new(references: Vec<ReferenceIdentifier>) -> Result<Self, InvalidServiceIdentity> {
        if references.is_empty() || references.len() > MAX_REFERENCES {
            return Err(InvalidServiceIdentity);
        }
        let mut normalized = Vec::with_capacity(references.len());
        for reference in references {
            normalized.push(match reference {
                ReferenceIdentifier::Dns(dns) => {
                    ReferenceIdentifier::Dns(strict_owned_domain(dns.as_ref())?)
                }
                ReferenceIdentifier::Ip(ip) => ReferenceIdentifier::Ip(ip),
                ReferenceIdentifier::Uri(uri) => ReferenceIdentifier::Uri(uri),
                ReferenceIdentifier::Srv(srv) => ReferenceIdentifier::Srv(srv),
            });
        }
        Ok(Self {
            references: normalized,
            wildcard_policy: WildcardPolicy::Allow,
        })
    }

    /// Returns reference identifiers in caller-supplied preference order.
    #[must_use]
    pub fn references(&self) -> &[ReferenceIdentifier] {
        &self.references
    }

    /// Sets whether wildcard DNS identifiers can satisfy a reference.
    #[must_use]
    pub fn with_wildcard_policy(mut self, policy: WildcardPolicy) -> Self {
        self.wildcard_policy = policy;
        self
    }
}

/// Error returned for invalid or empty service identity input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidServiceIdentity;

impl fmt::Display for InvalidServiceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid service identity")
    }
}

impl core::error::Error for InvalidServiceIdentity {}

impl EndEntityCert<'_> {
    /// Verifies this certificate against any reference in `identity`, in order.
    ///
    /// DNS names are matched only against DNS SANs, IP addresses only against
    /// IP SANs, URI IDs by case-insensitive scheme plus DNS host, and SRV IDs
    /// against the SRVName `otherName`. The certificate subject is never used.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CertNotValidForName`] when none of the references
    /// matches a presented identifier.
    pub fn verify_service_identity<'i>(
        &self,
        identity: &'i ServiceIdentity,
    ) -> Result<&'i ReferenceIdentifier, Error> {
        let san = self.inner.subject_alt_name;
        for reference in &identity.references {
            let matched = match reference {
                ReferenceIdentifier::Dns(dns) => verify_dns(dns, san, identity.wildcard_policy)?,
                ReferenceIdentifier::Ip(ip) => name::verify_ip_address(ip, san).is_ok(),
                ReferenceIdentifier::Uri(uri) => verify_uri(uri, san),
                ReferenceIdentifier::Srv(srv) => verify_srv(srv, san),
            };
            if matched {
                return Ok(reference);
            }
        }
        Err(Error::CertNotValidForName)
    }
}

fn verify_dns(
    reference: &DnsName<'_>,
    san: Option<&[u8]>,
    wildcard_policy: WildcardPolicy,
) -> Result<bool, Error> {
    match name::dns::verify_dns_name_with_wildcards(
        reference,
        san,
        wildcard_policy == WildcardPolicy::Allow,
    ) {
        Ok(()) => Ok(true),
        Err(Error::CertNotValidForName) => Ok(false),
        Err(error) => Err(error),
    }
}

fn verify_uri(reference: &UriId, san: Option<&[u8]>) -> bool {
    for entry in GeneralNames::new(san) {
        let Ok(GeneralName::UniformResourceIdentifier(presented)) = entry else {
            continue;
        };
        let Some((scheme, domain)) = name::service::uri_dns_components(presented, true) else {
            continue;
        };
        if scheme.eq_ignore_ascii_case(&reference.scheme)
            && !domain.ends_with('.')
            && dns_eq(&domain, reference.domain.as_ref())
        {
            return true;
        }
    }
    false
}

fn verify_srv(reference: &SrvId, san: Option<&[u8]>) -> bool {
    for entry in GeneralNames::new(san) {
        let Ok(GeneralName::Other { tag: 0, value }) = entry else {
            continue;
        };
        let Ok(Some(value)) = name::service::srv_name_value(value) else {
            continue;
        };
        let Ok(text) = core::str::from_utf8(value) else {
            continue;
        };
        let Some((service, domain)) = text.split_once('.') else {
            continue;
        };
        if service.eq_ignore_ascii_case(reference.service.as_str())
            && !domain.ends_with('.')
            && domain.eq_ignore_ascii_case(reference.domain.as_ref())
        {
            return true;
        }
    }
    false
}

fn strict_owned_domain(domain: &str) -> Result<DnsName<'static>, InvalidServiceIdentity> {
    let relative = domain.strip_suffix('.').unwrap_or(domain);
    let normalized = relative.to_ascii_lowercase();
    DnsName::try_from(normalized).map_err(|_| InvalidServiceIdentity)
}

fn dns_eq(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

fn hash_dns<H: Hasher>(dns: &str, state: &mut H) {
    dns.trim_end_matches('.').to_ascii_lowercase().hash(state);
}

#[cfg(test)]
#[path = "service_identity_tests.rs"]
mod tests;
