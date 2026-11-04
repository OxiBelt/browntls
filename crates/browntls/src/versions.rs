//! Supported protocol versions.

use core::fmt;

use crate::enums::ProtocolVersion;

/// A TLS protocol version supported by this library.
#[non_exhaustive]
#[derive(Eq, PartialEq)]
pub struct SupportedProtocolVersion {
    /// The TLS enumeration naming this version.
    pub version: ProtocolVersion,
}

impl fmt::Debug for SupportedProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.version.fmt(f)
    }
}

/// TLS 1.2.
#[cfg(feature = "tls12")]
pub static TLS12: SupportedProtocolVersion = SupportedProtocolVersion {
    version: ProtocolVersion::TLSv1_2,
};

/// TLS 1.3.
pub static TLS13: SupportedProtocolVersion = SupportedProtocolVersion {
    version: ProtocolVersion::TLSv1_3,
};

/// Every version this library supports, in preference order.
pub static ALL_VERSIONS: &[&SupportedProtocolVersion] = &[
    &TLS13,
    #[cfg(feature = "tls12")]
    &TLS12,
];

/// The versions enabled by default.
pub static DEFAULT_VERSIONS: &[&SupportedProtocolVersion] = ALL_VERSIONS;

/// The versions a configuration enables.
#[derive(Clone, Copy)]
pub(crate) struct EnabledVersions {
    #[cfg(feature = "tls12")]
    tls12: Option<&'static SupportedProtocolVersion>,
    tls13: Option<&'static SupportedProtocolVersion>,
}

impl fmt::Debug for EnabledVersions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        #[cfg(feature = "tls12")]
        if let Some(v) = self.tls12 {
            list.entry(v);
        }
        if let Some(v) = self.tls13 {
            list.entry(v);
        }
        list.finish()
    }
}

impl EnabledVersions {
    pub(crate) fn new(versions: &[&'static SupportedProtocolVersion]) -> Self {
        let mut ev = Self {
            #[cfg(feature = "tls12")]
            tls12: None,
            tls13: None,
        };
        for v in versions {
            match v.version {
                #[cfg(feature = "tls12")]
                ProtocolVersion::TLSv1_2 => ev.tls12 = Some(v),
                ProtocolVersion::TLSv1_3 => ev.tls13 = Some(v),
                _ => {}
            }
        }
        ev
    }

    pub(crate) fn contains(&self, version: ProtocolVersion) -> bool {
        match version {
            #[cfg(feature = "tls12")]
            ProtocolVersion::TLSv1_2 => self.tls12.is_some(),
            ProtocolVersion::TLSv1_3 => self.tls13.is_some(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_versions() {
        let ev = EnabledVersions::new(&[&TLS13]);
        assert!(ev.contains(ProtocolVersion::TLSv1_3));
        assert!(!ev.contains(ProtocolVersion::TLSv1_2));
        assert!(!ev.contains(ProtocolVersion::TLSv1_1));
        assert_eq!(alloc::format!("{ev:?}"), "[TLSv1_3]");
        let all = EnabledVersions::new(ALL_VERSIONS);
        assert!(all.contains(ProtocolVersion::TLSv1_3));
    }
}
