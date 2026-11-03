//! Session state saved for resumption.

use alloc::vec::Vec;
use core::fmt;

use browntls_pki::{DnsName, UnixTime};

use super::base::{PayloadU8, PayloadU16};
use super::codec::{Codec, Reader};
use super::handshake::CertificateChain;
#[cfg(feature = "tls12")]
use super::handshake::SessionId;
use crate::enums::{CipherSuite, ProtocolVersion};
use crate::error::InvalidMessage;
use crate::sync::Arc;
#[cfg(feature = "tls12")]
use crate::tls12::Tls12CipherSuite;
use crate::tls13::Tls13CipherSuite;

/// A value with the time it was retrieved from storage, for age computations.
pub(crate) struct Retrieved<T> {
    pub(crate) value: T,
    retrieved_at: UnixTime,
}

impl<T> Retrieved<T> {
    pub(crate) fn new(value: T, retrieved_at: UnixTime) -> Self {
        Self {
            value,
            retrieved_at,
        }
    }

    pub(crate) fn map<M>(&self, f: impl FnOnce(&T) -> Option<&M>) -> Option<Retrieved<&M>> {
        Some(Retrieved {
            value: f(&self.value)?,
            retrieved_at: self.retrieved_at,
        })
    }
}

impl Retrieved<&Tls13ClientSessionValue> {
    /// The `obfuscated_ticket_age` for the PSK identity (RFC 8446 §4.2.11.1).
    pub(crate) fn obfuscated_ticket_age(&self) -> u32 {
        let age_secs = self
            .retrieved_at
            .as_secs()
            .saturating_sub(self.value.common.epoch);
        let age_millis = u32::try_from(age_secs.saturating_mul(1000)).unwrap_or(u32::MAX);
        age_millis.wrapping_add(self.value.age_add)
    }
}

impl<T: core::ops::Deref<Target = ClientSessionCommon>> Retrieved<T> {
    pub(crate) fn has_expired(&self) -> bool {
        let common = &*self.value;
        common.lifetime_secs != 0
            && common.epoch.saturating_add(u64::from(common.lifetime_secs))
                < self.retrieved_at.as_secs()
    }
}

impl<T> core::ops::Deref for Retrieved<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

/// A TLS 1.3 ticket and the secrets needed to use it.
pub struct Tls13ClientSessionValue {
    suite: &'static Tls13CipherSuite,
    age_add: u32,
    max_early_data_size: u32,
    pub(crate) common: ClientSessionCommon,
}

impl Tls13ClientSessionValue {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        suite: &'static Tls13CipherSuite,
        ticket: Vec<u8>,
        secret: &[u8],
        server_cert_chain: Arc<CertificateChain<'static>>,
        time_now: UnixTime,
        lifetime_secs: u32,
        age_add: u32,
        max_early_data_size: u32,
    ) -> Self {
        Self {
            suite,
            age_add,
            max_early_data_size,
            common: ClientSessionCommon::new(
                ticket,
                secret,
                time_now,
                lifetime_secs,
                server_cert_chain,
            ),
        }
    }

    /// How much early data the server will accept with this ticket.
    pub fn max_early_data_size(&self) -> u32 {
        self.max_early_data_size
    }

    /// The suite the session used.
    pub fn suite(&self) -> &'static Tls13CipherSuite {
        self.suite
    }

    /// Test helper: makes the session look older.
    #[doc(hidden)]
    pub fn rewind_epoch(&mut self, delta: u32) {
        self.common.epoch = self.common.epoch.saturating_sub(u64::from(delta));
    }
}

impl core::ops::Deref for Tls13ClientSessionValue {
    type Target = ClientSessionCommon;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl fmt::Debug for Tls13ClientSessionValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls13ClientSessionValue")
            .field("suite", &self.suite.common.suite)
            .field("max_early_data_size", &self.max_early_data_size)
            .field("common", &self.common)
            .finish_non_exhaustive()
    }
}

/// A TLS 1.2 session (ID and/or ticket) and its master secret.
#[cfg(feature = "tls12")]
#[derive(Clone)]
pub struct Tls12ClientSessionValue {
    suite: &'static Tls12CipherSuite,
    pub(crate) session_id: SessionId,
    extended_ms: bool,
    pub(crate) common: ClientSessionCommon,
}

#[cfg(feature = "tls12")]
impl Tls12ClientSessionValue {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        suite: &'static Tls12CipherSuite,
        session_id: SessionId,
        ticket: Vec<u8>,
        master_secret: &[u8],
        server_cert_chain: Arc<CertificateChain<'static>>,
        time_now: UnixTime,
        lifetime_secs: u32,
        extended_ms: bool,
    ) -> Self {
        Self {
            suite,
            session_id,
            extended_ms,
            common: ClientSessionCommon::new(
                ticket,
                master_secret,
                time_now,
                lifetime_secs,
                server_cert_chain,
            ),
        }
    }

    pub(crate) fn extended_ms(&self) -> bool {
        self.extended_ms
    }

    pub(crate) fn suite(&self) -> &'static Tls12CipherSuite {
        self.suite
    }

    /// Test helper: makes the session look older.
    #[doc(hidden)]
    pub fn rewind_epoch(&mut self, delta: u32) {
        self.common.epoch = self.common.epoch.saturating_sub(u64::from(delta));
    }
}

#[cfg(feature = "tls12")]
impl core::ops::Deref for Tls12ClientSessionValue {
    type Target = ClientSessionCommon;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

#[cfg(feature = "tls12")]
impl fmt::Debug for Tls12ClientSessionValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls12ClientSessionValue")
            .field("suite", &self.suite.common.suite)
            .field("extended_ms", &self.extended_ms)
            .field("common", &self.common)
            .finish_non_exhaustive()
    }
}

/// What every client session value shares.
#[derive(Clone)]
pub struct ClientSessionCommon {
    ticket: Vec<u8>,
    secret: Vec<u8>,
    epoch: u64,
    lifetime_secs: u32,
    server_cert_chain: Arc<CertificateChain<'static>>,
}

impl ClientSessionCommon {
    fn new(
        ticket: Vec<u8>,
        secret: &[u8],
        time_now: UnixTime,
        lifetime_secs: u32,
        server_cert_chain: Arc<CertificateChain<'static>>,
    ) -> Self {
        Self {
            ticket,
            secret: secret.to_vec(),
            epoch: time_now.as_secs(),
            lifetime_secs: lifetime_secs.min(MAX_TICKET_LIFETIME),
            server_cert_chain,
        }
    }

    pub(crate) fn server_cert_chain(&self) -> &CertificateChain<'static> {
        &self.server_cert_chain
    }

    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }

    pub(crate) fn ticket(&self) -> &[u8] {
        &self.ticket
    }
}

impl Drop for ClientSessionCommon {
    fn drop(&mut self) {
        crate::crypto::zeroize_vec(&mut self.secret);
    }
}

impl fmt::Debug for ClientSessionCommon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSessionCommon")
            .field("ticket_len", &self.ticket.len())
            .field("epoch", &self.epoch)
            .field("lifetime_secs", &self.lifetime_secs)
            .finish_non_exhaustive()
    }
}

/// RFC 8446 §4.6.1: ticket lifetimes are at most seven days.
pub(crate) const MAX_TICKET_LIFETIME: u32 = 7 * 24 * 60 * 60;

/// The server's record of a session, stored in the session cache or
/// encrypted into a ticket.
pub(crate) struct ServerSessionValue {
    pub(crate) sni: Option<DnsName<'static>>,
    pub(crate) version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) master_secret: PayloadU8,
    pub(crate) extended_ms: bool,
    pub(crate) client_cert_chain: Option<CertificateChain<'static>>,
    pub(crate) alpn: Option<PayloadU8>,
    pub(crate) application_data: PayloadU16,
    /// Seconds since the epoch when the session was created.
    pub creation_time_sec: u64,
    pub(crate) age_obfuscation_offset: u32,
    freshness: Option<bool>,
}

impl ServerSessionValue {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        sni: Option<&DnsName<'_>>,
        version: ProtocolVersion,
        cipher_suite: CipherSuite,
        master_secret: &[u8],
        client_cert_chain: Option<CertificateChain<'static>>,
        alpn: Option<Vec<u8>>,
        application_data: Vec<u8>,
        creation_time: UnixTime,
        age_obfuscation_offset: u32,
    ) -> Self {
        Self {
            sni: sni.map(DnsName::to_owned),
            version,
            cipher_suite,
            master_secret: PayloadU8::new(master_secret.to_vec()),
            extended_ms: false,
            client_cert_chain,
            alpn: alpn.map(PayloadU8::new),
            application_data: PayloadU16::new(application_data),
            creation_time_sec: creation_time.as_secs(),
            age_obfuscation_offset,
            freshness: None,
        }
    }

    pub(crate) fn set_extended_ms_used(&mut self) {
        self.extended_ms = true;
    }

    /// Records whether the client's reported ticket age is consistent with the
    /// ticket's real age (RFC 8446 §8.3), for the 0-RTT decision.
    pub(crate) fn set_freshness(
        mut self,
        obfuscated_client_age_ms: u32,
        time_now: UnixTime,
    ) -> Self {
        let client_age_ms = obfuscated_client_age_ms.wrapping_sub(self.age_obfuscation_offset);
        let server_age_ms = time_now
            .as_secs()
            .saturating_sub(self.creation_time_sec)
            .saturating_mul(1000);
        let server_age_ms = u32::try_from(server_age_ms).unwrap_or(u32::MAX);
        let age_difference = server_age_ms.abs_diff(client_age_ms);
        self.freshness = Some(age_difference <= MAX_FRESHNESS_SKEW_MS);
        self
    }

    /// Whether the ticket's age matched the server's clock (0-RTT gate).
    pub(crate) fn is_fresh(&self) -> bool {
        self.freshness.unwrap_or_default()
    }
}

/// How far the client's and server's view of a ticket's age may differ.
const MAX_FRESHNESS_SKEW_MS: u32 = 60 * 1000;

impl Drop for ServerSessionValue {
    fn drop(&mut self) {
        crate::crypto::zeroize_vec(&mut self.master_secret.0);
    }
}

impl fmt::Debug for ServerSessionValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerSessionValue")
            .field("sni", &self.sni)
            .field("version", &self.version)
            .field("cipher_suite", &self.cipher_suite)
            .field("extended_ms", &self.extended_ms)
            .field("has_client_cert", &self.client_cert_chain.is_some())
            .field("alpn", &self.alpn)
            .field("creation_time_sec", &self.creation_time_sec)
            .finish_non_exhaustive()
    }
}

impl Codec<'_> for ServerSessionValue {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match &self.sni {
            Some(sni) => {
                1u8.encode(bytes);
                PayloadU8::new(sni.as_ref().as_bytes().to_vec()).encode(bytes);
            }
            None => 0u8.encode(bytes),
        }
        self.version.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.master_secret.encode(bytes);
        u8::from(self.extended_ms).encode(bytes);
        match &self.client_cert_chain {
            Some(chain) => {
                1u8.encode(bytes);
                chain.encode(bytes);
            }
            None => 0u8.encode(bytes),
        }
        match &self.alpn {
            Some(alpn) => {
                1u8.encode(bytes);
                alpn.encode(bytes);
            }
            None => 0u8.encode(bytes),
        }
        self.application_data.encode(bytes);
        self.creation_time_sec.encode(bytes);
        self.age_obfuscation_offset.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let sni = match u8::read(r)? {
            1 => {
                let raw = PayloadU8::read(r)?;
                let s =
                    core::str::from_utf8(&raw.0).map_err(|_| InvalidMessage::InvalidServerName)?;
                Some(
                    DnsName::try_from(s)
                        .map_err(|_| InvalidMessage::InvalidServerName)?
                        .to_owned(),
                )
            }
            0 => None,
            _ => return Err(InvalidMessage::InvalidServerName),
        };
        let version = ProtocolVersion::read(r)?;
        let cipher_suite = CipherSuite::read(r)?;
        let master_secret = PayloadU8::read(r)?;
        let extended_ms = match u8::read(r)? {
            0 => false,
            1 => true,
            _ => return Err(InvalidMessage::IllegalEmptyValue),
        };
        let client_cert_chain = match u8::read(r)? {
            1 => Some(CertificateChain::read(r)?.into_owned()),
            0 => None,
            _ => return Err(InvalidMessage::IllegalEmptyValue),
        };
        let alpn = match u8::read(r)? {
            1 => Some(PayloadU8::read(r)?),
            0 => None,
            _ => return Err(InvalidMessage::IllegalEmptyValue),
        };
        let application_data = PayloadU16::read(r)?;
        let creation_time_sec = u64::read(r)?;
        let age_obfuscation_offset = u32::read(r)?;
        Ok(Self {
            sni,
            version,
            cipher_suite,
            master_secret,
            extended_ms,
            client_cert_chain,
            alpn,
            application_data,
            creation_time_sec,
            age_obfuscation_offset,
            freshness: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use browntls_pki::CertificateDer;

    use super::*;

    fn sample() -> ServerSessionValue {
        let mut v = ServerSessionValue::new(
            Some(&DnsName::try_from("example.com").unwrap()),
            ProtocolVersion::TLSv1_3,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            &[1, 2, 3],
            Some(CertificateChain(alloc::vec![
                CertificateDer::from_slice(&[9]).into_owned()
            ])),
            Some(alloc::vec![b'h', b'2']),
            alloc::vec![7, 7],
            UnixTime::since_unix_epoch(core::time::Duration::from_secs(1000)),
            0x1234,
        );
        v.set_extended_ms_used();
        v
    }

    #[test]
    fn server_value_roundtrip() {
        let v = sample();
        let enc = v.get_encoding();
        let back = ServerSessionValue::read_bytes(&enc).unwrap();
        assert_eq!(back.sni, v.sni);
        assert_eq!(back.version, v.version);
        assert_eq!(back.cipher_suite, v.cipher_suite);
        assert_eq!(back.master_secret, v.master_secret);
        assert!(back.extended_ms);
        assert_eq!(back.client_cert_chain, v.client_cert_chain);
        assert_eq!(back.alpn, v.alpn);
        assert_eq!(back.application_data, v.application_data);
        assert_eq!(back.creation_time_sec, 1000);
        assert_eq!(back.age_obfuscation_offset, 0x1234);
        assert!(!back.is_fresh());
        assert!(ServerSessionValue::read_bytes(&enc[..enc.len() - 1]).is_err());
        assert!(alloc::format!("{back:?}").contains("example.com"));
    }

    #[test]
    fn freshness() {
        let v = sample();
        let now = UnixTime::since_unix_epoch(core::time::Duration::from_secs(1010));
        // client says 10 000 ms old, obfuscated by the offset
        let fresh = v.set_freshness(10_000u32.wrapping_add(0x1234), now);
        assert!(fresh.is_fresh());
        let v = sample();
        let stale = v.set_freshness(500_000u32.wrapping_add(0x1234), now);
        assert!(!stale.is_fresh());
    }

    #[test]
    fn client_value_age() {
        let chain = Arc::new(CertificateChain::default());
        let suite = Tls13CipherSuite {
            common: crate::suites::CipherSuiteCommon {
                suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                hash_provider: &DummyHash,
                confidentiality_limit: 1,
            },
            hkdf_provider: &DummyHkdf,
            aead_alg: &DummyAead,
        };
        let suite: &'static Tls13CipherSuite =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(suite));
        let created = UnixTime::since_unix_epoch(core::time::Duration::from_secs(100));
        let v = Tls13ClientSessionValue::new(suite, alloc::vec![1], &[2], chain, created, 60, 5, 0);
        assert_eq!(v.max_early_data_size(), 0);
        let later = UnixTime::since_unix_epoch(core::time::Duration::from_secs(130));
        let r = Retrieved::new(&v, later);
        assert_eq!(r.obfuscated_ticket_age(), 30_000 + 5);
        let r2 = Retrieved::new(v, later);
        assert!(!r2.has_expired());
        let much_later = UnixTime::since_unix_epoch(core::time::Duration::from_secs(1000));
        let r3 = Retrieved::new(r2.value, much_later);
        assert!(r3.has_expired());
    }

    struct DummyHash;
    impl crate::crypto::hash::Hash for DummyHash {
        fn start(&self) -> alloc::boxed::Box<dyn crate::crypto::hash::Context> {
            unimplemented!()
        }
        fn hash(&self, _: &[u8]) -> crate::crypto::hash::Output {
            unimplemented!()
        }
        fn output_len(&self) -> usize {
            32
        }
        fn algorithm(&self) -> crate::crypto::hash::HashAlgorithm {
            crate::crypto::hash::HashAlgorithm::SHA256
        }
    }
    struct DummyHkdf;
    impl crate::crypto::tls13::Hkdf for DummyHkdf {
        fn extract_from_zero_ikm(
            &self,
            _: Option<&[u8]>,
        ) -> alloc::boxed::Box<dyn crate::crypto::tls13::HkdfExpander> {
            unimplemented!()
        }
        fn extract_from_secret(
            &self,
            _: Option<&[u8]>,
            _: &[u8],
        ) -> alloc::boxed::Box<dyn crate::crypto::tls13::HkdfExpander> {
            unimplemented!()
        }
        fn expander_for_okm(
            &self,
            _: &crate::crypto::tls13::OkmBlock,
        ) -> alloc::boxed::Box<dyn crate::crypto::tls13::HkdfExpander> {
            unimplemented!()
        }
        fn hmac_sign(
            &self,
            _: &crate::crypto::tls13::OkmBlock,
            _: &[u8],
        ) -> crate::crypto::hmac::Tag {
            unimplemented!()
        }
    }
    struct DummyAead;
    impl crate::crypto::cipher::Tls13AeadAlgorithm for DummyAead {
        fn encrypter(
            &self,
            _: crate::crypto::cipher::AeadKey,
            _: crate::crypto::cipher::Iv,
        ) -> alloc::boxed::Box<dyn crate::crypto::cipher::MessageEncrypter> {
            unimplemented!()
        }
        fn decrypter(
            &self,
            _: crate::crypto::cipher::AeadKey,
            _: crate::crypto::cipher::Iv,
        ) -> alloc::boxed::Box<dyn crate::crypto::cipher::MessageDecrypter> {
            unimplemented!()
        }
        fn key_len(&self) -> usize {
            16
        }
        fn extract_keys(
            &self,
            _: crate::crypto::cipher::AeadKey,
            _: crate::crypto::cipher::Iv,
        ) -> Result<
            crate::suites::ConnectionTrafficSecrets,
            crate::crypto::cipher::UnsupportedOperationError,
        > {
            Err(crate::crypto::cipher::UnsupportedOperationError)
        }
    }
}
