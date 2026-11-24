//! Session state saved for resumption.

use alloc::vec::Vec;
use core::fmt;

use browntls_pki::{DnsName, ReferenceIdentifier, ServerName, ServiceIdentity, UnixTime};

use super::base::{PayloadU8, PayloadU16};
use super::codec::{Codec, Reader};
use super::handshake::CertificateChain;
#[cfg(feature = "tls12")]
use super::handshake::SessionId;
use crate::client::ResolvesClientCert;
use crate::enums::{CipherSuite, ProtocolVersion};
use crate::error::InvalidMessage;
use crate::psk::ExternalPskBinding;
use crate::sync::{Arc, Weak};
#[cfg(feature = "tls12")]
use crate::tls12::Tls12CipherSuite;
use crate::tls13::Tls13CipherSuite;
use crate::tls13::key_schedule::Protocol;
use crate::verify::ServerCertVerifier;

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
    early_data_alpn: Option<Vec<u8>>,
    early_data_record_size_limit: u16,
    /// QUIC: the server's transport parameters, remembered for 0-RTT
    /// (RFC 9000 §7.4.1); empty otherwise.
    quic_params: PayloadU16,
    pub(crate) common: ClientSessionCommon,
    /// The external PSK the session was established with, if any.
    external_psk: Option<ExternalPskBinding>,
    /// The absolute expiry of the delegated credential that authenticated the
    /// original full handshake. Descendant tickets preserve it unchanged.
    delegated_credential_expiry: Option<UnixTime>,
    /// The protocol the ticket was issued over, the only one it resumes:
    /// the binder's label prefix differs between TLS and DTLS (RFC 9147
    /// §5.9).
    protocol: Protocol,
}

impl Tls13ClientSessionValue {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        suite: &'static Tls13CipherSuite,
        ticket: Vec<u8>,
        secret: &[u8],
        server_cert_chain: Arc<CertificateChain<'static>>,
        binding: &ClientConfigBinding<'_>,
        time_now: UnixTime,
        lifetime_secs: u32,
        age_add: u32,
        max_early_data_size: u32,
    ) -> Self {
        Self {
            suite,
            age_add,
            max_early_data_size,
            early_data_alpn: None,
            early_data_record_size_limit: crate::common_state::max_record_size_limit(true),
            quic_params: PayloadU16::empty(),
            common: ClientSessionCommon::new(
                ticket,
                secret,
                time_now,
                lifetime_secs,
                server_cert_chain,
                binding,
            ),
            external_psk: None,
            delegated_credential_expiry: None,
            protocol: Protocol::Tls13,
        }
    }

    /// Records the protocol the ticket was issued over (TLS 1.3 unless
    /// set).
    pub(crate) fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// The protocol the ticket was issued over.
    pub(crate) fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Records the external PSK the session was established with.
    pub(crate) fn with_external_psk(mut self, external_psk: Option<ExternalPskBinding>) -> Self {
        self.external_psk = external_psk;
        self
    }

    pub(crate) fn external_psk(&self) -> Option<&ExternalPskBinding> {
        self.external_psk.as_ref()
    }

    pub(crate) fn with_delegated_credential_expiry(mut self, expiry: Option<UnixTime>) -> Self {
        self.delegated_credential_expiry = expiry;
        self
    }

    pub(crate) fn delegated_credential_expiry(&self) -> Option<UnixTime> {
        self.delegated_credential_expiry
    }

    pub(crate) fn delegated_credential_expired_at(&self, now: UnixTime) -> bool {
        self.delegated_credential_expiry
            .is_some_and(|expiry| now >= expiry)
    }

    /// The identity of the external PSK (RFC 9846 §4.3.11) the session was
    /// established with, if it was; resuming it needs that PSK to still be
    /// configured, and reports this identity again.
    pub fn external_psk_identity(&self) -> Option<&[u8]> {
        self.external_psk.as_ref().map(|b| b.identity.as_slice())
    }

    /// How much early data the server will accept with this ticket.
    pub fn max_early_data_size(&self) -> u32 {
        self.max_early_data_size
    }

    pub(crate) fn with_early_data_alpn(mut self, alpn: Option<&[u8]>) -> Self {
        if self.max_early_data_size != 0 {
            self.early_data_alpn = alpn.map(<[u8]>::to_vec);
        }
        self
    }

    pub(crate) fn early_data_alpn(&self) -> Option<&[u8]> {
        self.early_data_alpn.as_deref()
    }

    pub(crate) fn with_early_data_record_size_limit(mut self, limit: u16) -> Self {
        self.early_data_record_size_limit = limit;
        self
    }

    pub(crate) fn early_data_record_size_limit(&self) -> u16 {
        self.early_data_record_size_limit
    }

    /// QUIC: the server's transport parameters when the ticket was issued.
    pub fn quic_params(&self) -> &[u8] {
        &self.quic_params.0
    }

    pub(crate) fn set_quic_params(&mut self, params: &[u8]) {
        self.quic_params = PayloadU16::new(params.to_vec());
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
            .field("external_psk", &self.external_psk.is_some())
            .field(
                "delegated_credential_expiry",
                &self.delegated_credential_expiry,
            )
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

/// A stream TLS 1.2 or DTLS 1.2 session and its master secret.
#[cfg(feature = "tls12")]
#[derive(Clone)]
pub struct Tls12ClientSessionValue {
    version: ProtocolVersion,
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
        binding: &ClientConfigBinding<'_>,
        time_now: UnixTime,
        lifetime_secs: u32,
        extended_ms: bool,
    ) -> Self {
        Self {
            suite,
            session_id,
            extended_ms,
            version: ProtocolVersion::TLSv1_2,
            common: ClientSessionCommon::new(
                ticket,
                master_secret,
                time_now,
                lifetime_secs,
                server_cert_chain,
                binding,
            ),
        }
    }

    /// The transport and version that established this session.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.version
    }

    pub(crate) fn set_dtls12(&mut self) {
        self.version = ProtocolVersion::DTLSv1_2;
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
            .field("version", &self.version)
            .field("suite", &self.suite.common.suite)
            .field("extended_ms", &self.extended_ms)
            .field("common", &self.common)
            .finish_non_exhaustive()
    }
}

/// The client configuration objects that decided how a session was
/// authenticated: the server certificate verifier that accepted the server
/// and the resolver that chose the client's credentials.
///
/// A session store may be shared between configurations (it sits behind an
/// `Arc` in [`crate::client::Resumption`]). Resuming skips server
/// certificate verification and keeps the original client identity, so a
/// session must only be offered by a configuration that uses the very same
/// verifier and resolver objects that established it.
pub(crate) struct ClientConfigBinding<'a> {
    pub(crate) server_cert_verifier: &'a Arc<dyn ServerCertVerifier>,
    pub(crate) client_creds: &'a Arc<dyn ResolvesClientCert>,
}

/// What every client session value shares.
#[derive(Clone)]
pub struct ClientSessionCommon {
    ticket: Vec<u8>,
    secret: Vec<u8>,
    epoch: u64,
    lifetime_secs: u32,
    server_cert_chain: Arc<CertificateChain<'static>>,
    routing_name: Option<ServerName<'static>>,
    service_identity: Option<Arc<ServiceIdentity>>,
    pub(crate) matched_service_identity: Option<ReferenceIdentifier>,
    /// Identity of the verifier that authenticated the server. A `Weak`
    /// keeps the allocation (so its address cannot be reused by another
    /// verifier while the session lives) without keeping the verifier
    /// itself alive in the cache.
    server_cert_verifier: Weak<dyn ServerCertVerifier>,
    /// Identity of the resolver that chose the client's credentials.
    client_creds: Weak<dyn ResolvesClientCert>,
}

impl ClientSessionCommon {
    fn new(
        ticket: Vec<u8>,
        secret: &[u8],
        time_now: UnixTime,
        lifetime_secs: u32,
        server_cert_chain: Arc<CertificateChain<'static>>,
        binding: &ClientConfigBinding<'_>,
    ) -> Self {
        Self {
            ticket,
            secret: secret.to_vec(),
            epoch: time_now.as_secs(),
            lifetime_secs: lifetime_secs.min(MAX_TICKET_LIFETIME),
            server_cert_chain,
            routing_name: None,
            service_identity: None,
            matched_service_identity: None,
            server_cert_verifier: Arc::downgrade(binding.server_cert_verifier),
            client_creds: Arc::downgrade(binding.client_creds),
        }
    }

    /// Whether `binding` names the same verifier and client credential
    /// resolver objects that established this session. Only the object
    /// identities are compared (not their behavior or configuration), so a
    /// replaced verifier never inherits a session, even an equivalent one.
    /// The addresses are compared without the trait-object metadata, which
    /// may differ for the same object.
    pub(crate) fn compatible_config(&self, binding: &ClientConfigBinding<'_>) -> bool {
        core::ptr::addr_eq(
            self.server_cert_verifier.as_ptr(),
            Arc::as_ptr(binding.server_cert_verifier),
        ) && core::ptr::addr_eq(
            self.client_creds.as_ptr(),
            Arc::as_ptr(binding.client_creds),
        )
    }

    pub(crate) fn bind_server_identity(
        &mut self,
        routing_name: &ServerName<'static>,
        service_identity: Option<&Arc<ServiceIdentity>>,
        matched: Option<&ReferenceIdentifier>,
    ) {
        self.routing_name = Some(routing_name.clone());
        self.service_identity = service_identity.cloned();
        self.matched_service_identity = matched.cloned();
    }

    pub(crate) fn compatible_server_identity(
        &self,
        routing_name: &ServerName<'_>,
        service_identity: Option<&ServiceIdentity>,
    ) -> bool {
        self.routing_name
            .as_ref()
            .is_none_or(|saved| saved == routing_name)
            && self.service_identity.as_deref() == service_identity
            && (service_identity.is_none()
                || (self.matched_service_identity.is_some()
                    && !self.server_cert_chain.0.is_empty()))
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
    /// The external PSK a TLS 1.3 session was established with: resuming
    /// it requires that PSK to still be configured and usable.
    pub(crate) external_psk: Option<ExternalPskBinding>,
    /// The absolute expiry of the server delegated credential that
    /// authenticated the original TLS 1.3 full handshake.
    pub(crate) delegated_credential_expiry: Option<UnixTime>,
    /// The absolute expiry of the client delegated credential (RFC 9345
    /// §4.1.2) that authenticated `client_cert_chain` in the original
    /// TLS 1.3 full handshake.
    pub(crate) client_delegated_credential_expiry: Option<UnixTime>,
    /// The original handshake authenticated with only an external PSK.
    pub(crate) certificate_free: bool,
    /// The effective server receive limit under stream TLS 1.3 0-RTT
    /// keys. Absent for older sessions and tickets without stream 0-RTT.
    pub(crate) early_data_record_size_limit: Option<u16>,
}

impl ServerSessionValue {
    /// Classifies a stored or authenticated session without copying its
    /// certificate chain, key material or application data.
    pub(crate) fn encoded_version(plaintext: &[u8]) -> Option<ProtocolVersion> {
        let mut reader = Reader::init(plaintext);
        match u8::read(&mut reader).ok()? {
            0 => {}
            1 => {
                let name_len = u8::read(&mut reader).ok()?;
                reader.take(usize::from(name_len))?;
            }
            _ => return None,
        }
        ProtocolVersion::read(&mut reader).ok()
    }

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
            external_psk: None,
            delegated_credential_expiry: None,
            client_delegated_credential_expiry: None,
            certificate_free: false,
            early_data_record_size_limit: None,
        }
    }

    pub(crate) fn set_external_psk(&mut self, external_psk: Option<ExternalPskBinding>) {
        self.external_psk = external_psk;
    }

    pub(crate) fn set_delegated_credential_expiry(&mut self, expiry: Option<UnixTime>) {
        self.delegated_credential_expiry = expiry;
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
            .field("external_psk", &self.external_psk.is_some())
            .field(
                "delegated_credential_expiry",
                &self.delegated_credential_expiry,
            )
            .field(
                "client_delegated_credential_expiry",
                &self.client_delegated_credential_expiry,
            )
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
        match &self.external_psk {
            None => 0u8.encode(bytes),
            Some(binding) => {
                match &binding.import_context {
                    None => 3u8.encode(bytes),
                    Some(_) => 4u8.encode(bytes),
                }
                PayloadU16::encode_slice(&binding.identity, bytes);
                if let Some(context) = &binding.import_context {
                    PayloadU16::encode_slice(context, bytes);
                }
                PayloadU8::new(binding.key_tag.clone()).encode(bytes);
            }
        }
        // A bit per delegated credential deadline: 1 for the server's, 2
        // for the client's; the deadlines follow in that order.
        let deadlines = [
            self.delegated_credential_expiry,
            self.client_delegated_credential_expiry,
        ];
        let tag = u8::from(deadlines[0].is_some()) | (u8::from(deadlines[1].is_some()) << 1);
        tag.encode(bytes);
        for expiry in deadlines.into_iter().flatten() {
            expiry.as_secs().encode(bytes);
        }
        if let Some(limit) = self.early_data_record_size_limit {
            (2 | u8::from(self.certificate_free)).encode(bytes);
            limit.encode(bytes);
        } else if self.certificate_free {
            1u8.encode(bytes);
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let sni = match u8::read(r)? {
            1 => {
                let raw = PayloadU8::read(r)?;
                let s =
                    core::str::from_utf8(&raw.0).map_err(|_| InvalidMessage::InvalidServerName)?;
                Some(
                    DnsName::try_from_ascii(s)
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
        let external_psk = match u8::read(r)? {
            0 => None,
            tag @ (3 | 4) => {
                let identity = PayloadU16::read(r)?.0;
                let import_context = match tag {
                    4 => Some(PayloadU16::read(r)?.0),
                    _ => None,
                };
                let key_tag = PayloadU8::read(r)?.0;
                if !matches!(key_tag.len(), 32 | 48) {
                    return Err(InvalidMessage::IllegalEmptyValue);
                }
                Some(ExternalPskBinding {
                    identity,
                    import_context,
                    key_tag,
                })
            }
            _ => return Err(InvalidMessage::IllegalEmptyValue),
        };
        let deadlines = u8::read(r)?;
        if deadlines > 3 {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        let mut deadline = |bit: u8| -> Result<Option<UnixTime>, InvalidMessage> {
            if deadlines & bit == 0 {
                return Ok(None);
            }
            Ok(Some(UnixTime::since_unix_epoch(
                core::time::Duration::from_secs(u64::read(r)?),
            )))
        };
        let delegated_credential_expiry = deadline(1)?;
        let client_delegated_credential_expiry = deadline(2)?;
        // A DTLS 1.3 session is a TLS 1.3 one issued over DTLS.
        let tls13 = matches!(
            version,
            ProtocolVersion::TLSv1_3 | ProtocolVersion::DTLSv1_3
        );
        // Delegated credentials are TLS 1.3 only, and a client's
        // authenticates a certificate chain.
        if (deadlines != 0 && !tls13)
            || (client_delegated_credential_expiry.is_some() && client_cert_chain.is_none())
        {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        // The optional tail used to encode only the certificate-free
        // marker (1). Bit 1 introduces the stream 0-RTT cap.
        let flags = if r.any_left() {
            let flags = u8::read(r)?;
            if !(1..=3).contains(&flags) {
                return Err(InvalidMessage::IllegalEmptyValue);
            }
            flags
        } else {
            0
        };
        let certificate_free = flags & 1 != 0;
        if certificate_free
            && (!tls13
                || external_psk.is_none()
                || client_cert_chain.is_some()
                || delegated_credential_expiry.is_some())
        {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        let early_data_record_size_limit = if flags & 2 != 0 {
            let limit = u16::read(r)?;
            if version != ProtocolVersion::TLSv1_3
                || !(crate::common_state::MIN_RECORD_SIZE_LIMIT
                    ..=crate::common_state::max_record_size_limit(true))
                    .contains(&limit)
            {
                return Err(InvalidMessage::IllegalEmptyValue);
            }
            Some(limit)
        } else {
            None
        };
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
            external_psk,
            delegated_credential_expiry,
            client_delegated_credential_expiry,
            certificate_free,
            early_data_record_size_limit,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests;
