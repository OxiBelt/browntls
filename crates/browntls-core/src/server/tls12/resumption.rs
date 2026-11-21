//! DTLS 1.2 resumption domains and server authentication policy binding.
//!
//! Stream TLS keeps its existing persistence encoding. DTLS adds an opaque
//! configuration domain and the selected credentials outside that encoding;
//! it also retains DTLSv1_2 inside the value, including in encrypted tickets.

use alloc::borrow::Cow;
use alloc::vec::Vec;

use browntls_pki::CertificateDer;

use super::super::hs::{NegotiatedCertTypes, ServerContext};
use super::super::{ProducesTickets, ResolvesServerCert, ServerConfig};
use crate::common_state::CommonState;
use crate::enums::ProtocolVersion;
use crate::error::Error;
use crate::msgs::codec::Codec;
use crate::msgs::persist::ServerSessionValue;
use crate::sync::{Arc, Weak};
use crate::tls12::Tls12CipherSuite;
use crate::verify::ClientCertVerifier;

const DOMAIN: &[u8] = b"browntls dtls12 session 1";

/// A fresh domain for one verifier/resolver policy. Weak references prevent
/// identity reuse without retaining either policy object in old clones.
#[derive(Debug)]
pub(crate) struct Context {
    id: [u8; 32],
    verifier: Weak<dyn ClientCertVerifier>,
    resolver: Weak<dyn ResolvesServerCert>,
}

impl Context {
    pub(crate) fn new(config: &ServerConfig) -> Result<Self, Error> {
        let mut id = [0; 32];
        config.provider.secure_random.fill(&mut id)?;
        Ok(Self {
            id,
            verifier: Arc::downgrade(&config.verifier),
            resolver: Arc::downgrade(&config.cert_resolver),
        })
    }

    fn matches(&self, config: &ServerConfig) -> bool {
        core::ptr::addr_eq(self.verifier.as_ptr(), Arc::as_ptr(&config.verifier))
            && core::ptr::addr_eq(self.resolver.as_ptr(), Arc::as_ptr(&config.cert_resolver))
    }
}

pub(super) fn ticketer<'a>(
    config: &'a ServerConfig,
    common: &CommonState,
) -> &'a dyn ProducesTickets {
    if common.is_dtls() {
        &*config.dtls12_ticketer
    } else {
        &*config.ticketer
    }
}

/// Captures the selected chain and certificate types before either a full
/// or abbreviated handshake. A changed policy falls back to a full handshake
/// until the caller explicitly enables a fresh context.
pub(super) fn bind(
    cx: &mut ServerContext<'_>,
    config: &ServerConfig,
    suite: &'static Tls12CipherSuite,
    certs: &[CertificateDer<'_>],
    cert_types: &NegotiatedCertTypes,
) -> bool {
    if !cx.common.is_dtls() {
        return true;
    }
    let Some(context) = config
        .dtls12_resumption_context
        .as_ref()
        .filter(|c| c.matches(config))
    else {
        return false;
    };
    let mut binding = DOMAIN.to_vec();
    binding.extend_from_slice(&context.id);
    let mut hash = suite.common.hash_provider.start();
    for cert in certs {
        hash.update(&(cert.as_ref().len() as u64).to_be_bytes());
        hash.update(cert.as_ref());
    }
    binding.extend_from_slice(hash.finish().as_ref());
    binding.extend_from_slice(&[
        u8::from(config.verifier.offer_client_auth()),
        u8::from(config.verifier.client_auth_mandatory()),
        u8::from(config.verifier.requires_raw_public_keys()),
        cert_types.client.map(u8::from).unwrap_or(0),
        cert_types.server.map(u8::from).unwrap_or(0),
    ]);
    cx.data.dtls12_session_binding = Some(binding);
    true
}

pub(super) fn key<'a>(common: &CommonState, id: &'a [u8]) -> Cow<'a, [u8]> {
    if common.is_dtls() {
        let mut key = DOMAIN.to_vec();
        key.extend_from_slice(id);
        Cow::Owned(key)
    } else {
        Cow::Borrowed(id)
    }
}

pub(super) fn encode(cx: &ServerContext<'_>, value: &ServerSessionValue) -> Result<Vec<u8>, Error> {
    if !cx.common.is_dtls() {
        return Ok(value.get_encoding());
    }
    let mut out = cx
        .data
        .dtls12_session_binding
        .clone()
        .ok_or_else(|| Error::General("missing DTLS 1.2 session binding".into()))?;
    value.encode(&mut out);
    Ok(out)
}

pub(super) fn decode(
    cx: &ServerContext<'_>,
    config: &ServerConfig,
    plain: &[u8],
    ticket_lifetime: Option<u32>,
) -> Option<ServerSessionValue> {
    let plain = if cx.common.is_dtls() {
        plain.strip_prefix(cx.data.dtls12_session_binding.as_deref()?)?
    } else {
        plain
    };
    let value = ServerSessionValue::read_bytes(plain).ok()?;
    let version = if cx.common.is_dtls() {
        ProtocolVersion::DTLSv1_2
    } else {
        ProtocolVersion::TLSv1_2
    };
    if value.version != version || value.master_secret.0.len() != 48 {
        return None;
    }
    if cx.common.is_dtls() {
        let now = config.current_time().ok()?.as_secs();
        let lifetime = ticket_lifetime
            .unwrap_or(crate::msgs::persist::MAX_TICKET_LIFETIME)
            .min(crate::msgs::persist::MAX_TICKET_LIFETIME);
        if now < value.creation_time_sec
            || now.saturating_sub(value.creation_time_sec) >= u64::from(lifetime)
            || value.alpn.as_ref().map(|p| &p.0) != cx.common.alpn_protocol.as_ref()
            || (config.verifier.client_auth_mandatory() && value.client_cert_chain.is_none())
        {
            return None;
        }
    }
    Some(value)
}
