//! The server handshake up to version and suite negotiation.

#[cfg(feature = "tls12")]
pub(crate) mod dtls12;
mod select;

use alloc::boxed::Box;
use alloc::vec::Vec;

use browntls_pki::DnsName;

use super::common::ActiveCertifiedKey;
use super::server_conn::{ClientHello, ServerConfig, ServerConnectionData};
use super::tls13;
use crate::common_state::{ConnectionRandoms, KxState};
use crate::conn::{Context, State};
use crate::crypto::{KeyExchangeAlgorithm, SupportedKxGroup};
use crate::enums::{
    AlertDescription, CipherSuite, HandshakeType, ProtocolVersion, SignatureAlgorithm,
    SignatureScheme,
};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
use crate::log::{debug, trace};
use crate::msgs::enums::{Compression, ECPointFormat, NamedGroup, PskKeyExchangeMode};
use crate::msgs::grease::is_grease_u16;
use crate::msgs::handshake::{ClientHelloPayload, HandshakePayload, Random, SessionId};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist::ServerSessionValue;
use crate::suites::SupportedCipherSuite;
use crate::sync::Arc;

mod cert_with_extern_psk;
mod retry;
pub(super) use select::{
    NegotiatedCertTypes, kx_groups_by_preference, record_size_limit_ack, tls13_tickets_to_send,
};
use select::{choose_kx_group, negotiate_cert_type};

pub(super) type NextState = Box<dyn State<ServerConnectionData>>;
pub(super) type NextStateOrError = Result<NextState, Error>;
pub(super) type ServerContext<'a> = Context<'a, ServerConnectionData>;

/// The curve of an ECDSA signing key, found through the one ECDSA scheme it
/// signs with; `None` for other key types.
fn ecdsa_certificate_curve(key: &dyn crate::sign::SigningKey) -> Option<NamedGroup> {
    if key.algorithm() != SignatureAlgorithm::ECDSA {
        return None;
    }
    [
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            NamedGroup::secp256r1,
        ),
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            NamedGroup::secp384r1,
        ),
        (
            SignatureScheme::ECDSA_NISTP521_SHA512,
            NamedGroup::secp521r1,
        ),
    ]
    .into_iter()
    .find(|(scheme, _)| key.choose_scheme(&[*scheme]).is_some())
    .map(|(_, curve)| curve)
}

/// Whether a stored session may be resumed with the parameters negotiated now.
pub(super) fn can_resume(
    suite: SupportedCipherSuite,
    sni: &Option<DnsName<'static>>,
    using_ems: bool,
    resumedata: &ServerSessionValue,
) -> bool {
    // RFC 6066 §3: the server name must match the original connection's.
    // RFC 7627 §5.3: a session may not change its extended-master-secret use.
    resumedata.cipher_suite == suite.suite()
        && (resumedata.extended_ms == using_ems || (resumedata.extended_ms && !using_ems))
        && &resumedata.sni == sni
}

/// The transcript before and after the hash is known.
pub(super) enum HandshakeHashOrBuffer {
    Buffer(HandshakeHashBuffer),
    Hash(HandshakeHash),
}

/// The initial server state: waiting for a ClientHello.
pub(super) struct ExpectClientHello {
    pub(super) config: Arc<ServerConfig>,
    pub(super) transcript: HandshakeHashOrBuffer,
    pub(super) session_id: SessionId,
    pub(super) done_retry: bool,
    pub(super) retry_cert_with_extern_psk: bool,
    /// What our HelloRetryRequest selected, which the second ClientHello
    /// must follow (RFC 9846 §4.2.4).
    pub(super) retry_choice: Option<RetryChoice>,
    /// The cookie our HelloRetryRequest carried, which the second
    /// ClientHello must echo (RFC 9846 §4.3.2).
    pub(super) sent_cookie: Option<Vec<u8>>,
    pub(super) send_tickets: usize,
}

/// The cipher suite and key exchange group a HelloRetryRequest selected.
#[derive(Clone, Copy)]
pub(super) struct RetryChoice {
    pub(super) suite: &'static crate::tls13::Tls13CipherSuite,
    pub(super) group: &'static dyn SupportedKxGroup,
    /// Whether the HelloRetryRequest named `group` (always, but on DTLS
    /// when only a cookie was asked for, RFC 9147 §5.1).
    pub(super) group_named: bool,
}

impl ExpectClientHello {
    pub(super) fn new(config: Arc<ServerConfig>) -> Self {
        let mut transcript_buffer = HandshakeHashBuffer::new();
        if config.verifier.offer_client_auth() {
            transcript_buffer.set_client_auth_enabled();
        }
        Self {
            config,
            transcript: HandshakeHashOrBuffer::Buffer(transcript_buffer),
            session_id: SessionId::empty(),
            done_retry: false,
            retry_cert_with_extern_psk: false,
            retry_choice: None,
            sent_cookie: None,
            send_tickets: 0,
        }
    }

    /// Negotiates version, suite and key exchange group, chooses the
    /// certificate and hands off to the version-specific handler.
    pub(super) fn with_certified_key(
        mut self,
        sig_schemes: Vec<SignatureScheme>,
        client_hello: &ClientHelloPayload,
        m: &Message<'_>,
        cx: &mut ServerContext<'_>,
    ) -> NextStateOrError {
        self.process_cookie(client_hello, cx)?;
        // RFC 9261: what exported authenticators need after the handshake.
        cx.data.authenticators.config = Some(self.config.clone());
        cx.data.authenticators.client_sig_schemes = sig_schemes.clone();

        let tls13_enabled = self.config.supports_version(ProtocolVersion::TLSv1_3)
            && cx
                .common
                .dtls
                .as_ref()
                .is_none_or(|d| d.allows(ProtocolVersion::TLSv1_3));
        let tls12_enabled = self.config.supports_version(ProtocolVersion::TLSv1_2)
            && cx
                .common
                .dtls
                .as_ref()
                .is_none_or(|d| d.allows(ProtocolVersion::TLSv1_2));

        // RFC 9846 §4.3.1: version negotiation.
        let version = if let Some(versions) = &client_hello.extensions.supported_versions {
            // RFC 9846 §4.2.2: a TLS 1.3 ClientHello carries legacy_version
            // 0x0303; a server receiving any other value MUST abort with
            // protocol_version.
            if versions.contains(&ProtocolVersion::TLSv1_3)
                && client_hello.client_version != ProtocolVersion::TLSv1_2
            {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::ProtocolVersion,
                    PeerMisbehaved::IllegalClientHelloLegacyVersion,
                ));
            }
            if versions.contains(&ProtocolVersion::TLSv1_3) && tls13_enabled {
                ProtocolVersion::TLSv1_3
            } else if !versions.contains(&ProtocolVersion::TLSv1_2) || !tls12_enabled {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::ProtocolVersion,
                    PeerIncompatible::Tls12NotOfferedOrEnabled,
                ));
            } else {
                ProtocolVersion::TLSv1_2
            }
        } else if u16::from(client_hello.client_version) < u16::from(ProtocolVersion::TLSv1_2) {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::ProtocolVersion,
                PeerIncompatible::Tls12NotOffered,
            ));
        } else if !tls12_enabled && tls13_enabled {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::ProtocolVersion,
                PeerIncompatible::SupportedVersionsExtensionRequired,
            ));
        } else if !tls12_enabled {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::ProtocolVersion,
                PeerIncompatible::Tls12NotOfferedOrEnabled,
            ));
        } else {
            ProtocolVersion::TLSv1_2
        };

        // RFC 7507 §3: a client that fell back to a lower version than it
        // supports says so with TLS_FALLBACK_SCSV; a server able to speak a
        // higher version than the client's highest then refuses, since an
        // attacker may have caused the fallback.
        if client_hello
            .cipher_suites
            .contains(&CipherSuite::TLS_FALLBACK_SCSV)
        {
            let client_max = client_hello
                .extensions
                .supported_versions
                .as_ref()
                .and_then(|versions| {
                    versions
                        .iter()
                        .map(|v| u16::from(*v))
                        .filter(|v| !is_grease_u16(*v))
                        .max()
                })
                .unwrap_or_else(|| u16::from(client_hello.client_version));
            let our_max = if tls13_enabled {
                ProtocolVersion::TLSv1_3
            } else {
                ProtocolVersion::TLSv1_2
            };
            if client_max < u16::from(our_max) {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::InappropriateFallback,
                    PeerMisbehaved::InappropriateFallback,
                ));
            }
        }

        crate::quic::tls::require_tls13(cx.common, version)?;
        crate::tls13::dtls::require_enabled_version(cx.common, version)?;
        if version == ProtocolVersion::TLSv1_3 {
            cert_with_extern_psk::check_client_hello(
                cx.common,
                &client_hello.extensions,
                self.done_retry.then_some(self.retry_cert_with_extern_psk),
            )?;
            cert_with_extern_psk::reject_tickets(
                cx.common,
                &self.config,
                &client_hello.extensions,
            )?;
        }
        if self.config.require_cert_with_extern_psk
            && (version != ProtocolVersion::TLSv1_3
                || client_hello.extensions.cert_with_extern_psk.is_none())
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::CertWithExternPskRequired,
            ));
        }
        if let Some(dtls) = &mut cx.common.dtls {
            dtls.select_version(version);
        }
        if version == ProtocolVersion::TLSv1_3 {
            crate::tls13::dtls::read_client_hello(cx.common, client_hello)?;
        }
        #[cfg(feature = "tls12")]
        if version == ProtocolVersion::TLSv1_2
            && cx.common.is_dtls()
            && self.dtls12_retry(client_hello, cx)?
        {
            return Ok(Box::new(self));
        }
        cx.common.negotiated_version = Some(version);

        // RFC 8446 §4.1.2: compression must be null only.
        if !client_hello
            .compression_methods
            .contains(&Compression::Null)
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerIncompatible::NullCompressionRequired,
            ));
        }
        if version == ProtocolVersion::TLSv1_3 && client_hello.compression_methods.len() != 1 {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::OfferedIncorrectCompressions,
            ));
        }
        if version == ProtocolVersion::TLSv1_2 && client_hello.early_data_offered() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::UnsupportedExtension,
                PeerMisbehaved::OfferedEarlyDataWithOldProtocolVersion,
            ));
        }

        // RFC 8449: once we answer the client's record_size_limit (in the
        // TLS 1.3 EncryptedExtensions or the TLS 1.2 ServerHello), each
        // side's protected records respect the other's limit. This runs
        // again for a second ClientHello. Not on DTLS, whose records do
        // not honour it yet.
        if !cx.common.is_dtls()
            && !cx.common.is_quic()
            && let Some(theirs) = client_hello.extensions.record_size_limit
        {
            if let Some(ours) = record_size_limit_ack(&self.config, client_hello, version) {
                cx.common.apply_record_size_limits(
                    ours,
                    theirs,
                    version == ProtocolVersion::TLSv1_3,
                )?;
            } else {
                cx.common.validate_peer_record_size_limit(theirs)?;
            }
        }

        // On a server configured with external PSKs, a TLS 1.3 ClientHello
        // that offers a PSK we may accept (with psk_dhe_ke, the only mode we
        // use) can do without a certificate: whether one is needed is
        // decided once a PSK is, or is not, selected (RFC 9846 §4.3.11).
        // Other servers keep failing at once without a certificate.
        let psk_may_authenticate = version == ProtocolVersion::TLSv1_3
            && self.config.external_psks.is_some()
            && client_hello.extensions.preshared_key.is_some()
            && client_hello
                .extensions
                .psk_modes
                .as_ref()
                .is_some_and(|modes| modes.contains(&PskKeyExchangeMode::PSK_DHE_KE));

        // Choose the certificate. RFC 9846 §4.3.3: a client that wants
        // certificate authentication sends signature_algorithms; one that
        // offered only a PSK may omit it (see `process_client_hello`).
        // The resolver may say it chose with the client's trusted_ca_keys
        // (RFC 6066 §6); only a full TLS 1.2 handshake acts on that.
        let trusted_ca_keys_ack = core::sync::atomic::AtomicBool::new(false);
        let certkey = if sig_schemes.is_empty() {
            None
        } else {
            self.config.cert_resolver.resolve(
                ClientHello::new(cx.data.sni.as_ref(), &sig_schemes, client_hello)
                    .with_trusted_ca_keys_ack(&trusted_ca_keys_ack),
            )
        };
        if sig_schemes.is_empty() && !psk_may_authenticate {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::MissingExtension,
                PeerIncompatible::SignatureAlgorithmsExtensionRequired,
            ));
        }
        if certkey.is_none() && !psk_may_authenticate {
            return Err(no_server_certificate(cx));
        }
        let certkey = certkey
            .as_deref()
            .map(ActiveCertifiedKey::from_certified_key);

        // RFC 7250: certificate types, for the server's and the client's
        // credentials.
        let cert_types = NegotiatedCertTypes {
            server: negotiate_cert_type(
                client_hello
                    .extensions
                    .server_certificate_types
                    .as_deref()
                    .unwrap_or_default(),
                self.config.cert_resolver.only_raw_public_keys(),
                cx,
            )?,
            client: negotiate_cert_type(
                client_hello
                    .extensions
                    .client_certificate_types
                    .as_deref()
                    .unwrap_or_default(),
                self.config.verifier.requires_raw_public_keys(),
                cx,
            )?,
        };

        // ALPN (RFC 7301 §3.2): server preference among the client's offers.
        if let Some(offered) = client_hello.alpn_protocols() {
            let selected = self
                .config
                .alpn_protocols
                .iter()
                .find(|ours| {
                    offered
                        .iter()
                        .any(|theirs| theirs.as_ref() == ours.as_slice())
                })
                .cloned();
            match selected {
                Some(proto) => cx.common.alpn_protocol = Some(proto),
                None if !self.config.alpn_protocols.is_empty() => {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::NoApplicationProtocol,
                        Error::NoApplicationProtocol,
                    ));
                }
                None => {}
            }
        }
        let offered = client_hello.alpn_protocols().is_some();
        crate::quic::tls::require_alpn(cx.common, !self.config.alpn_protocols.is_empty(), offered)?;

        // Key exchange groups (RFC 8446 §4.2.7, RFC 8422 §5.1.1).
        // RFC 8422 §5.1: without the extension no ECC suite may be
        // negotiated, and ECC suites are all there is (missing_extension is
        // a TLS 1.3 alert).
        let client_groups = client_hello.named_groups().ok_or_else(|| {
            cx.common.send_fatal_alert(
                if version == ProtocolVersion::TLSv1_3 {
                    AlertDescription::MissingExtension
                } else {
                    AlertDescription::HandshakeFailure
                },
                PeerIncompatible::NamedGroupsExtensionRequired,
            )
        })?;
        if version == ProtocolVersion::TLSv1_2
            && let Some(formats) = &client_hello.extensions.ec_point_formats
            && !formats.contains(&ECPointFormat::Uncompressed)
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerIncompatible::UncompressedEcPointsRequired,
            ));
        }
        // RFC 9846 §4.2.4: after a HelloRetryRequest, the second
        // ClientHello answers it with TLS 1.3, a single key share for the
        // group it selected, and still offers the cipher suite it selected.
        // A HelloRetryRequest that named no group (DTLS, asking for its
        // cookie only) leaves the shares as they were: one for the group
        // selected from them must still be there.
        if let Some(choice) = &self.retry_choice {
            let follows_retry = client_hello.key_shares().is_some_and(|shares| {
                let group = choice.group.name();
                match choice.group_named {
                    true => shares.len() == 1 && shares[0].group == group,
                    false => shares.iter().any(|share| share.group == group),
                }
            });
            if version != ProtocolVersion::TLSv1_3 || !follows_retry {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::RefusedToFollowHelloRetryRequest,
                ));
            }
            if !client_hello
                .cipher_suites
                .contains(&choice.suite.common.suite)
            {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::CipherSuiteDifferedOnRetry,
                ));
            }
        }
        let selected_kxg = match &self.retry_choice {
            Some(choice) => Some(choice.group),
            None => choose_kx_group(
                self.config.kx_groups(),
                client_groups,
                client_hello,
                version,
            ),
        }
        .ok_or_else(|| {
            cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::NoKxGroupsInCommon,
            )
        })?;
        cx.common.kx_state = KxState::Started(selected_kxg);

        // Cipher suite: suitable for the version, the certificate's key type
        // and the key exchange algorithms available. Without a certificate
        // only TLS 1.3, whose suites are independent of it, gets here.
        let sigalg = certkey.as_ref().map(|k| k.get_key().algorithm());
        let kx_algo = selected_kxg.name().key_exchange_algorithm();
        // RFC 8422 §5.3: in TLS 1.2 the server must respect the client's
        // curves for the certificate too; an ECDSA certificate on a curve
        // the client did not list rules out every ECDSA suite. (TLS 1.3
        // binds the certificate's curve through signature_algorithms.)
        let ecdsa_cert_usable = version != ProtocolVersion::TLSv1_2
            || certkey
                .as_ref()
                .and_then(|k| ecdsa_certificate_curve(k.get_key()))
                .is_none_or(|curve| client_groups.contains(&curve));
        // RFC 7366 §2 and RFC 9325 §4.2: a block cipher suite is only
        // usable with Encrypt-then-MAC unless the configuration allows
        // MAC-then-encrypt.
        let client_offers_etm = client_hello.extensions.encrypt_then_mac.is_some();
        let block_ciphers_usable = client_offers_etm || self.config.allow_mac_then_encrypt;
        let mut suitable: Vec<SupportedCipherSuite> = self
            .config
            .provider
            .cipher_suites
            .iter()
            .copied()
            .filter(|suite| suite.version().version == version)
            .filter(|suite| sigalg.is_none_or(|alg| suite.usable_for_signature_algorithm(alg)))
            .filter(|suite| {
                ecdsa_cert_usable
                    || !suite.usable_for_signature_algorithm(SignatureAlgorithm::ECDSA)
            })
            .filter(|suite| {
                suite.usable_for_kx_algorithm(kx_algo) || kx_algo != KeyExchangeAlgorithm::ECDHE
            })
            .filter(|suite| block_ciphers_usable || !suite.is_tls12_block_cipher())
            // RFC 9001 §5.3: QUIC needs a header protection scheme.
            .filter(|suite| !cx.common.is_quic() || suite.usable_for_quic())
            // RFC 9147 §4.2.3, §4.5.3: DTLS needs record number encryption,
            // and no CCM_8 suite.
            .filter(|suite| !cx.common.is_dtls() || suite.usable_for_dtls())
            .collect();

        // External PSKs the client offered (RFC 9846 §4.3.11). The server
        // "MUST ensure that it selects a compatible PSK (if any) and cipher
        // suite": the first offered external PSK usable with some suite we
        // could pick narrows the choice to the suites it is usable with
        // (after a HelloRetryRequest the suite is already fixed).
        let external_psks = match (
            &self.config.external_psks,
            &client_hello.extensions.preshared_key,
        ) {
            (Some(resolver), Some(offer)) if psk_may_authenticate => {
                crate::psk::external_psk_candidates(
                    &**resolver,
                    offer
                        .identities
                        .iter()
                        .zip(&offer.binders)
                        .map(|(id, binder)| (id.identity.0.as_slice(), binder.as_ref().len())),
                    cx.data.sni.as_ref(),
                    cx.common.alpn_protocol.as_deref(),
                    crate::tls13::key_schedule::Protocol::of(cx.common),
                )
            }
            _ => Vec::new(),
        };
        if self.retry_choice.is_none()
            && let Some(first) = external_psks.iter().find(|candidate| {
                suitable.iter().any(|s| {
                    client_hello.cipher_suites.contains(&s.suite())
                        && s.tls13().is_some_and(|t| candidate.compatible_with(t))
                })
            })
        {
            suitable.retain(|s| s.tls13().is_some_and(|t| first.compatible_with(t)));
        }

        // Preferred suites first, then the non-preferred tier (RFC 9846
        // optional suites); within a tier, the client's order unless
        // `ignore_client_order`.
        let retry_suite = self
            .retry_choice
            .map(|choice| SupportedCipherSuite::Tls13(choice.suite));
        let suite = retry_suite
            .into_iter()
            .find(|s| suitable.contains(s))
            .or_else(|| {
                // The HelloRetryRequest's suite is no longer usable: the
                // retry changed what the suite choice depends on.
                if retry_suite.is_some() {
                    return None;
                }
                [false, true].into_iter().find_map(|non_preferred| {
                    let tier: Vec<SupportedCipherSuite> = suitable
                        .iter()
                        .copied()
                        .filter(|s| s.suite().is_non_preferred() == non_preferred)
                        .collect();
                    if self.config.ignore_client_order {
                        tier.iter()
                            .copied()
                            .find(|s| client_hello.cipher_suites.contains(&s.suite()))
                    } else {
                        client_hello.cipher_suites.iter().find_map(|offered| {
                            tier.iter().copied().find(|s| s.suite() == *offered)
                        })
                    }
                })
            })
            .ok_or_else(|| {
                if retry_suite.is_some() {
                    cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::CipherSuiteDifferedOnRetry,
                    )
                } else {
                    cx.common.send_fatal_alert(
                        AlertDescription::HandshakeFailure,
                        PeerIncompatible::NoCipherSuitesInCommon,
                    )
                }
            })?;
        debug!("decided upon suite {:?}", suite.suite());
        cx.common.suite = Some(suite);

        let transcript = match self.transcript {
            HandshakeHashOrBuffer::Buffer(buffer) => buffer.start_hash(suite.hash_provider()),
            HandshakeHashOrBuffer::Hash(hash)
                if hash.algorithm() == suite.hash_provider().algorithm() =>
            {
                hash
            }
            HandshakeHashOrBuffer::Hash(_) => {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::HandshakeHashVariedAfterRetry,
                ));
            }
        };

        let randoms = ConnectionRandoms::new(
            client_hello.random,
            Random::new(self.config.provider.secure_random)?,
        );

        match suite {
            SupportedCipherSuite::Tls13(suite) => tls13::CompleteClientHelloHandling {
                config: self.config,
                transcript,
                suite,
                randoms,
                done_retry: self.done_retry,
                send_tickets: self.send_tickets,
                cert_types,
                external_psks,
            }
            .handle_client_hello(
                cx,
                certkey,
                m,
                client_hello,
                selected_kxg,
                sig_schemes,
            ),
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(suite) => {
                // External PSKs exist only in TLS 1.3.
                if self.config.require_external_psk {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::HandshakeFailure,
                        PeerIncompatible::ExternalPskRequired,
                    ));
                }
                // Only a TLS 1.3 handshake may go without a certificate.
                let Some(certkey) = certkey else {
                    return Err(no_server_certificate(cx));
                };
                let using_ems = client_hello.ems_support_offered();
                if (self.config.require_ems || cx.common.is_dtls()) && !using_ems {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::HandshakeFailure,
                        PeerIncompatible::ExtendedMasterSecretExtensionRequired,
                    ));
                }
                // RFC 7366 §3: acknowledged for block cipher suites only.
                let using_etm = client_offers_etm && suite.record.is_block_cipher();
                super::tls12::CompleteClientHelloHandling {
                    config: self.config,
                    transcript,
                    session_id: self.session_id,
                    suite,
                    using_ems,
                    using_etm,
                    randoms,
                    send_ticket: self.send_tickets > 0,
                    cert_types,
                    trusted_ca_keys_ack: trusted_ca_keys_ack.into_inner(),
                }
                .handle_client_hello(
                    cx,
                    certkey,
                    m,
                    client_hello,
                    selected_kxg,
                    sig_schemes,
                    tls13_enabled,
                )
            }
        }
    }
}

/// Fails the handshake for want of a server certificate.
///
/// RFC 9325 §3.7 (RFC 6066 §3): a server name the server does not serve
/// gets unrecognized_name.
pub(super) fn no_server_certificate(cx: &mut ServerContext<'_>) -> Error {
    cx.common.send_fatal_alert(
        if cx.data.sni.is_some() {
            AlertDescription::UnrecognisedName
        } else {
            AlertDescription::AccessDenied
        },
        Error::general("no server certificate chain resolved"),
    )
}

impl State<ServerConnectionData> for ExpectClientHello {
    fn handle(self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        // RFC 9846 §4.3.2: a stateless server may see the client's
        // change_cipher_spec ahead of a second ClientHello on a fresh
        // connection; `process_cookie` refuses it ahead of any other.
        if let MessagePayload::ChangeCipherSpec(_) = &m.payload
            && !self.done_retry
            && self.config.hello_retry_cookies.is_some()
        {
            cx.common.process_middlebox_ccs()?;
            return Ok(self);
        }
        // RFC 9849 §7.1: decide on ECH before anything else; an accepted
        // offer replaces the ClientHello with the inner one.
        let m = match crate::ech::server::process_client_hello(
            self.config.ech_role(),
            &mut cx.data.ech,
            cx.common,
            &m,
            self.done_retry,
        )? {
            Some(inner) => inner,
            None => m,
        };
        let (client_hello, sig_schemes) = process_client_hello(&m, self.done_retry, cx)?;
        self.with_certified_key(sig_schemes, client_hello, &m, cx)
    }
}

/// Validates the parts of a ClientHello that do not depend on configuration
/// and records the server name.
pub(super) fn process_client_hello<'a>(
    m: &'a Message<'_>,
    done_retry: bool,
    cx: &mut ServerContext<'_>,
) -> Result<(&'a ClientHelloPayload, Vec<SignatureScheme>), Error> {
    let client_hello =
        require_handshake_msg!(m, HandshakeType::ClientHello, HandshakePayload::ClientHello)?;
    trace!("we got a clienthello {:?}", client_hello);

    if client_hello.has_duplicate_key_share() {
        return Err(cx.common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::OfferedDuplicateKeyShares,
        ));
    }
    if client_hello.has_duplicate_certificate_compression() {
        return Err(cx.common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::OfferedDuplicateCertificateCompressions,
        ));
    }

    crate::quic::tls::read_client_hello(cx.common, client_hello)?;
    // Preserve the default DTLS 1.3 validation order before cookie handling.
    // A mixed endpoint checks again once its configured version is selected.
    if cx
        .common
        .dtls
        .as_ref()
        .is_some_and(|d| !d.allows(ProtocolVersion::TLSv1_2))
    {
        crate::tls13::dtls::read_client_hello(cx.common, client_hello)?;
    }

    // RFC 8446 §4.1.2: the second ClientHello must repeat the server name.
    let sni = client_hello.sni().cloned();
    if done_retry {
        if cx.data.sni != sni {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::ServerNameDifferedOnRetry,
            ));
        }
    } else {
        cx.data.sni = sni;
    }

    // RFC 5246 §7.4.1.4.1 lets a TLS 1.2 client omit signature_algorithms
    // and implies SHA-1, which RFC 9155 forbids; so the extension is
    // required in both versions (missing_extension is a TLS 1.3 alert).
    let offers_tls13 = client_hello
        .extensions
        .supported_versions
        .as_ref()
        .is_some_and(|v| v.contains(&ProtocolVersion::TLSv1_3));
    // RFC 9846 §4.3.3 requires signature_algorithms of a client that wants
    // certificate authentication: one that offers only TLS 1.3 and a PSK may
    // leave it out, and is then served only with that PSK.
    let psk_only = client_hello.extensions.preshared_key.is_some()
        && client_hello
            .extensions
            .supported_versions
            .as_ref()
            .is_some_and(|v| v.iter().all(|v| *v == ProtocolVersion::TLSv1_3) && !v.is_empty());
    if psk_only && client_hello.signature_schemes().is_none() {
        return Ok((client_hello, Vec::new()));
    }
    let sig_schemes = client_hello
        .signature_schemes()
        .ok_or_else(|| {
            cx.common.send_fatal_alert(
                if offers_tls13 {
                    AlertDescription::MissingExtension
                } else {
                    AlertDescription::HandshakeFailure
                },
                PeerIncompatible::SignatureAlgorithmsExtensionRequired,
            )
        })?
        .to_vec();

    Ok((client_hello, sig_schemes))
}
