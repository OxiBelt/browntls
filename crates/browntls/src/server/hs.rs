//! The server handshake up to version and suite negotiation.

use alloc::boxed::Box;
use alloc::vec::Vec;

use browntls_pki::DnsName;

use super::common::ActiveCertifiedKey;
use super::cookie::RetryCookie;
use super::server_conn::{ClientHello, ServerConfig, ServerConnectionData};
use super::tls13;
use crate::common_state::{ConnectionRandoms, KxState};
use crate::conn::{Context, State};
use crate::crypto::{KeyExchangeAlgorithm, SupportedKxGroup};
use crate::enums::{
    AlertDescription, CertificateType, CipherSuite, HandshakeType, ProtocolVersion,
    SignatureAlgorithm, SignatureScheme,
};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
use crate::log::{debug, trace};
use crate::msgs::codec::Codec;
use crate::msgs::enums::{Compression, ECPointFormat, NamedGroup, PskKeyExchangeMode};
use crate::msgs::grease::is_grease_u16;
use crate::msgs::handshake::{
    ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, Random, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist::ServerSessionValue;
use crate::suites::SupportedCipherSuite;
use crate::sync::Arc;

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
            retry_choice: None,
            sent_cookie: None,
            send_tickets: 0,
        }
    }

    /// Checks the cookie of a second ClientHello, or continues a stateless
    /// retry (RFC 9846 §4.3.2) when a first message carries one of ours.
    fn process_cookie(
        &mut self,
        client_hello: &ClientHelloPayload,
        cx: &mut ServerContext<'_>,
    ) -> Result<(), Error> {
        let received = client_hello.extensions.cookie.as_ref().map(|c| &c.0);
        if self.done_retry {
            // The client MUST copy the cookie it was sent.
            return match (&self.sent_cookie, received) {
                (None, _) => Ok(()),
                (Some(_), None) => Err(cx.common.send_fatal_alert(
                    AlertDescription::MissingExtension,
                    PeerMisbehaved::MissingCookieInSecondClientHello,
                )),
                (Some(sent), Some(received)) if sent == received => Ok(()),
                (Some(_), Some(_)) => Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::InvalidHelloRetryRequestCookie,
                )),
            };
        }
        match (received, &self.config.hello_retry_cookies) {
            (Some(cookie), Some(sealer)) => {
                let sealer = sealer.clone();
                self.resume_from_cookie(&*sealer, cookie, client_hello, cx)
            }
            // RFC 9846 §4.3.2: a stateless server ignores change_cipher_spec
            // records ahead of a second ClientHello; ahead of any other it
            // is unexpected.
            _ if cx.common.received_middlebox_ccs > 0 => Err(cx.common.send_fatal_alert(
                AlertDescription::UnexpectedMessage,
                PeerMisbehaved::IllegalMiddleboxChangeCipherSpec,
            )),
            // Without a sealer we issue no cookies, and ignore one a client
            // sends in its first ClientHello.
            _ => Ok(()),
        }
    }

    /// Restores the state a HelloRetryRequest left in its cookie, so this
    /// connection continues the handshake from the second ClientHello.
    fn resume_from_cookie(
        &mut self,
        sealer: &dyn super::server_conn::ProducesTickets,
        cookie: &[u8],
        client_hello: &ClientHelloPayload,
        cx: &mut ServerContext<'_>,
    ) -> Result<(), Error> {
        // Without a clock the cookie cannot be checked: fail closed, with
        // an explicit alert also on the Acceptor path.
        let now = match self.config.current_time() {
            Ok(now) => now.as_secs(),
            Err(err) => {
                return Err(cx
                    .common
                    .send_fatal_alert(AlertDescription::InternalError, err));
            }
        };
        let invalid = |cx: &mut ServerContext<'_>| {
            cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::InvalidHelloRetryRequestCookie,
            )
        };
        let Some(state) = RetryCookie::open(sealer, cookie, now) else {
            return Err(invalid(cx));
        };
        // We issue no cookie when the first ClientHello offered ECH, so a
        // second one may not offer it either (RFC 9849 §7.1.1).
        if !matches!(cx.data.ech, crate::ech::server::ServerEch::NotOffered) {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::EchChangedOnRetry,
            ));
        }
        // The configuration may have changed since the cookie was issued.
        let Some(suite) = self
            .config
            .find_cipher_suite(state.suite)
            .and_then(|s| s.tls13())
        else {
            return Err(invalid(cx));
        };
        let Some(group) =
            self.config.kx_groups().iter().copied().find(|g| {
                g.name() == state.group && g.usable_for_version(ProtocolVersion::TLSv1_3)
            })
        else {
            return Err(invalid(cx));
        };
        if state.client_hello_hash.len() != suite.common.hash_provider.output_len() {
            return Err(invalid(cx));
        }
        // RFC 9846 §4.2.2: the second ClientHello repeats the first, apart
        // from what the HelloRetryRequest asked to change.
        if client_hello.session_id != state.session_id {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::RefusedToFollowHelloRetryRequest,
            ));
        }
        let sni = cx
            .data
            .sni
            .as_ref()
            .map(|name| name.as_ref().as_bytes())
            .unwrap_or_default();
        if sni != state.server_name.as_slice() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::ServerNameDifferedOnRetry,
            ));
        }

        // RFC 9846 §4.5: message_hash(Hash(ClientHello1)), then the
        // HelloRetryRequest exactly as sent (it is rebuilt from the cookie).
        let mut transcript = HandshakeHashBuffer::new().start_hash(suite.common.hash_provider);
        transcript.add(
            &HandshakeMessagePayload::build_handshake_hash(&state.client_hello_hash).get_encoding(),
        );
        transcript.add_message(&tls13::hello_retry_request_message(
            suite,
            state.session_id,
            group.name(),
            Some(cookie.to_vec()),
        ));
        debug!("continuing a stateless HelloRetryRequest from its cookie");
        self.transcript = HandshakeHashOrBuffer::Hash(transcript);
        self.done_retry = true;
        self.retry_choice = Some(RetryChoice { suite, group });
        self.sent_cookie = Some(cookie.to_vec());
        cx.common.handshake_kind =
            Some(crate::common_state::HandshakeKind::FullWithHelloRetryRequest);
        Ok(())
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

        let tls13_enabled = self.config.supports_version(ProtocolVersion::TLSv1_3);
        let tls12_enabled = self.config.supports_version(ProtocolVersion::TLSv1_2);

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
        // again for a second ClientHello.
        if let (Some(ours), Some(theirs)) = (
            record_size_limit_ack(&self.config, client_hello, version),
            client_hello.extensions.record_size_limit,
        ) {
            cx.common.apply_record_size_limits(
                ours,
                theirs,
                version == ProtocolVersion::TLSv1_3,
            )?;
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
        let certkey = if sig_schemes.is_empty() {
            None
        } else {
            self.config.cert_resolver.resolve(ClientHello::new(
                cx.data.sni.as_ref(),
                &sig_schemes,
                client_hello,
            ))
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

        // RFC 7250: certificate types, for the server's and the client's credentials.
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
        if let Some(choice) = &self.retry_choice {
            let single_share_for_group = client_hello
                .key_shares()
                .is_some_and(|shares| shares.len() == 1 && shares[0].group == choice.group.name());
            if version != ProtocolVersion::TLSv1_3 || !single_share_for_group {
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
                if self.config.require_ems && !using_ems {
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

/// The `record_size_limit` to send for `version` (RFC 8449 §4): our
/// configured value, clamped to the protocol maximum, when the client sent
/// the extension and the configuration has one.
pub(super) fn record_size_limit_ack(
    config: &ServerConfig,
    client_hello: &ClientHelloPayload,
    version: ProtocolVersion,
) -> Option<u16> {
    client_hello.extensions.record_size_limit?;
    let max = crate::common_state::max_record_size_limit(version == ProtocolVersion::TLSv1_3);
    config.record_size_limit.map(|limit| limit.min(max))
}

/// How many TLS 1.3 tickets to send, and the RFC 9149 `expected_count` to
/// announce in EncryptedExtensions when the client sent `ticket_request`.
///
/// RFC 9846 §4.7.1: tickets go only to a client whose ClientHello carried a
/// suitable `psk_key_exchange_modes`; `psk_dhe_ke` is the only mode we
/// resume with. RFC 9149 §3: no more tickets than the client asked for, for
/// a resumed session (`resumption_count`) or a new one
/// (`new_session_count`, also when we declined the offered PSK), and never
/// more than `send_tls13_tickets`, our own maximum.
pub(super) fn tls13_tickets_to_send(
    config: &ServerConfig,
    client_hello: &ClientHelloPayload,
    resumed: bool,
) -> (usize, Option<u8>) {
    let client_takes_tickets = client_hello
        .extensions
        .psk_modes
        .as_ref()
        .is_some_and(|modes| modes.contains(&PskKeyExchangeMode::PSK_DHE_KE));
    let ours = if client_takes_tickets {
        config.send_tls13_tickets
    } else {
        0
    };
    match client_hello.extensions.ticket_request {
        Some(request) => {
            let wanted = match resumed {
                true => request.resumption_count,
                false => request.new_session_count,
            };
            let count = ours.min(usize::from(wanted));
            // `count` is at most `wanted`, a u8.
            (count, u8::try_from(count).ok())
        }
        None => (ours, None),
    }
}

/// The RFC 7250 certificate types to announce, one per direction; `None`
/// when the client did not raise the question.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct NegotiatedCertTypes {
    pub(super) client: Option<CertificateType>,
    pub(super) server: Option<CertificateType>,
}

/// Picks a certificate type from what the client supports. A side configured
/// for raw public keys only accepts a client that offers them; otherwise X.509
/// is used (and the client must allow it when it sent the extension at all).
fn negotiate_cert_type(
    client_supports: &[CertificateType],
    requires_raw_keys: bool,
    cx: &mut ServerContext<'_>,
) -> Result<Option<CertificateType>, Error> {
    let raw = client_supports.contains(&CertificateType::RawPublicKey);
    let x509 = client_supports.contains(&CertificateType::X509);
    match (requires_raw_keys, raw, x509) {
        (true, true, _) => Ok(Some(CertificateType::RawPublicKey)),
        (false, _, true) => Ok(Some(CertificateType::X509)),
        (false, false, false) => Ok(None),
        (true, false, _) | (false, true, false) => Err(cx.common.send_fatal_alert(
            AlertDescription::HandshakeFailure,
            PeerIncompatible::IncorrectCertificateTypeExtension,
        )),
    }
}

/// Picks the key exchange group, preferred groups before the non-preferred
/// tier ([`NamedGroup::is_non_preferred`]): within a tier, for TLS 1.3 the
/// first of our groups the client sent a key share for, otherwise the first
/// group both support (a HelloRetryRequest will ask for its share). A key
/// share for a non-preferred group is therefore not accepted while a
/// preferred group is mutually supported.
fn choose_kx_group(
    ours: &[&'static dyn SupportedKxGroup],
    theirs: &[NamedGroup],
    client_hello: &ClientHelloPayload,
    version: ProtocolVersion,
) -> Option<&'static dyn SupportedKxGroup> {
    let usable = |g: &&'static dyn SupportedKxGroup| {
        theirs.contains(&g.name()) && g.usable_for_version(version)
    };
    for non_preferred in [false, true] {
        let in_tier = |g: &&'static dyn SupportedKxGroup| {
            usable(g) && g.name().is_non_preferred() == non_preferred
        };
        if version == ProtocolVersion::TLSv1_3
            && let Some(shares) = client_hello.key_shares()
            && let Some(with_share) = ours
                .iter()
                .copied()
                .find(|g| in_tier(g) && shares.iter().any(|s| s.group == g.name()))
        {
            return Some(with_share);
        }
        if let Some(group) = ours.iter().copied().find(in_tier) {
            return Some(group);
        }
    }
    None
}

/// Our groups usable with `version`, in preference order: the preferred
/// tier, then the non-preferred one, each in configuration order.
pub(super) fn kx_groups_by_preference(
    ours: &[&'static dyn SupportedKxGroup],
    version: ProtocolVersion,
) -> Vec<&'static dyn SupportedKxGroup> {
    [false, true]
        .into_iter()
        .flat_map(|non_preferred| {
            ours.iter().copied().filter(move |g| {
                g.usable_for_version(version) && g.name().is_non_preferred() == non_preferred
            })
        })
        .collect()
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
            self.config.ech.as_deref(),
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
