//! The server handshake up to version and suite negotiation.

use alloc::boxed::Box;
use alloc::vec::Vec;

use browntls_pki::DnsName;

use super::common::ActiveCertifiedKey;
use super::server_conn::{ClientHello, ServerConfig, ServerConnectionData};
use super::tls13;
use crate::common_state::{ConnectionRandoms, KxState};
use crate::conn::{Context, State};
use crate::crypto::{KeyExchangeAlgorithm, SupportedKxGroup};
use crate::enums::{AlertDescription, HandshakeType, ProtocolVersion, SignatureScheme};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
use crate::log::{debug, trace};
use crate::msgs::enums::{Compression, ECPointFormat, NamedGroup};
use crate::msgs::handshake::{ClientHelloPayload, HandshakePayload, Random, SessionId};
use crate::msgs::message::Message;
use crate::msgs::persist::ServerSessionValue;
use crate::suites::SupportedCipherSuite;
use crate::sync::Arc;

pub(super) type NextState = Box<dyn State<ServerConnectionData>>;
pub(super) type NextStateOrError = Result<NextState, Error>;
pub(super) type ServerContext<'a> = Context<'a, ServerConnectionData>;

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
    pub(super) using_ems: bool,
    pub(super) done_retry: bool,
    pub(super) send_tickets: usize,
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
            using_ems: false,
            done_retry: false,
            send_tickets: 0,
        }
    }

    /// Negotiates version, suite and key exchange group, chooses the
    /// certificate and hands off to the version-specific handler.
    pub(super) fn with_certified_key(
        self,
        sig_schemes: Vec<SignatureScheme>,
        client_hello: &ClientHelloPayload,
        m: &Message<'_>,
        cx: &mut ServerContext<'_>,
    ) -> NextStateOrError {
        let tls13_enabled = self.config.supports_version(ProtocolVersion::TLSv1_3);
        let tls12_enabled = self.config.supports_version(ProtocolVersion::TLSv1_2);

        // RFC 8446 §4.2.1: version negotiation.
        let version = if let Some(versions) = &client_hello.extensions.supported_versions {
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

        // Choose the certificate.
        let certkey = self
            .config
            .cert_resolver
            .resolve(ClientHello::new(
                cx.data.sni.as_ref(),
                &sig_schemes,
                client_hello,
            ))
            .ok_or_else(|| {
                cx.common.send_fatal_alert(
                    AlertDescription::AccessDenied,
                    Error::general("no server certificate chain resolved"),
                )
            })?;
        let certkey = ActiveCertifiedKey::from_certified_key(&certkey);

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
        let client_groups = client_hello.named_groups().ok_or_else(|| {
            cx.common.send_fatal_alert(
                AlertDescription::MissingExtension,
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
        let selected_kxg = choose_kx_group(
            self.config.kx_groups(),
            client_groups,
            client_hello,
            version,
        )
        .ok_or_else(|| {
            cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::NoKxGroupsInCommon,
            )
        })?;
        cx.common.kx_state = KxState::Started(selected_kxg);

        // Cipher suite: suitable for the version, the certificate's key type
        // and the key exchange algorithms available.
        let sigalg = certkey.get_key().algorithm();
        let kx_algo = selected_kxg.name().key_exchange_algorithm();
        let suitable: Vec<SupportedCipherSuite> = self
            .config
            .provider
            .cipher_suites
            .iter()
            .copied()
            .filter(|suite| suite.version().version == version)
            .filter(|suite| suite.usable_for_signature_algorithm(sigalg))
            .filter(|suite| {
                suite.usable_for_kx_algorithm(kx_algo) || kx_algo != KeyExchangeAlgorithm::ECDHE
            })
            .collect();

        let suite = if self.config.ignore_client_order {
            suitable
                .iter()
                .copied()
                .find(|s| client_hello.cipher_suites.contains(&s.suite()))
        } else {
            client_hello
                .cipher_suites
                .iter()
                .find_map(|offered| suitable.iter().copied().find(|s| s.suite() == *offered))
        }
        .ok_or_else(|| {
            cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::NoCipherSuitesInCommon,
            )
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
                let using_ems = client_hello.ems_support_offered();
                if self.config.require_ems && !using_ems {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::HandshakeFailure,
                        PeerIncompatible::ExtendedMasterSecretExtensionRequired,
                    ));
                }
                // TODO(tls12): dispatch to the TLS 1.2 server handshake.
                let _ = (
                    suite,
                    using_ems,
                    transcript,
                    randoms,
                    certkey,
                    selected_kxg,
                    m,
                    tls13_enabled,
                );
                Err(cx.common.send_fatal_alert(
                    AlertDescription::InternalError,
                    Error::general("TLS 1.2 server handshake not yet implemented"),
                ))
            }
        }
    }
}

/// Picks the key exchange group: for TLS 1.3, the first of our groups the
/// client sent a key share for, otherwise the first group both support (a
/// HelloRetryRequest will ask for its share).
fn choose_kx_group(
    ours: &[&'static dyn SupportedKxGroup],
    theirs: &[NamedGroup],
    client_hello: &ClientHelloPayload,
    version: ProtocolVersion,
) -> Option<&'static dyn SupportedKxGroup> {
    let usable = |g: &&'static dyn SupportedKxGroup| {
        theirs.contains(&g.name()) && g.usable_for_version(version)
    };
    if version == ProtocolVersion::TLSv1_3
        && let Some(shares) = client_hello.key_shares()
        && let Some(with_share) = ours
            .iter()
            .copied()
            .find(|g| usable(g) && shares.iter().any(|s| s.group == g.name()))
    {
        return Some(with_share);
    }
    ours.iter().copied().find(usable)
}

impl State<ServerConnectionData> for ExpectClientHello {
    fn handle(self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
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

    let sig_schemes = client_hello
        .signature_schemes()
        .ok_or_else(|| {
            cx.common.send_fatal_alert(
                AlertDescription::MissingExtension,
                PeerIncompatible::SignatureAlgorithmsExtensionRequired,
            )
        })?
        .to_vec();

    Ok((client_hello, sig_schemes))
}
