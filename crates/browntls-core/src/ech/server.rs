//! The server side of ECH (RFC 9849 §7): shared mode, and the decryption
//! that the client-facing server of split mode ([`super::split`]) shares
//! with it, and the back-end server of split mode.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use super::codec::{
    EchClientHello, client_hello_extensions_offset, find_extension, raw_extensions,
};
use super::{EchServerConfig, EchStatus, hpke_info};
use crate::common_state::CommonState;
use crate::crypto::hpke::{EncapsulatedSecret, HpkeOpener, HpkeSymmetricCipherSuite};
use crate::enums::{AlertDescription, ProtocolVersion};
use crate::error::{Error, PeerMisbehaved};
use crate::key_log::KeyLog;
use crate::msgs::base::Payload;
use crate::msgs::codec::Reader;
use crate::msgs::handshake::{
    ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};

const ECH: u16 = 0xfe0d;
const OUTER_EXTENSIONS: u16 = 0xfd00;

/// The part a server plays in ECH (RFC 9849 §7).
#[derive(Clone, Copy)]
pub(crate) enum Role<'a> {
    /// ECH is not configured: the extension is ignored.
    Off,
    /// Shared mode: decrypt with these keys and complete the handshake.
    Shared(&'a EchServerConfig),
    /// The back-end server of split mode (§7.2): a client-facing server
    /// has already decrypted the ClientHello.
    Backend,
}

/// A fatal error and the alert that reports it.
#[derive(Debug, PartialEq)]
pub(crate) struct Fatal(pub(crate) AlertDescription, pub(crate) Error);

impl Fatal {
    fn illegal(why: PeerMisbehaved) -> Self {
        Self(AlertDescription::IllegalParameter, why.into())
    }

    /// Sends the alert on `common` and returns the error.
    pub(crate) fn send(self, common: &mut CommonState) -> Error {
        common.send_fatal_alert(self.0, self.1)
    }
}

/// What the server decided about ECH.
#[derive(Default)]
pub(crate) enum ServerEch {
    /// No ECH extension, or no keys configured.
    #[default]
    NotOffered,
    /// An outer ECH extension that did not decrypt (GREASE, or stale keys).
    Rejected,
    /// The inner ClientHello is in use; the context opens a second one.
    Accepted(Box<Accepted>),
    /// A back-end server received an inner ClientHello from a client-facing
    /// server (§7.2): it confirms acceptance.
    Backend,
}

/// An accepted offer: the HPKE context and what a second ClientHello must
/// repeat (§7.1.1).
pub(crate) struct Accepted {
    opener: Box<dyn HpkeOpener>,
    config_id: u8,
    cipher_suite: HpkeSymmetricCipherSuite,
}

impl ServerEch {
    pub(crate) fn status(&self) -> EchStatus {
        match self {
            Self::NotOffered => EchStatus::NotOffered,
            Self::Rejected => EchStatus::Rejected,
            Self::Accepted(_) | Self::Backend => EchStatus::Accepted,
        }
    }

    /// Whether the ServerHello (and a HelloRetryRequest) confirms ECH.
    pub(crate) fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted(_) | Self::Backend)
    }
}

impl fmt::Debug for ServerEch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.status(), f)
    }
}

/// The ClientHello in a handshake message, with its encoded body (without
/// the handshake header).
pub(crate) fn client_hello<'a>(m: &'a Message<'_>) -> Option<(&'a ClientHelloPayload, &'a [u8])> {
    match &m.payload {
        MessagePayload::Handshake {
            parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(ch)),
            encoded,
        } => Some((ch, encoded.bytes().get(4..)?)),
        _ => None,
    }
}

/// Looks at a ClientHello for ECH. Returns the ClientHelloInner to continue
/// with when ECH is (still) accepted, or `None` to continue with `m`.
///
/// After a HelloRetryRequest (`done_retry`), only an accepted offer is
/// processed again, with the same HPKE context (§7.1.1).
///
/// `key_log` receives the ECH records of an offer accepted in shared mode
/// ([`open_first`]); no other role writes any.
pub(crate) fn process_client_hello(
    role: Role<'_>,
    state: &mut ServerEch,
    common: &mut CommonState,
    m: &Message<'_>,
    done_retry: bool,
    key_log: &dyn KeyLog,
) -> Result<Option<Message<'static>>, Error> {
    let Some((ch, body)) = client_hello(m) else {
        return Ok(None);
    };
    let result = match role {
        Role::Off => check_outer_extensions(ch).map(|()| None),
        Role::Backend => backend(state, ch, done_retry).map(|()| None),
        Role::Shared(config) => shared(config, state, ch, body, m.version, done_retry, key_log),
    };
    result.map_err(|fatal| fatal.send(common))
}

/// §5.1: only an EncodedClientHelloInner may carry `ech_outer_extensions`.
pub(crate) fn check_outer_extensions(ch: &ClientHelloPayload) -> Result<(), Fatal> {
    match ch.extensions.ech_outer_extensions {
        Some(_) => Err(Fatal::illegal(PeerMisbehaved::IllegalEchOuterExtensions)),
        None => Ok(()),
    }
}

fn shared(
    config: &EchServerConfig,
    state: &mut ServerEch,
    ch: &ClientHelloPayload,
    body: &[u8],
    version: ProtocolVersion,
    done_retry: bool,
    key_log: &dyn KeyLog,
) -> Result<Option<Message<'static>>, Fatal> {
    check_outer_extensions(ch)?;
    if done_retry {
        let ServerEch::Accepted(accepted) = state else {
            // §7.1.1: after rejecting, the second ClientHello is processed
            // as it is.
            return Ok(None);
        };
        return open_retry(accepted, ch, body, version).map(Some);
    }
    match open_first(config, ch, body, version, key_log)? {
        Opened::NotOffered => Ok(None),
        Opened::Rejected => {
            *state = ServerEch::Rejected;
            Ok(None)
        }
        Opened::Accepted(accepted, inner) => {
            *state = ServerEch::Accepted(accepted);
            Ok(Some(*inner))
        }
    }
}

/// The back-end server of split mode (§7, §7.2).
fn backend(state: &mut ServerEch, ch: &ClientHelloPayload, done_retry: bool) -> Result<(), Fatal> {
    check_outer_extensions(ch)?;
    let ech = &ch.extensions.encrypted_client_hello;
    if done_retry {
        return match (&*state, ech) {
            (ServerEch::Backend, Some(EchClientHello::Inner)) => check_inner_versions(ch),
            // The client-facing server forwards every second
            // ClientHelloInner with its `inner` extension (§6.1.5).
            (ServerEch::Backend, None) => Err(Fatal(
                AlertDescription::MissingExtension,
                PeerMisbehaved::MissingEchExtensionInSecondClientHello.into(),
            )),
            (ServerEch::Backend, Some(_)) => {
                Err(Fatal::illegal(PeerMisbehaved::IllegalEchClientHelloType))
            }
            // ECH appeared only in the second ClientHello.
            (_, Some(_)) => Err(Fatal::illegal(PeerMisbehaved::EchChangedOnRetry)),
            (_, None) => Ok(()),
        };
    }
    match ech {
        None => Ok(()),
        Some(EchClientHello::Inner) => {
            check_inner_versions(ch)?;
            *state = ServerEch::Backend;
            Ok(())
        }
        // §7: a back-end server never receives `outer`.
        Some(EchClientHello::Outer(_) | EchClientHello::Unknown(_)) => {
            Err(Fatal::illegal(PeerMisbehaved::IllegalEchClientHelloType))
        }
    }
}

/// §7.1: a ClientHelloInner offers nothing below TLS 1.3. The client-facing
/// server enforces this; a back-end server checks it again, so that it
/// never negotiates TLS 1.2 with an inner ClientHello, where it could not
/// confirm acceptance (§7.2).
fn check_inner_versions(ch: &ClientHelloPayload) -> Result<(), Fatal> {
    if offers_tls12_or_below(ch) {
        return Err(Fatal::illegal(PeerMisbehaved::IllegalEchInnerClientHello));
    }
    Ok(())
}

fn offers_tls12_or_below(ch: &ClientHelloPayload) -> bool {
    ch.extensions
        .supported_versions
        .as_ref()
        .is_none_or(|versions| {
            versions
                .iter()
                .any(|v| (0x0300..=0x0303).contains(&u16::from(*v)))
        })
}

/// The outcome of decrypting a first ClientHello.
pub(crate) enum Opened {
    /// No ECH extension.
    NotOffered,
    /// An outer ECH extension that did not decrypt with any candidate key.
    Rejected,
    /// The ClientHelloInner, and the context for a second one.
    Accepted(Box<Accepted>, Box<Message<'static>>),
}

/// Decrypts the ECH extension of a first ClientHello (`ch`, encoded as
/// `body`) with `config`'s keys (§7.1).
///
/// With the `key-log` feature this is the only place a server writes
/// `ECH_SECRET` and `ECH_CONFIG` (RFC 9850 §2.3), and it does so only for
/// an offer it accepts: after the context opened the payload, the public
/// name matched where that is checked, and the inner ClientHello decoded.
/// The records name the outer ClientHello's random and the configuration
/// of the key that decrypted. The KEM secret of each candidate is a local
/// of one loop iteration: a candidate that fails drops (and zeroises) it,
/// and neither [`Accepted`] nor anything else kept for the connection
/// holds it. A second ClientHello ([`open_retry`]) reuses the context and
/// writes nothing.
pub(crate) fn open_first(
    config: &EchServerConfig,
    ch: &ClientHelloPayload,
    body: &[u8],
    version: ProtocolVersion,
    key_log: &dyn KeyLog,
) -> Result<Opened, Fatal> {
    #[cfg(not(feature = "key-log"))]
    let _ = key_log;
    let outer = match &ch.extensions.encrypted_client_hello {
        None => return Ok(Opened::NotOffered),
        Some(EchClientHello::Outer(outer)) => outer,
        // §7: neither mode receives `inner` from the network.
        Some(EchClientHello::Inner | EchClientHello::Unknown(_)) => {
            return Err(Fatal::illegal(PeerMisbehaved::IllegalEchClientHelloType));
        }
    };
    let aad = outer_aad(body, outer.payload.0.len());
    let enc = EncapsulatedSecret(outer.enc.0.clone());
    // §7.1: candidates by configuration identifier, or every key when
    // configured to ignore identifiers (§10.4).
    for key in config
        .keys
        .iter()
        .filter(|k| config.trial_decryption || k.key_config.config_id == outer.config_id)
    {
        let info = hpke_info(&key.encoded);
        for hpke in key
            .suites
            .iter()
            .filter(|s| s.suite().sym == outer.cipher_suite)
        {
            #[cfg(feature = "key-log")]
            let mut kem_secret = crate::crypto::hpke::KemSecret::empty();
            #[cfg(feature = "key-log")]
            let opener = super::key_log::setup_opener(
                *hpke,
                key_log,
                &enc,
                &info,
                &key.private_key,
                &mut kem_secret,
            );
            #[cfg(not(feature = "key-log"))]
            let opener = hpke.setup_opener(&enc, &info, &key.private_key);
            let Ok(mut opener) = opener else {
                continue;
            };
            let Ok(inner) = opener.open(&aad, &outer.payload.0) else {
                continue;
            };
            // §7.1: the optional check of the outer server name against
            // the public name of the configuration that decrypted.
            if config.check_public_name
                && !ch.sni().is_some_and(|name| {
                    name.as_ref()
                        .as_bytes()
                        .eq_ignore_ascii_case(&key.public_name)
                })
            {
                return Err(Fatal::illegal(PeerMisbehaved::EchPublicNameMismatch));
            }
            let message = decode_inner(version, body, &ch.session_id, &inner)?;
            #[cfg(feature = "key-log")]
            super::key_log::emit(key_log, &ch.random.0, &kem_secret, &key.encoded);
            let accepted = Box::new(Accepted {
                opener,
                config_id: outer.config_id,
                cipher_suite: outer.cipher_suite,
            });
            return Ok(Opened::Accepted(accepted, Box::new(message)));
        }
    }
    Ok(Opened::Rejected)
}

/// Decrypts the ECH extension of a second ClientHello after an accepted
/// first one (§7.1.1).
pub(crate) fn open_retry(
    accepted: &mut Accepted,
    ch: &ClientHelloPayload,
    body: &[u8],
    version: ProtocolVersion,
) -> Result<Message<'static>, Fatal> {
    let outer = match &ch.extensions.encrypted_client_hello {
        Some(EchClientHello::Outer(outer)) => outer,
        Some(_) => return Err(Fatal::illegal(PeerMisbehaved::IllegalEchClientHelloType)),
        None => {
            return Err(Fatal(
                AlertDescription::MissingExtension,
                PeerMisbehaved::MissingEchExtensionInSecondClientHello.into(),
            ));
        }
    };
    if outer.config_id != accepted.config_id
        || outer.cipher_suite != accepted.cipher_suite
        || !outer.enc.0.is_empty()
    {
        return Err(Fatal::illegal(PeerMisbehaved::EchChangedOnRetry));
    }
    let aad = outer_aad(body, outer.payload.0.len());
    let Ok(inner) = accepted.opener.open(&aad, &outer.payload.0) else {
        return Err(Fatal(
            AlertDescription::DecryptError,
            PeerMisbehaved::EchDecryptionFailedOnRetry.into(),
        ));
    };
    decode_inner(version, body, &ch.session_id, &inner)
}

/// `ClientHelloOuterAAD` (§5.2): the outer ClientHello body as received,
/// with the ECH payload (the last `payload_len` bytes of the extension)
/// zeroed.
fn outer_aad(body: &[u8], payload_len: usize) -> Vec<u8> {
    let mut aad = body.to_vec();
    if let Some(range) = find_extension(body, client_hello_extensions_offset, ECH)
        && let Some(start) = range.end.checked_sub(payload_len)
    {
        aad[start..range.end].fill(0);
    }
    aad
}

/// Rebuilds ClientHelloInner from `encoded` (§5.1), using the outer
/// ClientHello `outer_body` for referenced extensions and its session ID,
/// and checks it (§7.1).
pub(super) fn decode_inner(
    version: ProtocolVersion,
    outer_body: &[u8],
    outer_session_id: &SessionId,
    encoded: &[u8],
) -> Result<Message<'static>, Fatal> {
    let illegal = Fatal::illegal;
    let too_short = || {
        Fatal(
            AlertDescription::DecodeError,
            crate::error::InvalidMessage::MessageTooShort.into(),
        )
    };
    let Some(parts) = split_inner(encoded) else {
        return Err(too_short());
    };
    if parts.padding.iter().any(|b| *b != 0) {
        return Err(illegal(PeerMisbehaved::IllegalEchPadding));
    }
    let Some(inner_exts) = raw_extensions(parts.extensions) else {
        return Err(too_short());
    };
    let outer_start = client_hello_extensions_offset(outer_body).unwrap_or(outer_body.len());
    let outer_block = &outer_body[outer_start..];
    let outer_exts = raw_extensions(outer_block).unwrap_or_default();

    // Linear-time expansion (Appendix A): one cursor into the outer
    // extensions, which referenced types must follow in order.
    let mut block = Vec::with_capacity(parts.extensions.len());
    let mut cursor = 0;
    for ext in &inner_exts {
        if ext.typ != OUTER_EXTENSIONS {
            block.extend_from_slice(&parts.extensions[ext.whole.clone()]);
            continue;
        }
        let list = &parts.extensions[ext.body.clone()];
        let types = match list.split_first() {
            Some((len, types))
                if usize::from(*len) == types.len()
                    && !types.is_empty()
                    && types.len() % 2 == 0 =>
            {
                types
            }
            _ => return Err(illegal(PeerMisbehaved::IllegalEchOuterExtensions)),
        };
        for typ in types.as_chunks::<2>().0 {
            let typ = u16::from_be_bytes(*typ);
            if typ == ECH {
                return Err(illegal(PeerMisbehaved::IllegalEchOuterExtensions));
            }
            let Some(found) = outer_exts[cursor..].iter().position(|o| o.typ == typ) else {
                return Err(illegal(PeerMisbehaved::IllegalEchOuterExtensions));
            };
            let o = &outer_exts[cursor + found];
            block.extend_from_slice(&outer_block[o.whole.clone()]);
            cursor += found + 1;
        }
    }
    let Ok(block_len) = u16::try_from(block.len()) else {
        return Err(illegal(PeerMisbehaved::IllegalEchOuterExtensions));
    };

    let mut body = Vec::with_capacity(encoded.len() + outer_body.len());
    body.extend_from_slice(parts.version_and_random);
    body.push(outer_session_id.as_ref().len() as u8);
    body.extend_from_slice(outer_session_id.as_ref());
    body.extend_from_slice(parts.suites_and_compression);
    body.extend_from_slice(&block_len.to_be_bytes());
    body.extend_from_slice(&block);

    let mut bytes = Vec::with_capacity(4 + body.len());
    bytes.push(1); // client_hello
    let len = body.len() as u32;
    bytes.extend_from_slice(&len.to_be_bytes()[1..]);
    bytes.extend_from_slice(&body);

    let parsed = {
        let mut r = Reader::init(&bytes);
        let parsed = HandshakeMessagePayload::read_version(&mut r, version)
            .and_then(|p| r.expect_empty("ClientHelloInner").map(|()| p))
            .map_err(|err| Fatal(AlertDescription::from(err), err.into()))?;
        parsed.into_owned()
    };
    let HandshakePayload::ClientHello(inner) = &parsed.0 else {
        return Err(illegal(PeerMisbehaved::IllegalEchInnerClientHello));
    };
    // §7.1: an `inner` extension, and no TLS 1.2 or below.
    if inner.extensions.encrypted_client_hello != Some(EchClientHello::Inner)
        || offers_tls12_or_below(inner)
    {
        return Err(illegal(PeerMisbehaved::IllegalEchInnerClientHello));
    }
    Ok(Message {
        version,
        payload: MessagePayload::Handshake {
            parsed,
            encoded: Payload::Owned(bytes),
        },
    })
}

/// The parts of an EncodedClientHelloInner.
struct InnerParts<'a> {
    version_and_random: &'a [u8],
    suites_and_compression: &'a [u8],
    /// With its length prefix.
    extensions: &'a [u8],
    padding: &'a [u8],
}

fn split_inner(encoded: &[u8]) -> Option<InnerParts<'_>> {
    let mut r = Reader::init(encoded);
    let version_and_random = r.take(34)?;
    let session_id_len = usize::from(*r.take(1)?.first()?);
    r.take(session_id_len)?;
    let start = r.used();
    let suites_len = r.take(2)?;
    r.take(usize::from(u16::from_be_bytes([
        suites_len[0],
        suites_len[1],
    ])))?;
    let compression_len = usize::from(*r.take(1)?.first()?);
    r.take(compression_len)?;
    let suites_and_compression = &encoded[start..r.used()];
    let ext_start = r.used();
    let ext_len = r.take(2)?;
    r.take(usize::from(u16::from_be_bytes([ext_len[0], ext_len[1]])))?;
    let extensions = &encoded[ext_start..r.used()];
    Some(InnerParts {
        version_and_random,
        suites_and_compression,
        extensions,
        padding: r.rest(),
    })
}
