//! The server side of ECH in shared mode (RFC 9849 §7).

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
use crate::msgs::base::Payload;
use crate::msgs::codec::Reader;
use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload, SessionId};
use crate::msgs::message::{Message, MessagePayload};

const ECH: u16 = 0xfe0d;
const OUTER_EXTENSIONS: u16 = 0xfd00;

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
}

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
            Self::Accepted(_) => EchStatus::Accepted,
        }
    }

    pub(crate) fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }
}

impl fmt::Debug for ServerEch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.status(), f)
    }
}

/// Looks at a ClientHello for ECH. Returns the ClientHelloInner to continue
/// with when ECH is (still) accepted, or `None` to continue with `m`.
///
/// After a HelloRetryRequest (`done_retry`), only an accepted offer is
/// processed again, with the same HPKE context (§7.1.1).
pub(crate) fn process_client_hello(
    config: Option<&EchServerConfig>,
    state: &mut ServerEch,
    common: &mut CommonState,
    m: &Message<'_>,
    done_retry: bool,
) -> Result<Option<Message<'static>>, Error> {
    let (ch, encoded) = match &m.payload {
        MessagePayload::Handshake {
            parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(ch)),
            encoded,
        } => (ch, encoded.bytes()),
        _ => return Ok(None),
    };
    // §5.1: only an EncodedClientHelloInner may carry it.
    if ch.extensions.ech_outer_extensions.is_some() {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::IllegalEchOuterExtensions,
        ));
    }
    let Some(config) = config else {
        return Ok(None);
    };
    let Some(body) = encoded.get(4..) else {
        return Ok(None);
    };

    if done_retry {
        let ServerEch::Accepted(accepted) = state else {
            // §7.1.1: after rejecting, the second ClientHello is processed
            // as it is.
            return Ok(None);
        };
        let outer = match &ch.extensions.encrypted_client_hello {
            Some(EchClientHello::Outer(outer)) => outer,
            Some(_) => {
                return Err(common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::IllegalEchClientHelloType,
                ));
            }
            None => {
                return Err(common
                    .missing_extension(PeerMisbehaved::MissingEchExtensionInSecondClientHello));
            }
        };
        if outer.config_id != accepted.config_id
            || outer.cipher_suite != accepted.cipher_suite
            || !outer.enc.0.is_empty()
        {
            return Err(common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::EchChangedOnRetry,
            ));
        }
        let aad = outer_aad(body, outer.payload.0.len());
        let Ok(inner) = accepted.opener.open(&aad, &outer.payload.0) else {
            return Err(common.send_fatal_alert(
                AlertDescription::DecryptError,
                PeerMisbehaved::EchDecryptionFailedOnRetry,
            ));
        };
        return decode_inner(common, m.version, body, &ch.session_id, &inner).map(Some);
    }

    let outer = match &ch.extensions.encrypted_client_hello {
        None => return Ok(None),
        Some(EchClientHello::Outer(outer)) => outer,
        // §7: shared mode never receives `inner` from the network.
        Some(EchClientHello::Inner | EchClientHello::Unknown(_)) => {
            return Err(common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::IllegalEchClientHelloType,
            ));
        }
    };
    let aad = outer_aad(body, outer.payload.0.len());
    let enc = EncapsulatedSecret(outer.enc.0.clone());
    for key in config
        .keys
        .iter()
        .filter(|k| k.key_config.config_id == outer.config_id)
    {
        let info = hpke_info(&key.encoded);
        for hpke in key
            .suites
            .iter()
            .filter(|s| s.suite().sym == outer.cipher_suite)
        {
            let Ok(mut opener) = hpke.setup_opener(&enc, &info, &key.private_key) else {
                continue;
            };
            let Ok(inner) = opener.open(&aad, &outer.payload.0) else {
                continue;
            };
            let message = decode_inner(common, m.version, body, &ch.session_id, &inner)?;
            *state = ServerEch::Accepted(Box::new(Accepted {
                opener,
                config_id: outer.config_id,
                cipher_suite: outer.cipher_suite,
            }));
            return Ok(Some(message));
        }
    }
    *state = ServerEch::Rejected;
    Ok(None)
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
    common: &mut CommonState,
    version: ProtocolVersion,
    outer_body: &[u8],
    outer_session_id: &SessionId,
    encoded: &[u8],
) -> Result<Message<'static>, Error> {
    let illegal = |common: &mut CommonState, why: PeerMisbehaved| {
        common.send_fatal_alert(AlertDescription::IllegalParameter, why)
    };
    let Some(parts) = split_inner(encoded) else {
        return Err(common.send_fatal_alert(
            AlertDescription::DecodeError,
            crate::error::InvalidMessage::MessageTooShort,
        ));
    };
    if parts.padding.iter().any(|b| *b != 0) {
        return Err(illegal(common, PeerMisbehaved::IllegalEchPadding));
    }
    let Some(inner_exts) = raw_extensions(parts.extensions) else {
        return Err(common.send_fatal_alert(
            AlertDescription::DecodeError,
            crate::error::InvalidMessage::MessageTooShort,
        ));
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
            _ => return Err(illegal(common, PeerMisbehaved::IllegalEchOuterExtensions)),
        };
        for typ in types.as_chunks::<2>().0 {
            let typ = u16::from_be_bytes(*typ);
            if typ == ECH {
                return Err(illegal(common, PeerMisbehaved::IllegalEchOuterExtensions));
            }
            let Some(found) = outer_exts[cursor..].iter().position(|o| o.typ == typ) else {
                return Err(illegal(common, PeerMisbehaved::IllegalEchOuterExtensions));
            };
            let o = &outer_exts[cursor + found];
            block.extend_from_slice(&outer_block[o.whole.clone()]);
            cursor += found + 1;
        }
    }
    let Ok(block_len) = u16::try_from(block.len()) else {
        return Err(illegal(common, PeerMisbehaved::IllegalEchOuterExtensions));
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
            .map_err(|err| common.send_fatal_alert(AlertDescription::from(err), err))?;
        parsed.into_owned()
    };
    let HandshakePayload::ClientHello(inner) = &parsed.0 else {
        return Err(illegal(common, PeerMisbehaved::IllegalEchInnerClientHello));
    };
    // §7.1: an `inner` extension, and no TLS 1.2 or below.
    let offers_old_version = inner
        .extensions
        .supported_versions
        .as_ref()
        .is_none_or(|versions| {
            versions
                .iter()
                .any(|v| (0x0300..=0x0303).contains(&u16::from(*v)))
        });
    if inner.extensions.encrypted_client_hello != Some(EchClientHello::Inner) || offers_old_version
    {
        return Err(illegal(common, PeerMisbehaved::IllegalEchInnerClientHello));
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
