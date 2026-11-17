//! Reading a ClientHello before a [`ServerConfig`] is chosen: the part the
//! buffered [`Acceptor`](super::Acceptor) (`std`) and the
//! [`UnbufferedAcceptor`](super::UnbufferedAcceptor) share.
//!
//! Both drive a [`ConnectionCore`] parked in [`Accepting`]: the first
//! ClientHello is read with [`ConnectionCore::first_handshake_message`] and
//! checked with the configuration-independent part of the handshake
//! ([`hs::process_client_hello`]); once the application has chosen a
//! configuration, [`configure`] applies it to the same core, which then
//! continues exactly as a connection created with that configuration would
//! (deframer, handshake joiner and CommonState carried over).

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{ClientHello, ServerConfig, ServerConnectionData};
use crate::common_state::{CommonState, Side};
use crate::conn::{ConnectionCore, Context, State};
use crate::enums::{HandshakeType, ProtocolVersion, SignatureScheme};
use crate::error::Error;
use crate::msgs::base::Payload;
use crate::msgs::deframer::DeframerBuffer;
use crate::msgs::handshake::{ClientHelloPayload, HandshakeMessagePayload, HandshakePayload};
use crate::msgs::message::{Message, MessagePayload};
use crate::server::hs;
use crate::sync::Arc;

/// A core for an acceptor: no configuration yet, so it only reads the
/// first ClientHello (see [`read_client_hello`]).
pub(super) fn accepting_core() -> ConnectionCore<ServerConnectionData> {
    ConnectionCore::new(
        Box::new(Accepting),
        ServerConnectionData::default(),
        CommonState::new(Side::Server),
    )
}

/// The ClientHello an acceptor read, checked by [`hs::process_client_hello`].
///
/// The parsed payload is kept apart from its encoding, so that
/// [`Self::client_hello`] needs no fallible match on a [`Message`]; the
/// message is rebuilt (without copying) by [`configure`].
pub(super) struct AcceptedHello {
    version: ProtocolVersion,
    payload: ClientHelloPayload,
    encoded: Payload<'static>,
    sig_schemes: Vec<SignatureScheme>,
}

impl AcceptedHello {
    /// What a certificate resolver would see of the ClientHello.
    pub(super) fn client_hello<'a>(&'a self, data: &'a ServerConnectionData) -> ClientHello<'a> {
        ClientHello::new(data.sni.as_ref(), &self.sig_schemes, &self.payload)
    }

    fn into_message(self) -> (Message<'static>, Vec<SignatureScheme>) {
        let message = Message {
            version: self.version,
            payload: MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(self.payload)),
                encoded: self.encoded,
            },
        };
        (message, self.sig_schemes)
    }
}

/// Reads the first ClientHello from `buffer` into `core` (made by
/// [`accepting_core`]).
///
/// Returns `None` while the ClientHello is incomplete: the records read so
/// far are discarded from `buffer` and their handshake bytes kept in the
/// core's joiner. Before it, only `change_cipher_spec` records are allowed
/// (set aside for a stateless HelloRetryRequest, RFC 9846 §4.3.2); anything
/// else, a malformed record or a ClientHello that fails the
/// configuration-independent checks ends the core with an error and a
/// queued fatal alert.
pub(super) fn read_client_hello(
    core: &mut ConnectionCore<ServerConnectionData>,
    buffer: &mut impl DeframerBuffer,
) -> Result<Option<AcceptedHello>, Error> {
    let result = match core.first_handshake_message(buffer) {
        Ok(Some(message)) => checked(core, message).map(Some),
        Ok(None) => Ok(None),
        Err(err) => Err(err),
    };
    result.map_err(|err| failed(core, err))
}

/// Runs the configuration-independent ClientHello checks on `message`.
fn checked(
    core: &mut ConnectionCore<ServerConnectionData>,
    message: Message<'static>,
) -> Result<AcceptedHello, Error> {
    let mut cx = Context {
        common: &mut core.common_state,
        data: &mut core.data,
    };
    let (_, sig_schemes) = hs::process_client_hello(&message, false, &mut cx)?;
    // `process_client_hello` accepted it as a ClientHello, so the
    // `else` branch is unreachable; it is an error rather than a panic.
    let Message {
        version,
        payload:
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(payload)),
                encoded,
            },
    } = message
    else {
        return Err(client_hello_expected(&message.payload));
    };
    Ok(AcceptedHello {
        version,
        payload,
        encoded,
        sig_schemes,
    })
}

/// Continues the handshake in `core` with `config`, from the ClientHello
/// [`read_client_hello`] returned.
///
/// Applies the checks and settings that a connection created with `config`
/// gets ([`ServerConfig::apply_to`]), then, with ECH keys in `config`
/// (RFC 9849 §7.1), replaces an accepted encrypted ClientHello by the inner
/// one (checked again by [`hs::process_client_hello`]), and processes the
/// ClientHello as [`hs::ExpectClientHello`] does: stateless retry cookie,
/// version, suite and group, certificate, early data, the first flight.
///
/// On error the core has failed ([`ConnectionCore::fail`]: a TLS 1.2
/// session it resumed is forgotten) and a fatal alert is queued, also when
/// `config` itself is refused (`internal_error`).
pub(super) fn configure(
    core: &mut ConnectionCore<ServerConnectionData>,
    hello: AcceptedHello,
    config: Arc<ServerConfig>,
) -> Result<(), Error> {
    match handshake_with(core, hello, config) {
        Ok(state) => {
            core.state = Ok(state);
            Ok(())
        }
        Err(err) => Err(failed(core, err)),
    }
}

fn handshake_with(
    core: &mut ConnectionCore<ServerConnectionData>,
    hello: AcceptedHello,
    config: Arc<ServerConfig>,
) -> Result<Box<dyn State<ServerConnectionData>>, Error> {
    config.apply_to(&mut core.common_state)?;
    let mut cx = Context {
        common: &mut core.common_state,
        data: &mut core.data,
    };
    let (outer, outer_sig_schemes) = hello.into_message();
    // RFC 9849 §7.1: an encrypted ClientHello that decrypts replaces the one
    // the acceptor saw.
    let inner = crate::ech::server::process_client_hello(
        config.ech_role(),
        &mut cx.data.ech,
        cx.common,
        &outer,
        false,
    )?;
    let state = hs::ExpectClientHello::new(config);
    match &inner {
        Some(inner) => {
            let (payload, sig_schemes) = hs::process_client_hello(inner, false, &mut cx)?;
            state.with_certified_key(sig_schemes, payload, inner, &mut cx)
        }
        None => {
            let payload = match &outer.payload {
                MessagePayload::Handshake {
                    parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(payload)),
                    ..
                } => payload,
                // `into_message` built a ClientHello: unreachable.
                other => return Err(client_hello_expected(other)),
            };
            state.with_certified_key(outer_sig_schemes, payload, &outer, &mut cx)
        }
    }
}

/// Ends `core` with `err`, making sure a fatal alert is queued.
fn failed(core: &mut ConnectionCore<ServerConnectionData>, err: Error) -> Error {
    let err =
        ConnectionCore::<ServerConnectionData>::ensure_alert_sent(&mut core.common_state, err);
    core.fail(err)
}

fn client_hello_expected(payload: &MessagePayload<'_>) -> Error {
    crate::check::inappropriate_handshake_message(
        payload,
        &[crate::enums::ContentType::Handshake],
        &[HandshakeType::ClientHello],
    )
}

/// The state an acceptor's core parks in: it never handles messages itself
/// ([`read_client_hello`] reads them).
struct Accepting;

impl State<ServerConnectionData> for Accepting {
    fn handle(
        self: Box<Self>,
        _cx: &mut Context<'_, ServerConnectionData>,
        _message: Message<'_>,
    ) -> Result<Box<dyn State<ServerConnectionData>>, Error> {
        Err(Error::general(
            "Acceptor connections cannot process messages",
        ))
    }
}
