//! The client-facing server of ECH split mode (RFC 9849 §3.1, §7.1).
//!
//! In split mode the server that holds the ECH keys (the client-facing
//! server) does not terminate TLS for the names it hides. It decrypts the
//! client's ClientHelloInner, forwards it to the back-end server that does
//! terminate TLS (configured with
//! [`ServerConfig::ech_backend`](crate::ServerConfig::ech_backend)), and
//! relays everything else between the two unmodified, so it never sees the
//! connection's plaintext.
//!
//! [`ClientFacing`] does this without I/O, on the bytes of the two
//! transport connections:
//!
//! 1. Feed the client's bytes to [`ClientFacing::read_client`] until
//!    [`ClientFacing::decision`] is known.
//! 2. On [`ClientFacingDecision::Forward`], open a connection to the
//!    back-end server for [`ClientFacing::server_name`] (the inner
//!    ClientHello's name), and from then on feed each side's bytes to
//!    [`ClientFacing::read_client`] and [`ClientFacing::read_backend`],
//!    sending what [`ClientFacing::take_for_backend`] and
//!    [`ClientFacing::take_for_client`] return. Once
//!    [`ClientFacing::is_relaying`] holds, nothing is inspected any more,
//!    and the caller may copy bytes between the connections directly.
//! 3. On [`ClientFacingDecision::Local`] (no ECH extension, or one that did
//!    not decrypt: GREASE or a stale configuration), the client-facing
//!    server completes the handshake itself with the outer ClientHello,
//!    authenticating as the public name and sending the retry
//!    configurations (§7.1): feed [`ClientFacing::into_received`] to a
//!    server connection whose [`ServerConfig::ech`](crate::ServerConfig::ech)
//!    holds the same [`EchServerConfig`], or use
//!    [`ClientFacing::into_server_connection`].
//!
//! After a HelloRetryRequest from the back-end server, the second
//! ClientHelloOuter is decrypted with the HPKE context of the first
//! (§7.1.1) and its inner ClientHello forwarded in turn.
//!
//! On a protocol error (an ECH extension of type `inner` from the client,
//! a second ClientHello that changes its ECH parameters or does not
//! decrypt, a malformed inner ClientHello), the methods return the error
//! and [`ClientFacing::take_for_client`] holds the fatal alert to send
//! before closing both connections.
//!
//! The back-end server's HelloRetryRequest cannot carry a cookie of the
//! client-facing server (§7.1.1), so a `ClientFacing` holds its state for
//! the whole handshake; the back-end server keeps its own HelloRetryRequest
//! stateful too, since its retry confirms ECH.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use super::server::{Accepted, Fatal, Opened, check_outer_extensions, client_hello};
use super::{EchServerConfig, EchStatus};
use crate::enums::{AlertDescription, ProtocolVersion};
use crate::error::{Error, InvalidMessage};
use crate::msgs::base::Payload;
use crate::msgs::codec::Reader;
use crate::msgs::handshake::{
    HELLO_RETRY_REQUEST_RANDOM, HandshakeMessagePayload, MAX_HANDSHAKE_SIZE,
};
use crate::msgs::message::{Message, MessagePayload};

const ALERT: u8 = 21;
const HANDSHAKE: u8 = 22;
const RECORD_HEADER: usize = 5;
/// The largest record fragment we write (RFC 8446 §5.1).
const MAX_FRAGMENT: usize = 0x4000;

/// What a handshake fragment did to the ClientHello being reassembled.
enum Collected {
    /// Added; the ClientHello may still be incomplete.
    Fragment,
    /// The handshake message is not a ClientHello.
    NotHello,
    /// A ClientHello whose framing is wrong.
    Malformed(InvalidMessage),
}
/// The bytes of a ServerHello (handshake header, `legacy_version` and
/// `random`) that tell it from a HelloRetryRequest.
const SERVER_HELLO_PREFIX: usize = 4 + 2 + 32;

/// What the client-facing server does with a connection.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientFacingDecision {
    /// ECH was accepted: the inner ClientHello is ready for the back-end
    /// server named by [`ClientFacing::server_name`].
    Forward,
    /// No ECH extension, or one that did not decrypt: complete the
    /// handshake locally with the outer ClientHello.
    Local,
}

/// Where the client's side of the connection stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientSide {
    /// Reassembling the first ClientHello.
    FirstHello,
    /// The decision is [`ClientFacingDecision::Local`]: bytes are only
    /// collected for the local server.
    Local,
    /// Forwarding complete records until the back-end server answers the
    /// first ClientHello.
    AwaitServerHello,
    /// The back-end server sent a HelloRetryRequest: reassembling the
    /// second ClientHello.
    SecondHello,
    /// Relaying bytes unmodified.
    Relay,
    /// A fatal error ended the connection.
    Failed,
}

/// The client-facing server of one connection in ECH split mode
/// (RFC 9849 §7.1); see the [module documentation](self).
pub struct ClientFacing {
    config: Arc<EchServerConfig>,
    client: ClientSide,
    /// The back-end server's first handshake message has been classified
    /// (or something else arrived first): its bytes pass unmodified.
    backend_relaying: bool,
    /// Client bytes not yet framed into records.
    from_client: Vec<u8>,
    /// Back-end bytes not yet framed into records.
    from_backend: Vec<u8>,
    /// The handshake bytes of the ClientHello being reassembled, and the
    /// record version it came with.
    hello: Vec<u8>,
    hello_version: [u8; 2],
    /// The start of the back-end server's first handshake message.
    backend_hello: Vec<u8>,
    /// Every byte the client sent until the decision, for a local server.
    received: Vec<u8>,
    to_backend: Vec<u8>,
    to_client: Vec<u8>,
    accepted: Option<Box<Accepted>>,
    decision: Option<ClientFacingDecision>,
    status: EchStatus,
    server_name: Option<String>,
    error: Option<Error>,
}

impl ClientFacing {
    /// A client-facing server for one new client connection, decrypting
    /// with `config`'s keys (matched by configuration identifier unless
    /// [`EchServerConfig::with_trial_decryption`] is set, and with the
    /// outer server name checked if
    /// [`EchServerConfig::with_public_name_check`] is set).
    pub fn new(config: Arc<EchServerConfig>) -> Self {
        Self {
            config,
            client: ClientSide::FirstHello,
            backend_relaying: false,
            from_client: Vec::new(),
            from_backend: Vec::new(),
            hello: Vec::new(),
            hello_version: [3, 1],
            backend_hello: Vec::new(),
            received: Vec::new(),
            to_backend: Vec::new(),
            to_client: Vec::new(),
            accepted: None,
            decision: None,
            status: EchStatus::NotOffered,
            server_name: None,
            error: None,
        }
    }

    /// Processes bytes received from the client.
    ///
    /// # Errors
    ///
    /// A fatal protocol error, also returned by every later call; the alert
    /// reporting it is then in [`take_for_client`](Self::take_for_client).
    pub fn read_client(&mut self, data: &[u8]) -> Result<(), Error> {
        self.check_failed()?;
        match self.client {
            ClientSide::Local => {
                self.received.extend_from_slice(data);
                Ok(())
            }
            ClientSide::Relay => {
                self.to_backend.extend_from_slice(data);
                Ok(())
            }
            _ => {
                if self.decision.is_none() {
                    self.received.extend_from_slice(data);
                }
                self.from_client.extend_from_slice(data);
                self.process_client()
            }
        }
    }

    /// Processes bytes received from the back-end server.
    ///
    /// # Errors
    ///
    /// [`Error::General`] unless the decision is
    /// [`ClientFacingDecision::Forward`]; an earlier fatal error.
    pub fn read_backend(&mut self, data: &[u8]) -> Result<(), Error> {
        self.check_failed()?;
        if self.decision != Some(ClientFacingDecision::Forward) {
            return Err(Error::General(String::from(
                "ECH client-facing server: nothing was forwarded to a back-end server",
            )));
        }
        if self.backend_relaying {
            self.to_client.extend_from_slice(data);
            return Ok(());
        }
        self.from_backend.extend_from_slice(data);
        self.process_backend();
        Ok(())
    }

    /// The decision, once the first ClientHello is complete.
    pub fn decision(&self) -> Option<ClientFacingDecision> {
        self.decision
    }

    /// The ECH status: [`EchStatus::Accepted`] when forwarding,
    /// [`EchStatus::Rejected`] for an ECH extension that did not decrypt,
    /// otherwise [`EchStatus::NotOffered`].
    pub fn ech_status(&self) -> EchStatus {
        self.status
    }

    /// The server name of the ClientHello the decision is about: the inner
    /// ClientHello's when forwarding (the back-end server to choose), the
    /// outer one's otherwise.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// Bytes to send to the back-end server.
    pub fn take_for_backend(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.to_backend)
    }

    /// Bytes to send to the client.
    pub fn take_for_client(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.to_client)
    }

    /// Whether both directions are relayed unmodified: after the back-end
    /// server's ServerHello (or anything else that ends the handshake's
    /// inspection). From then on, once the pending bytes are sent, the
    /// caller may copy bytes between the connections without this object.
    pub fn is_relaying(&self) -> bool {
        self.client == ClientSide::Relay && self.backend_relaying
    }

    /// Every byte received from the client so far, for a server that
    /// completes the handshake locally after
    /// [`ClientFacingDecision::Local`].
    pub fn into_received(self) -> Vec<u8> {
        self.received
    }

    /// Completes the handshake locally after [`ClientFacingDecision::Local`]:
    /// a [`ServerConnection`](crate::ServerConnection) with `config` that
    /// has read and processed every byte received from the client so far,
    /// so its answer may already be waiting to be written. Its
    /// [`ServerConfig::ech`](crate::ServerConfig::ech) should hold the same
    /// keys, so that it sends the retry configurations (RFC 9849 §7.1); it
    /// decrypts again, and reaches the same result.
    ///
    /// An error in what the client sent stays with the connection: its
    /// alert is queued, and its next `process_new_packets` returns the
    /// error.
    ///
    /// # Errors
    ///
    /// [`Error::General`] unless the decision is
    /// [`ClientFacingDecision::Local`], or if the connection cannot take
    /// every received byte; any error from creating the connection.
    #[cfg(feature = "std")]
    pub fn into_server_connection(
        self,
        config: Arc<crate::ServerConfig>,
    ) -> Result<crate::ServerConnection, Error> {
        if self.decision != Some(ClientFacingDecision::Local) {
            return Err(Error::General(String::from(
                "ECH client-facing server: the connection is not local",
            )));
        }
        let mut conn = crate::ServerConnection::new(config)?;
        let mut rest = &self.received[..];
        let mut stalled = false;
        while !rest.is_empty() {
            if matches!(conn.read_tls(&mut rest), Ok(n) if n > 0) {
                stalled = false;
                continue;
            }
            // The connection's buffer is full: let it process what it
            // holds. It keeps an error (and its alert) for the caller's
            // next `process_new_packets`.
            if conn.process_new_packets().is_err() {
                return Ok(conn);
            }
            if stalled {
                // Nothing was read even after processing: report it rather
                // than drop the rest of the client's bytes.
                return Err(Error::General(String::from(
                    "ECH client-facing server: the connection did not take every received byte",
                )));
            }
            stalled = true;
        }
        // An error is kept by the connection, as above.
        let _ = conn.process_new_packets();
        Ok(conn)
    }

    fn check_failed(&self) -> Result<(), Error> {
        match &self.error {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }

    fn fail(&mut self, Fatal(alert, error): Fatal) -> Error {
        // A plaintext fatal alert (RFC 8446 §6): before the back-end
        // server's ServerHello, the client has no other keys.
        self.to_client
            .extend_from_slice(&[ALERT, 3, 3, 0, 2, 2, u8::from(alert)]);
        self.client = ClientSide::Failed;
        self.from_client.clear();
        self.error = Some(error.clone());
        error
    }

    fn decide(&mut self, decision: ClientFacingDecision) {
        self.decision = Some(decision);
        match decision {
            ClientFacingDecision::Local => {
                self.client = ClientSide::Local;
                self.from_client.clear();
                self.hello.clear();
            }
            ClientFacingDecision::Forward => {
                self.client = ClientSide::AwaitServerHello;
                self.received = Vec::new();
            }
        }
    }

    /// Frames the client's bytes into records and acts on them.
    fn process_client(&mut self) -> Result<(), Error> {
        let mut at = 0;
        let result = loop {
            if matches!(self.client, ClientSide::Local | ClientSide::Failed) {
                break Ok(());
            }
            if self.client == ClientSide::Relay {
                self.to_backend.extend_from_slice(&self.from_client[at..]);
                at = self.from_client.len();
                break Ok(());
            }
            if self.client == ClientSide::FirstHello && !first_hello_record(&self.from_client[at..])
            {
                // Not a ClientHello record: the local server reports what
                // is wrong with it.
                self.decide(ClientFacingDecision::Local);
                break Ok(());
            }
            let Some(len) = record_len(&self.from_client[at..]) else {
                break Ok(());
            };
            let record = self.from_client[at..at + len].to_vec();
            at += len;
            if let Err(e) = self.client_record(&record) {
                break Err(e);
            }
        };
        if self.client != ClientSide::Failed && self.client != ClientSide::Local {
            self.from_client.drain(..at);
        }
        result
    }

    fn client_record(&mut self, record: &[u8]) -> Result<(), Error> {
        let typ = record[0];
        match self.client {
            ClientSide::FirstHello => {
                let collected = if typ == HANDSHAKE {
                    self.collect_hello(record)
                } else {
                    Collected::NotHello
                };
                match collected {
                    Collected::Fragment => {}
                    Collected::NotHello => {
                        // Not a ClientHello: the local server reports what
                        // is wrong with it.
                        self.status = EchStatus::NotOffered;
                        self.decide(ClientFacingDecision::Local);
                        return Ok(());
                    }
                    // Fatal here rather than local: the local server would
                    // decrypt and answer the ClientHello before noticing.
                    Collected::Malformed(err) => {
                        return Err(self.fail(Fatal(AlertDescription::from(err), err.into())));
                    }
                }
                if self.hello_complete() {
                    self.first_hello()?;
                }
                Ok(())
            }
            ClientSide::SecondHello if typ == HANDSHAKE => {
                match self.collect_hello(record) {
                    Collected::Fragment => {}
                    Collected::NotHello => {
                        return Err(self.fail(Fatal(
                            AlertDescription::UnexpectedMessage,
                            InvalidMessage::InvalidContentType.into(),
                        )));
                    }
                    Collected::Malformed(err) => {
                        return Err(self.fail(Fatal(AlertDescription::from(err), err.into())));
                    }
                }
                if self.hello_complete() {
                    self.second_hello()?;
                }
                Ok(())
            }
            ClientSide::AwaitServerHello | ClientSide::SecondHello => {
                // change_cipher_spec, early data and anything else go to
                // the back-end server unmodified.
                self.to_backend.extend_from_slice(record);
                Ok(())
            }
            ClientSide::Local | ClientSide::Relay | ClientSide::Failed => Ok(()),
        }
    }

    /// Adds a handshake record's fragment to the ClientHello being
    /// reassembled.
    fn collect_hello(&mut self, record: &[u8]) -> Collected {
        let fragment = &record[RECORD_HEADER..];
        if fragment.is_empty() {
            // RFC 8446 §5.1. Refused rather than ignored: empty records
            // would otherwise be buffered for the local server without end.
            return Collected::Malformed(InvalidMessage::InvalidEmptyPayload);
        }
        if self.hello.is_empty() {
            self.hello_version = [record[1], record[2]];
        }
        self.hello.extend_from_slice(fragment);
        match handshake_len(&self.hello) {
            Some((typ, _)) if typ != 1 => Collected::NotHello,
            Some((_, len)) if len > MAX_HANDSHAKE_SIZE as usize => {
                Collected::Malformed(InvalidMessage::MessageTooLarge)
            }
            // A client_hello followed by something else in its records: a
            // ClientHello must end at a record boundary (RFC 8446 §5.1).
            Some((_, len)) if self.hello.len() > 4 + len => {
                Collected::Malformed(InvalidMessage::TrailingData("ClientHello"))
            }
            _ => Collected::Fragment,
        }
    }

    fn hello_complete(&self) -> bool {
        handshake_len(&self.hello).is_some_and(|(_, len)| self.hello.len() == 4 + len)
    }

    /// Parses the reassembled ClientHello as the server would.
    fn parse_hello(&mut self) -> Result<Message<'static>, InvalidMessage> {
        let bytes = core::mem::take(&mut self.hello);
        let version = ProtocolVersion::from(u16::from_be_bytes(self.hello_version));
        let parsed = {
            let mut r = Reader::init(&bytes);
            let parsed = HandshakeMessagePayload::read_version(&mut r, version)?;
            r.expect_empty("ClientHello")?;
            parsed.into_owned()
        };
        Ok(Message {
            version,
            payload: MessagePayload::Handshake {
                parsed,
                encoded: Payload::Owned(bytes),
            },
        })
    }

    fn first_hello(&mut self) -> Result<(), Error> {
        let Ok(message) = self.parse_hello() else {
            self.decide(ClientFacingDecision::Local);
            return Ok(());
        };
        let Some((ch, body)) = client_hello(&message) else {
            self.decide(ClientFacingDecision::Local);
            return Ok(());
        };
        let outer_name = ch.sni().map(|n| String::from(n.as_ref()));
        let opened = match check_outer_extensions(ch)
            .and_then(|()| super::server::open_first(&self.config, ch, body, message.version))
        {
            Ok(opened) => opened,
            Err(fatal) => return Err(self.fail(fatal)),
        };
        match opened {
            Opened::NotOffered | Opened::Rejected => {
                self.status = match opened {
                    Opened::Rejected => EchStatus::Rejected,
                    _ => EchStatus::NotOffered,
                };
                self.server_name = outer_name;
                self.decide(ClientFacingDecision::Local);
            }
            Opened::Accepted(accepted, inner) => {
                self.status = EchStatus::Accepted;
                self.server_name = client_hello(&inner)
                    .and_then(|(ch, _)| ch.sni())
                    .map(|n| String::from(n.as_ref()));
                self.accepted = Some(accepted);
                self.forward_hello(&inner);
                self.decide(ClientFacingDecision::Forward);
            }
        }
        Ok(())
    }

    fn second_hello(&mut self) -> Result<(), Error> {
        let message = match self.parse_hello() {
            Ok(message) => message,
            Err(err) => return Err(self.fail(Fatal(AlertDescription::from(err), err.into()))),
        };
        let Some((ch, body)) = client_hello(&message) else {
            return Err(self.fail(Fatal(
                AlertDescription::UnexpectedMessage,
                InvalidMessage::InvalidContentType.into(),
            )));
        };
        let Some(accepted) = self.accepted.as_deref_mut() else {
            return Err(Error::General(String::from("no accepted ECH offer")));
        };
        let inner = match check_outer_extensions(ch)
            .and_then(|()| super::server::open_retry(accepted, ch, body, message.version))
        {
            Ok(inner) => inner,
            Err(fatal) => return Err(self.fail(fatal)),
        };
        self.forward_hello(&inner);
        // Nothing else is inspected: the back-end server's answer and the
        // rest of the handshake are encrypted.
        self.client = ClientSide::Relay;
        self.accepted = None;
        Ok(())
    }

    /// Queues `inner` for the back-end server, in records of the client's
    /// record version.
    fn forward_hello(&mut self, inner: &Message<'_>) {
        let MessagePayload::Handshake { encoded, .. } = &inner.payload else {
            return;
        };
        for chunk in encoded.bytes().chunks(MAX_FRAGMENT) {
            self.to_backend.push(HANDSHAKE);
            self.to_backend.extend_from_slice(&self.hello_version);
            self.to_backend
                .extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            self.to_backend.extend_from_slice(chunk);
        }
    }

    /// Frames the back-end server's bytes until its first handshake message
    /// shows whether it is a HelloRetryRequest; every record is passed on.
    fn process_backend(&mut self) {
        let mut at = 0;
        while !self.backend_relaying {
            let Some(len) = record_len(&self.from_backend[at..]) else {
                break;
            };
            let record = &self.from_backend[at..at + len];
            at += len;
            self.to_client.extend_from_slice(record);
            if record[0] != HANDSHAKE {
                // An alert (or anything unexpected): the handshake ends
                // or fails without our help.
                self.backend_answered(false);
                continue;
            }
            let want = SERVER_HELLO_PREFIX - self.backend_hello.len().min(SERVER_HELLO_PREFIX);
            let fragment = &record[RECORD_HEADER..];
            self.backend_hello
                .extend_from_slice(&fragment[..want.min(fragment.len())]);
            if self.backend_hello.len() == SERVER_HELLO_PREFIX {
                // server_hello with the HelloRetryRequest random.
                let hrr = self.backend_hello[0] == 2
                    && self.backend_hello[6..] == HELLO_RETRY_REQUEST_RANDOM.0;
                self.backend_answered(hrr);
            }
        }
        let rest = self.from_backend.split_off(at);
        self.from_backend.clear();
        if self.backend_relaying {
            self.to_client.extend_from_slice(&rest);
        } else {
            self.from_backend = rest;
        }
    }

    /// The back-end server answered the first ClientHello.
    fn backend_answered(&mut self, hello_retry_request: bool) {
        self.backend_relaying = true;
        self.backend_hello = Vec::new();
        if self.client != ClientSide::AwaitServerHello {
            return;
        }
        if hello_retry_request {
            self.client = ClientSide::SecondHello;
            self.hello.clear();
        } else {
            self.client = ClientSide::Relay;
            self.accepted = None;
            let rest = core::mem::take(&mut self.from_client);
            self.to_backend.extend_from_slice(&rest);
        }
    }
}

impl fmt::Debug for ClientFacing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientFacing")
            .field("decision", &self.decision)
            .field("status", &self.status)
            .field("server_name", &self.server_name)
            .field("relaying", &self.is_relaying())
            .finish_non_exhaustive()
    }
}

/// False if `buf`, the client's next bytes before the decision, cannot
/// start a plaintext handshake record (RFC 8446 §5.1). True while too
/// little has arrived to tell.
fn first_hello_record(buf: &[u8]) -> bool {
    match buf {
        [] => true,
        [typ, ..] if *typ != HANDSHAKE => false,
        [_, _, _, hi, lo, ..] => usize::from(u16::from_be_bytes([*hi, *lo])) <= MAX_FRAGMENT,
        _ => true,
    }
}

/// The length of the complete record at the start of `buf`, if there is
/// one.
fn record_len(buf: &[u8]) -> Option<usize> {
    let header = buf.get(..RECORD_HEADER)?;
    let len = RECORD_HEADER + usize::from(u16::from_be_bytes([header[3], header[4]]));
    (buf.len() >= len).then_some(len)
}

/// The type and body length of the handshake message starting `buf`.
fn handshake_len(buf: &[u8]) -> Option<(u8, usize)> {
    let header = buf.get(..4)?;
    Some((
        header[0],
        usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]),
    ))
}
