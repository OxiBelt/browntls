//! Output for the harness: one JSON object per line on standard output.

use std::fmt::Write as _;
use std::io::Write;

use browntls::crypto::native;
use browntls::{AlertDescription, CommonState, ConnectionCommon, Error, SideData};

/// A JSON value for [`emit`].
#[derive(Debug)]
pub(super) enum Value {
    Str(String),
    Num(usize),
    Bool(bool),
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Self::Str(s.to_owned())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Self::Str(s)
    }
}

/// Writes one JSON object on its own line to standard output.
pub(super) fn emit(fields: &[(&str, Value)]) {
    let mut line = String::from("{");
    for (i, (key, value)) in fields.iter().enumerate() {
        if i > 0 {
            line.push(',');
        }
        push_json_str(&mut line, key);
        line.push(':');
        match value {
            Value::Str(s) => push_json_str(&mut line, s),
            Value::Num(n) => {
                let _ = write!(line, "{n}");
            }
            Value::Bool(b) => {
                let _ = write!(line, "{b}");
            }
        }
    }
    line.push('}');
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The negotiated parameters of an established connection.
pub(super) fn negotiated(common: &CommonState) -> Vec<(&'static str, Value)> {
    let show = |v: Option<String>| Value::Str(v.unwrap_or_else(|| "none".into()));
    vec![
        (
            "version",
            show(common.protocol_version().map(|v| format!("{v:?}"))),
        ),
        (
            "suite",
            show(
                common
                    .negotiated_cipher_suite()
                    .map(|s| format!("{:?}", s.suite())),
            ),
        ),
        (
            "group",
            show(
                common
                    .negotiated_key_exchange_group()
                    .map(|g| format!("{:?}", g.name())),
            ),
        ),
        (
            "handshake",
            show(common.handshake_kind().map(|k| format!("{k:?}"))),
        ),
        (
            "peer_certificates",
            Value::Num(common.peer_certificates().map_or(0, <[_]>::len)),
        ),
        (
            "cert_with_extern_psk",
            Value::Bool(common.negotiated_cert_with_extern_psk()),
        ),
    ]
}

/// Whether `err` (from a server's handshake) is the client refusing an ECH
/// rejection (RFC 9849 §6.1.6), which precedes the client's retry.
pub(super) fn is_ech_required(err: &Error) -> bool {
    *err == Error::AlertReceived(AlertDescription::EncryptedClientHelloRequired)
}

/// The connection's error after an I/O failure: the TLS error the
/// connection recorded, if any.
pub(super) fn tls_error<S: SideData>(conn: &mut ConnectionCommon<S>) -> Option<Error> {
    conn.process_new_packets().err()
}

/// Prints the acceleration backend selected for each algorithm family.
pub(super) fn info() {
    emit(&[
        ("event", "info".into()),
        ("arch", std::env::consts::ARCH.into()),
        ("package_version", env!("CARGO_PKG_VERSION").into()),
    ]);
    for status in native::accel::status_all() {
        emit(&[
            ("event", "accel".into()),
            ("algorithm", status.algorithm.to_string().into()),
            ("backend", status.backend.to_string().into()),
            ("accelerated", Value::Bool(status.accelerated())),
        ]);
    }
}
