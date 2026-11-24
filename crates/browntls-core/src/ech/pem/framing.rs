use alloc::vec::Vec;
use core::ops::Range;

use super::{EchPemError, EchSecretBytes};

const MAX_PREFIX: usize = 256 * 1024;
pub(super) const MAX_PRIVATE_KEY: usize = 16 * 1024;
const PUBLIC_END: &[u8] = b"-----END ECHCONFIG-----";

type Block = Range<usize>;

#[derive(Clone, Copy)]
enum State {
    Before,
    Private(usize),
    AfterPrivate,
    Public(usize),
}

pub(super) fn read(
    mut next: impl FnMut(usize) -> Result<Option<u8>, EchPemError>,
) -> Result<(EchSecretBytes, Option<Block>, Block), EchPemError> {
    let mut prefix = EchSecretBytes(Vec::with_capacity(1024));
    let mut line_start = 0;
    let mut state = State::Before;
    let mut private = None;
    while prefix.0.len() < MAX_PREFIX {
        let byte = next(MAX_PREFIX - prefix.0.len())?.ok_or(EchPemError::InvalidPem)?;
        if prefix.0.len() == prefix.0.capacity() {
            // Grow without freeing a populated allocation before wiping it.
            let mut grown = EchSecretBytes(Vec::with_capacity(prefix.0.len() * 2));
            grown.0.extend_from_slice(&prefix.0);
            prefix = grown;
        }
        prefix.0.push(byte);
        let end = prefix.0.len();
        let line = &prefix.0[line_start..end];
        if let State::Public(start) = state
            && line == PUBLIC_END
        {
            return Ok((prefix, private, start..line_start));
        }
        if byte != b'\r' && byte != b'\n' {
            continue;
        }
        let line = line.trim_ascii_end();
        let delimiter = line.starts_with(b"-----BEGIN") || line.starts_with(b"-----END");
        state = match (state, line) {
            (State::Before, b"-----BEGIN PRIVATE KEY-----") => State::Private(end),
            (State::Before | State::AfterPrivate, b"-----BEGIN ECHCONFIG-----") => {
                State::Public(end)
            }
            (State::Private(start), b"-----END PRIVATE KEY-----") => {
                private = Some(start..line_start);
                State::AfterPrivate
            }
            _ if delimiter => return Err(EchPemError::InvalidPem),
            (previous, _) => previous,
        };
        line_start = end;
    }
    Err(EchPemError::InputTooLarge)
}

pub(super) fn decode_private(body: &[u8]) -> Result<EchSecretBytes, EchPemError> {
    let symbols = body
        .iter()
        .filter(|byte| !byte.is_ascii_whitespace())
        .count();
    let capacity = symbols.div_ceil(4) * 3;
    if capacity > MAX_PRIVATE_KEY + 2 {
        return Err(EchPemError::InputTooLarge);
    }
    let mut der = EchSecretBytes(Vec::with_capacity(capacity));
    browntls_pki::pem::base64_decode_to(body, |bytes| der.0.extend_from_slice(bytes))
        .map_err(|_| EchPemError::InvalidPem)?;
    if der.0.len() > MAX_PRIVATE_KEY {
        return Err(EchPemError::InputTooLarge);
    }
    Ok(der)
}

/// Includes room for both delimiters with either RFC 9934 label.
pub(super) fn encoded_capacity(len: usize) -> usize {
    let symbols = len.div_ceil(3) * 4;
    symbols + symbols.div_ceil(64) + 64
}

pub(super) fn encode(label: &[u8], bytes: &[u8], out: &mut Vec<u8>) {
    const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    out.extend_from_slice(b"-----BEGIN ");
    out.extend_from_slice(label);
    out.extend_from_slice(b"-----\n");
    for line in bytes.chunks(48) {
        for group in line.chunks(3) {
            let a = group[0];
            let b = group.get(1).copied().unwrap_or(0);
            let c = group.get(2).copied().unwrap_or(0);
            out.push(BASE64[usize::from(a >> 2)]);
            out.push(BASE64[usize::from((a & 3) << 4 | b >> 4)]);
            out.push(if group.len() >= 2 {
                BASE64[usize::from((b & 15) << 2 | c >> 6)]
            } else {
                b'='
            });
            out.push(if group.len() == 3 {
                BASE64[usize::from(c & 63)]
            } else {
                b'='
            });
        }
        out.push(b'\n');
    }
    out.extend_from_slice(b"-----END ");
    out.extend_from_slice(label);
    out.extend_from_slice(b"-----\n");
}
