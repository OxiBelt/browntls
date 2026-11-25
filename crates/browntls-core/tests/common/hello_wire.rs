//! Looking at, and changing, the extensions of a ClientHello or ServerHello
//! on the wire. The hello messages are unprotected, so a test can add an
//! extension the library never sends and see how the peer treats it.

use browntls_core::{ConnectionCommon, SideData};

/// `client_certificate_url` (RFC 6066 §5).
pub const EXT_CLIENT_CERTIFICATE_URL: u16 = 0x0002;
/// `trusted_ca_keys` (RFC 6066 §6).
pub const EXT_TRUSTED_CA_KEYS: u16 = 0x0003;
/// `truncated_hmac` (RFC 6066 §7).
pub const EXT_TRUNCATED_HMAC: u16 = 0x0004;

fn u16_at(buf: &[u8], at: usize) -> usize {
    usize::from(u16::from_be_bytes([buf[at], buf[at + 1]]))
}

/// Where the extension block of the hello at the start of `buf` begins (at
/// its length prefix); `client` says which hello it is. The hello must fill
/// its record.
fn extensions_at(buf: &[u8], client: bool) -> usize {
    assert_eq!(buf[0], 22, "not a handshake record");
    assert_eq!(buf[5], if client { 1 } else { 2 }, "not the expected hello");
    // Record header, handshake header, version, random.
    let mut at = 5 + 4 + 2 + 32;
    // Session ID.
    at += 1 + usize::from(buf[at]);
    if client {
        // Cipher suites and compression methods.
        at += 2 + u16_at(buf, at);
        at += 1 + usize::from(buf[at]);
    } else {
        // Cipher suite and compression method.
        at += 3;
    }
    assert_eq!(
        at + 2 + u16_at(buf, at),
        5 + u16_at(buf, 3),
        "the hello does not fill its record"
    );
    at
}

/// The extensions of the hello at the start of `buf`, in order: type and
/// body.
pub fn hello_extensions(buf: &[u8], client: bool) -> Vec<(u16, Vec<u8>)> {
    let mut at = extensions_at(buf, client);
    let end = at + 2 + u16_at(buf, at);
    at += 2;
    let mut out = Vec::new();
    while at < end {
        let len = u16_at(buf, at + 2);
        out.push((u16_at(buf, at) as u16, buf[at + 4..at + 4 + len].to_vec()));
        at += 4 + len;
    }
    assert_eq!(at, end);
    out
}

/// The extension types of the hello at the start of `buf`, in order.
pub fn hello_extension_types(buf: &[u8], client: bool) -> Vec<u16> {
    hello_extensions(buf, client)
        .into_iter()
        .map(|(typ, _)| typ)
        .collect()
}

/// Appends an extension to the hello at the start of `buf`, after the ones
/// it has, and corrects the three lengths around it. Whatever follows the
/// hello's record stays as it is.
pub fn add_hello_extension(buf: &mut Vec<u8>, client: bool, typ: u16, body: &[u8]) {
    let block_at = extensions_at(buf, client);
    let end = block_at + 2 + u16_at(buf, block_at);
    let mut ext = Vec::with_capacity(4 + body.len());
    ext.extend_from_slice(&typ.to_be_bytes());
    ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ext.extend_from_slice(body);
    let added = ext.len();
    buf.splice(end..end, ext);

    let add_u16 = |buf: &mut Vec<u8>, at: usize| {
        let new = u16::try_from(u16_at(buf, at) + added).unwrap();
        buf[at..at + 2].copy_from_slice(&new.to_be_bytes());
    };
    // The record, the handshake message (the low 16 bits of its 24-bit
    // length: a hello never comes near 64 KiB) and the extension block.
    add_u16(buf, 3);
    add_u16(buf, 7);
    add_u16(buf, block_at);
}

/// Adds `by` to the big-endian `u16` at `at`.
fn grow_u16(buf: &mut [u8], at: usize, by: isize) {
    let new = u16::try_from(u16_at(buf, at) as isize + by).unwrap();
    buf[at..at + 2].copy_from_slice(&new.to_be_bytes());
}

/// Removes every extension of type `typ` from the hello at the start of
/// `buf` and corrects the three lengths around them; returns whether there
/// was one.
pub fn remove_hello_extension(buf: &mut Vec<u8>, client: bool, typ: u16) -> bool {
    let block_at = extensions_at(buf, client);
    let end = block_at + 2 + u16_at(buf, block_at);
    let mut at = block_at + 2;
    let mut removed = 0;
    while at < end - removed {
        let len = 4 + u16_at(buf, at + 2);
        if u16_at(buf, at) == usize::from(typ) {
            buf.drain(at..at + len);
            removed += len;
        } else {
            at += len;
        }
    }
    let by = -(removed as isize);
    grow_u16(buf, 3, by);
    grow_u16(buf, 7, by);
    grow_u16(buf, block_at, by);
    removed != 0
}

/// The `legacy_version` of the hello at the start of `buf`.
pub fn hello_legacy_version(buf: &[u8]) -> u16 {
    assert_eq!(buf[0], 22, "not a handshake record");
    u16_at(buf, 9) as u16
}

/// Sets the `legacy_version` of the hello at the start of `buf`.
pub fn set_hello_legacy_version(buf: &mut [u8], version: u16) {
    assert_eq!(buf[0], 22, "not a handshake record");
    buf[9..11].copy_from_slice(&version.to_be_bytes());
}

/// The session ID of the hello at the start of `buf` (the echo, in a
/// ServerHello).
pub fn hello_session_id(buf: &[u8]) -> &[u8] {
    assert_eq!(buf[0], 22, "not a handshake record");
    let at = 5 + 4 + 2 + 32;
    &buf[at + 1..at + 1 + usize::from(buf[at])]
}

/// Where the cipher suite list of the ClientHello at the start of `buf`
/// begins (at its length prefix).
fn cipher_suites_at(buf: &[u8]) -> usize {
    assert_eq!(buf[0], 22, "not a handshake record");
    assert_eq!(buf[5], 1, "not a ClientHello");
    let at = 5 + 4 + 2 + 32;
    at + 1 + usize::from(buf[at])
}

/// The cipher suites the ClientHello at the start of `buf` offers, in
/// order, signalling values included.
pub fn client_hello_cipher_suites(buf: &[u8]) -> Vec<u16> {
    let at = cipher_suites_at(buf);
    let (suites, _) = buf[at + 2..at + 2 + u16_at(buf, at)].as_chunks::<2>();
    suites
        .iter()
        .map(|suite| u16::from_be_bytes(*suite))
        .collect()
}

/// Appends a cipher suite (or a signalling value) to the ClientHello at the
/// start of `buf` and corrects the three lengths around it.
pub fn add_client_hello_cipher_suite(buf: &mut Vec<u8>, suite: u16) {
    let at = cipher_suites_at(buf);
    let end = at + 2 + u16_at(buf, at);
    buf.splice(end..end, suite.to_be_bytes());
    grow_u16(buf, 3, 2);
    grow_u16(buf, 7, 2);
    grow_u16(buf, at, 2);
}

/// The first handshake message of the record at the start of `buf`, in a
/// record of its own: the hello without what the sender put after it.
pub fn first_handshake_message(buf: &[u8]) -> Vec<u8> {
    assert_eq!(buf[0], 22, "not a handshake record");
    let len = 4 + ((usize::from(buf[6]) << 16) | u16_at(buf, 7));
    assert!(len <= u16_at(buf, 3), "the message does not fit its record");
    let mut out = vec![22, buf[1], buf[2]];
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(&buf[5..5 + len]);
    out
}

/// Everything `conn` has queued to send.
pub fn take_flight<D: SideData>(conn: &mut ConnectionCommon<D>) -> Vec<u8> {
    let mut buf = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut buf).unwrap();
    }
    buf
}

/// Gives `bytes` to `conn` without processing them.
pub fn give<D: SideData>(conn: &mut ConnectionCommon<D>, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        conn.read_tls(&mut bytes).unwrap();
    }
}

/// The first record in `buf` as `(content type, body)`.
pub fn first_record(buf: &[u8]) -> Option<(u8, &[u8])> {
    let len = u16_at(buf.get(..5)?, 3);
    Some((buf[0], buf.get(5..5 + len)?))
}

/// The description of the fatal alert at the start of `buf`, if that is
/// what `buf` starts with.
pub fn fatal_alert(buf: &[u8]) -> Option<u8> {
    match first_record(buf)? {
        (21, [2, description]) => Some(*description),
        _ => None,
    }
}
