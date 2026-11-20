//! Reads the two TLS 1.3 messages a server may put GREASE values into
//! (RFC 8701 §4.1), a CertificateRequest and a NewSessionTicket, from their
//! unprotected bytes, and checks what a browntls server sends in them.

/// Whether `v` is one of the sixteen two-byte GREASE values (RFC 8701 §2).
pub fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

fn u16_at(buf: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([buf[at], buf[at + 1]])
}

/// The handshake messages in `bytes`, which holds whole messages: type and
/// body.
pub fn handshake_messages(mut bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let len = usize::from(bytes[1]) << 16 | usize::from(u16_at(bytes, 2));
        out.push((bytes[0], bytes[4..4 + len].to_vec()));
        bytes = &bytes[4 + len..];
    }
    out
}

/// The extensions of the block that ends `body` and starts at `at` with
/// its length: type and body.
fn extensions(body: &[u8], mut at: usize) -> Vec<(u16, Vec<u8>)> {
    let end = at + 2 + usize::from(u16_at(body, at));
    assert_eq!(end, body.len(), "the extensions end the message");
    at += 2;
    let mut out = Vec::new();
    while at < end {
        let len = usize::from(u16_at(body, at + 2));
        out.push((u16_at(body, at), body[at + 4..at + 4 + len].to_vec()));
        at += 4 + len;
    }
    assert_eq!(at, end);
    out
}

/// The extensions of a TLS 1.3 CertificateRequest body (RFC 9846 §4.4.2).
pub fn certificate_request_extensions(body: &[u8]) -> Vec<(u16, Vec<u8>)> {
    extensions(body, 1 + usize::from(body[0]))
}

/// The extensions of a TLS 1.3 NewSessionTicket body (RFC 9846 §4.7.1).
pub fn new_session_ticket_extensions(body: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let nonce_end = 9 + usize::from(body[8]);
    extensions(body, nonce_end + 2 + usize::from(u16_at(body, nonce_end)))
}

/// The schemes of a `signature_algorithms` extension body.
pub fn signature_schemes(body: &[u8]) -> Vec<u16> {
    assert_eq!(usize::from(u16_at(body, 0)), body.len() - 2);
    (1..body.len() / 2).map(|i| u16_at(body, 2 * i)).collect()
}

/// Checks the GREASE extensions of a server message: an empty one first, a
/// one-byte one last, of different types, and no other. Returns the two
/// types.
pub fn assert_grease_extensions(exts: &[(u16, Vec<u8>)]) -> (u16, u16) {
    let (first, last) = (&exts[0], &exts[exts.len() - 1]);
    assert!(is_grease(first.0) && first.1.is_empty(), "{exts:x?}");
    assert!(is_grease(last.0) && last.1 == [0], "{exts:x?}");
    assert_ne!(first.0, last.0, "an extension type appears once");
    assert_eq!(exts.iter().filter(|e| is_grease(e.0)).count(), 2);
    (first.0, last.0)
}

/// Checks a CertificateRequest body sent with GREASE on: the GREASE
/// extensions, and one GREASE scheme, first in `signature_algorithms`.
/// Returns the three GREASE values.
pub fn assert_greased_certificate_request(body: &[u8]) -> [u16; 3] {
    let exts = certificate_request_extensions(body);
    let (first, last) = assert_grease_extensions(&exts);
    let schemes = exts.iter().find(|e| e.0 == 0x000d).expect("schemes");
    let schemes = signature_schemes(&schemes.1);
    assert!(is_grease(schemes[0]), "{schemes:x?}");
    assert!(schemes.len() > 1, "real schemes follow");
    assert!(schemes[1..].iter().all(|s| !is_grease(*s)), "{schemes:x?}");
    [schemes[0], first, last]
}

/// Checks a CertificateRequest body sent with GREASE off.
pub fn assert_plain_certificate_request(body: &[u8]) {
    let exts = certificate_request_extensions(body);
    assert!(exts.iter().all(|e| !is_grease(e.0)), "{exts:x?}");
    let schemes = exts.iter().find(|e| e.0 == 0x000d).expect("schemes");
    let schemes = signature_schemes(&schemes.1);
    assert!(schemes.iter().all(|s| !is_grease(*s)), "{schemes:x?}");
}
