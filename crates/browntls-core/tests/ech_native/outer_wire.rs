//! The ECH extension of an outer ClientHello on the wire (RFC 9849 §5),
//! for the tests that decrypt a captured offer themselves.

pub(super) fn u16_at(buf: &[u8], at: usize) -> usize {
    usize::from(u16::from_be_bytes([buf[at], buf[at + 1]]))
}

/// The outer ClientHello of a capture, as far as ECH needs it.
pub(super) struct OuterHello {
    pub(super) random: Vec<u8>,
    /// `ClientHelloOuterAAD` (RFC 9849 §5.2): the ClientHello without its
    /// handshake header, the ECH payload replaced by zeros.
    pub(super) aad: Vec<u8>,
    pub(super) kdf: u16,
    pub(super) aead: u16,
    pub(super) enc: Vec<u8>,
    pub(super) payload: Vec<u8>,
}

/// Parses the ClientHello that fills the first record of `flight`.
pub(super) fn outer_hello(flight: &[u8]) -> OuterHello {
    assert_eq!((flight[0], flight[5]), (22, 1), "not a ClientHello");
    let len = u16_at(flight, 3);
    let body = &flight[9..5 + len];
    assert_eq!(
        body.len(),
        usize::from(flight[6]) << 16 | u16_at(flight, 7),
        "the ClientHello does not fill its record"
    );
    // Version, random, session ID, cipher suites, compression methods.
    let mut at = 2 + 32;
    at += 1 + usize::from(body[at]);
    at += 2 + u16_at(body, at);
    at += 1 + usize::from(body[at]);
    let end = at + 2 + u16_at(body, at);
    assert_eq!(end, body.len());
    at += 2;
    while at < end {
        let (typ, ext_len) = (u16_at(body, at), u16_at(body, at + 2));
        at += 4;
        if typ == 0xfe0d {
            // ECHClientHello: type `outer`, the cipher suite, the
            // configuration identifier, `enc`, the payload.
            let ext = &body[at..at + ext_len];
            assert_eq!(ext[0], 0, "not an outer ECH extension");
            let enc_len = u16_at(ext, 6);
            let payload_at = 8 + enc_len + 2;
            let payload_len = u16_at(ext, 8 + enc_len);
            assert_eq!(payload_at + payload_len, ext.len());
            let mut aad = body.to_vec();
            aad[at + payload_at..at + ext_len].fill(0);
            return OuterHello {
                random: body[2..34].to_vec(),
                aad,
                kdf: u16_at(ext, 1) as u16,
                aead: u16_at(ext, 3) as u16,
                enc: ext[8..8 + enc_len].to_vec(),
                payload: ext[payload_at..].to_vec(),
            };
        }
        at += ext_len;
    }
    panic!("no ECH extension");
}
