//! Stateless HelloRetryRequest cookies (RFC 9846 §4.3.2).
//!
//! When [`ServerConfig::hello_retry_cookies`] is set, a TLS 1.3
//! HelloRetryRequest carries a cookie holding what the server must remember
//! to continue the handshake from the second ClientHello: the hash of the
//! first ClientHello (which the transcript keeps as a `message_hash`
//! message, RFC 9846 §4.1) and the cipher suite and group the
//! HelloRetryRequest selected, plus the legacy session ID and server name
//! the second ClientHello must repeat. The record is sealed (encrypted and
//! authenticated) by the configured [`ProducesTickets`] under its own key.
//!
//! The cookie is attacker-controlled input when it comes back: it is
//! accepted only if it authenticates, carries our domain label and format
//! version, was issued no more than [`COOKIE_LIFETIME_SECS`] ago, and parses
//! exactly. Anything else is `illegal_parameter`.
//!
//! A DTLS 1.3 cookie has a label of its own, so that it never opens on a
//! TLS connection nor a TLS cookie on a DTLS one, and also holds the
//! client's transport address, which it must come back from (RFC 9147
//! §5.1).
//!
//! [`ServerConfig::hello_retry_cookies`]: super::ServerConfig::hello_retry_cookies

use alloc::vec::Vec;

use super::server_conn::ProducesTickets;
use crate::enums::CipherSuite;
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::NamedGroup;
use crate::msgs::handshake::SessionId;

/// Separates cookie plaintexts from those of any other sealed token.
const COOKIE_LABEL: &[u8; 16] = b"browntls hrr ck1";

/// The label of a DTLS 1.3 cookie.
const DTLS_COOKIE_LABEL: &[u8; 16] = b"browntls dtls ck";

/// How long a cookie is accepted after it was issued, in seconds.
pub(super) const COOKIE_LIFETIME_SECS: u64 = 60;

/// The state a HelloRetryRequest cookie carries.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct RetryCookie {
    /// When the cookie was issued, in seconds since the Unix epoch.
    pub(super) issued_at: u64,
    pub(super) suite: CipherSuite,
    pub(super) group: NamedGroup,
    /// `Hash(ClientHello1)` under the suite's hash.
    pub(super) client_hello_hash: Vec<u8>,
    /// The first ClientHello's `legacy_session_id`, which the
    /// HelloRetryRequest echoed.
    pub(super) session_id: SessionId,
    /// The first ClientHello's server name, empty when it sent none.
    pub(super) server_name: Vec<u8>,
    /// DTLS 1.3 only: what else the cookie is bound to.
    pub(super) dtls: Option<DtlsRetry>,
}

/// What a DTLS 1.3 cookie also carries.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct DtlsRetry {
    /// The client's transport address (RFC 9147 §5.1), opaque.
    pub(super) peer_address: Vec<u8>,
    /// Whether the HelloRetryRequest named `group` in its key_share
    /// extension. It does not when it only asked for the cookie, the first
    /// ClientHello's key share being acceptable.
    pub(super) group_named: bool,
}

impl RetryCookie {
    fn encode(&self) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(match self.dtls {
            Some(_) => DTLS_COOKIE_LABEL,
            None => COOKIE_LABEL,
        });
        self.issued_at.encode(&mut out);
        self.suite.encode(&mut out);
        self.group.encode(&mut out);
        out.push(u8::try_from(self.client_hello_hash.len()).ok()?);
        out.extend_from_slice(&self.client_hello_hash);
        self.session_id.encode(&mut out);
        out.push(u8::try_from(self.server_name.len()).ok()?);
        out.extend_from_slice(&self.server_name);
        if let Some(dtls) = &self.dtls {
            u16::try_from(dtls.peer_address.len()).ok()?;
            PayloadU16::encode_slice(&dtls.peer_address, &mut out);
            out.push(u8::from(dtls.group_named));
        }
        Some(out)
    }

    /// Decodes a TLS cookie, or a DTLS one when `dtls`.
    fn decode(plain: &[u8], dtls: bool) -> Option<Self> {
        let mut r = Reader::init(plain);
        let label = match dtls {
            true => DTLS_COOKIE_LABEL,
            false => COOKIE_LABEL,
        };
        if r.take(label.len())? != label {
            return None;
        }
        let issued_at = u64::read(&mut r).ok()?;
        let suite = CipherSuite::read(&mut r).ok()?;
        let group = NamedGroup::read(&mut r).ok()?;
        let hash_len = usize::from(u8::read(&mut r).ok()?);
        let client_hello_hash = r.take(hash_len)?.to_vec();
        let session_id = SessionId::read(&mut r).ok()?;
        let name_len = usize::from(u8::read(&mut r).ok()?);
        let server_name = r.take(name_len)?.to_vec();
        let dtls = match dtls {
            true => Some(DtlsRetry {
                peer_address: PayloadU16::read(&mut r).ok()?.0,
                group_named: match u8::read(&mut r).ok()? {
                    0 => false,
                    1 => true,
                    _ => return None,
                },
            }),
            false => None,
        };
        if r.any_left() {
            return None;
        }
        Some(Self {
            issued_at,
            suite,
            group,
            client_hello_hash,
            session_id,
            server_name,
            dtls,
        })
    }

    /// Seals the cookie, or `None` if the sealer refuses or it would not
    /// fit the cookie extension.
    pub(super) fn seal(&self, sealer: &dyn ProducesTickets) -> Option<Vec<u8>> {
        let sealed = sealer.encrypt(&self.encode()?)?;
        (!sealed.is_empty() && sealed.len() <= usize::from(u16::MAX)).then_some(sealed)
    }

    /// Opens a cookie received at `now` (seconds since the Unix epoch) on
    /// a TLS connection, or on a DTLS one from `dtls_peer_address`; `None`
    /// unless it is authentic, well formed, fresh, of that protocol and,
    /// for DTLS, issued to that address.
    pub(super) fn open(
        sealer: &dyn ProducesTickets,
        cookie: &[u8],
        now: u64,
        dtls_peer_address: Option<&[u8]>,
    ) -> Option<Self> {
        let cookie = Self::decode(&sealer.decrypt(cookie)?, dtls_peer_address.is_some())?;
        if let (Some(dtls), Some(address)) = (&cookie.dtls, dtls_peer_address)
            && dtls.peer_address != address
        {
            return None;
        }
        // Accept small clock differences between servers sharing a key in
        // either direction, never more than the lifetime.
        (now.abs_diff(cookie.issued_at) <= COOKIE_LIFETIME_SECS).then_some(cookie)
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use core::fmt;

    use super::*;

    /// A toy sealer: XOR "encryption" with a one-byte tag, enough to tell
    /// its own output from anything else in these codec tests.
    struct Toy(u8);

    impl fmt::Debug for Toy {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Toy")
        }
    }

    impl ProducesTickets for Toy {
        fn enabled(&self) -> bool {
            true
        }
        fn lifetime(&self) -> u32 {
            60
        }
        fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
            let mut out: Vec<u8> = plain.iter().map(|b| b ^ self.0).collect();
            out.push(self.0);
            Some(out)
        }
        fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
            let (tag, body) = cipher.split_last()?;
            (*tag == self.0).then(|| body.iter().map(|b| b ^ self.0).collect())
        }
    }

    fn sample() -> RetryCookie {
        RetryCookie {
            issued_at: 1_000,
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            group: NamedGroup::secp256r1,
            client_hello_hash: alloc::vec![7; 32],
            session_id: SessionId::read_bytes(&[3, 1, 2, 3]).unwrap(),
            server_name: b"example.com".to_vec(),
            dtls: None,
        }
    }

    fn dtls_sample(group_named: bool) -> RetryCookie {
        RetryCookie {
            session_id: SessionId::empty(),
            dtls: Some(DtlsRetry {
                peer_address: b"192.0.2.1:4433".to_vec(),
                group_named,
            }),
            ..sample()
        }
    }

    #[test]
    fn round_trip_and_freshness() {
        let sealer: Box<dyn ProducesTickets> = Box::new(Toy(0x5a));
        let sealed = sample().seal(&*sealer).unwrap();
        let open = |now| RetryCookie::open(&*sealer, &sealed, now, None);
        assert_eq!(open(1_000), Some(sample()));
        assert_eq!(open(1_060), Some(sample()));
        assert_eq!(open(1_061), None);
        assert_eq!(open(939), None);
        // Another key does not open it.
        assert_eq!(RetryCookie::open(&Toy(0x33), &sealed, 1_000, None), None);
    }

    #[test]
    fn malformed_plaintexts_are_refused() {
        let sealer = Toy(1);
        for (cookie, address) in [
            (sample(), None),
            (dtls_sample(true), Some(&b"192.0.2.1:4433"[..])),
        ] {
            let plain = cookie.encode().unwrap();
            let open = |plain: &[u8]| {
                let sealed = sealer.encrypt(plain).unwrap();
                RetryCookie::open(&sealer, &sealed, 1_000, address)
            };
            assert_eq!(open(&plain), Some(cookie));
            for cut in 0..plain.len() {
                assert_eq!(open(&plain[..cut]), None, "{cut}");
            }
            let mut longer = plain.clone();
            longer.push(0);
            assert_eq!(open(&longer), None);
            let mut relabelled = plain.clone();
            relabelled[0] ^= 1;
            assert_eq!(open(&relabelled), None);
            if address.is_some() {
                // `group_named` is 0 or 1.
                let mut flag = plain;
                if let Some(last) = flag.last_mut() {
                    *last = 2;
                }
                assert_eq!(open(&flag), None);
            }
        }
    }

    /// RFC 9147 §5.1: a DTLS cookie verifies only from the address it was
    /// issued to, and never as a TLS cookie; a TLS cookie never verifies on
    /// DTLS.
    #[test]
    fn dtls_cookie_is_bound_to_address_and_protocol() {
        let sealer = Toy(0x42);
        let address = &b"192.0.2.1:4433"[..];
        for group_named in [false, true] {
            let sealed = dtls_sample(group_named).seal(&sealer).unwrap();
            assert_eq!(
                RetryCookie::open(&sealer, &sealed, 1_000, Some(address)),
                Some(dtls_sample(group_named))
            );
            for other in [&b"192.0.2.1:4434"[..], b"192.0.2.2:4433", b""] {
                assert_eq!(
                    RetryCookie::open(&sealer, &sealed, 1_000, Some(other)),
                    None
                );
            }
            assert_eq!(RetryCookie::open(&sealer, &sealed, 1_000, None), None);
            assert_eq!(
                RetryCookie::open(&sealer, &sealed, 1_061, Some(address)),
                None
            );
        }
        let tls = sample().seal(&sealer).unwrap();
        assert_eq!(RetryCookie::open(&sealer, &tls, 1_000, Some(address)), None);
        assert_eq!(RetryCookie::open(&sealer, &tls, 1_000, Some(b"")), None);
    }

    /// Cookie and ticket plaintexts cannot be mistaken for each other, even
    /// under one key: a ticket (`ServerSessionValue`) starts with its 0 or 1
    /// SNI flag, a cookie with its label.
    #[test]
    fn cookie_and_ticket_plaintexts_are_disjoint() {
        use browntls_pki::{DnsName, UnixTime};

        use crate::enums::ProtocolVersion;
        use crate::msgs::persist::ServerSessionValue;

        assert!(COOKIE_LABEL[0] > 1);
        assert!(DTLS_COOKIE_LABEL[0] > 1);
        for cookie in [sample(), dtls_sample(true)] {
            let cookie = cookie.encode().unwrap();
            assert!(ServerSessionValue::read_bytes(&cookie).is_err());
        }

        let name = DnsName::try_from("example.com").unwrap();
        for sni in [None, Some(&name)] {
            let ticket = ServerSessionValue::new(
                sni,
                ProtocolVersion::TLSv1_3,
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                &[1; 32],
                None,
                None,
                alloc::vec![],
                UnixTime::since_unix_epoch(core::time::Duration::from_secs(1_000)),
                0,
            )
            .get_encoding();
            assert!(ticket[0] <= 1);
            assert_eq!(RetryCookie::decode(&ticket, false), None);
            assert_eq!(RetryCookie::decode(&ticket, true), None);
        }
    }
}
