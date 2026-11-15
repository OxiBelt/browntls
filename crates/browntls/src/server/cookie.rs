//! Stateless HelloRetryRequest cookies (RFC 9846 §4.3.2).
//!
//! When [`ServerConfig::hello_retry_cookies`] is set, a TLS 1.3
//! HelloRetryRequest carries a cookie holding what the server must remember
//! to continue the handshake from the second ClientHello: the hash of the
//! first ClientHello (which the transcript keeps as a `message_hash`
//! message, RFC 9846 §4.5) and the cipher suite and group the
//! HelloRetryRequest selected, plus the legacy session ID and server name
//! the second ClientHello must repeat. The record is sealed (encrypted and
//! authenticated) by the configured [`ProducesTickets`] under its own key.
//!
//! The cookie is attacker-controlled input when it comes back: it is
//! accepted only if it authenticates, carries our domain label and format
//! version, was issued no more than [`COOKIE_LIFETIME_SECS`] ago, and parses
//! exactly. Anything else is `illegal_parameter`.
//!
//! [`ServerConfig::hello_retry_cookies`]: super::ServerConfig::hello_retry_cookies

use alloc::vec::Vec;

use super::server_conn::ProducesTickets;
use crate::enums::CipherSuite;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::NamedGroup;
use crate::msgs::handshake::SessionId;

/// Separates cookie plaintexts from those of any other sealed token.
const COOKIE_LABEL: &[u8; 16] = b"browntls hrr ck1";

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
}

impl RetryCookie {
    fn encode(&self) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(COOKIE_LABEL);
        self.issued_at.encode(&mut out);
        self.suite.encode(&mut out);
        self.group.encode(&mut out);
        out.push(u8::try_from(self.client_hello_hash.len()).ok()?);
        out.extend_from_slice(&self.client_hello_hash);
        self.session_id.encode(&mut out);
        out.push(u8::try_from(self.server_name.len()).ok()?);
        out.extend_from_slice(&self.server_name);
        Some(out)
    }

    fn decode(plain: &[u8]) -> Option<Self> {
        let mut r = Reader::init(plain);
        if r.take(COOKIE_LABEL.len())? != COOKIE_LABEL {
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
        })
    }

    /// Seals the cookie, or `None` if the sealer refuses or it would not
    /// fit the cookie extension.
    pub(super) fn seal(&self, sealer: &dyn ProducesTickets) -> Option<Vec<u8>> {
        let sealed = sealer.encrypt(&self.encode()?)?;
        (!sealed.is_empty() && sealed.len() <= usize::from(u16::MAX)).then_some(sealed)
    }

    /// Opens a cookie received at `now` (seconds since the Unix epoch);
    /// `None` unless it is authentic, well formed and fresh.
    pub(super) fn open(sealer: &dyn ProducesTickets, cookie: &[u8], now: u64) -> Option<Self> {
        let cookie = Self::decode(&sealer.decrypt(cookie)?)?;
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
        }
    }

    #[test]
    fn round_trip_and_freshness() {
        let sealer: Box<dyn ProducesTickets> = Box::new(Toy(0x5a));
        let sealed = sample().seal(&*sealer).unwrap();
        assert_eq!(RetryCookie::open(&*sealer, &sealed, 1_000), Some(sample()));
        assert_eq!(RetryCookie::open(&*sealer, &sealed, 1_060), Some(sample()));
        assert_eq!(RetryCookie::open(&*sealer, &sealed, 1_061), None);
        assert_eq!(RetryCookie::open(&*sealer, &sealed, 939), None);
        // Another key does not open it.
        assert_eq!(RetryCookie::open(&Toy(0x33), &sealed, 1_000), None);
    }

    #[test]
    fn malformed_plaintexts_are_refused() {
        let sealer = Toy(1);
        let plain = sample().encode().unwrap();
        for cut in 0..plain.len() {
            let sealed = sealer.encrypt(&plain[..cut]).unwrap();
            assert_eq!(RetryCookie::open(&sealer, &sealed, 1_000), None, "{cut}");
        }
        let mut longer = plain.clone();
        longer.push(0);
        let sealed = sealer.encrypt(&longer).unwrap();
        assert_eq!(RetryCookie::open(&sealer, &sealed, 1_000), None);
        let mut relabelled = plain;
        relabelled[0] ^= 1;
        let sealed = sealer.encrypt(&relabelled).unwrap();
        assert_eq!(RetryCookie::open(&sealer, &sealed, 1_000), None);
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
        let cookie = sample().encode().unwrap();
        assert!(ServerSessionValue::read_bytes(&cookie).is_err());

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
            assert_eq!(RetryCookie::decode(&ticket), None);
        }
    }
}
