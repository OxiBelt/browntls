//! What the running kernel takes, asked on loopback sockets.
//!
//! A kernel with the `tls` module may still lack a cipher (built without
//! it, or restricted to approved algorithms), and it says so only when it
//! is given keys, after the connection's secrets were taken out of
//! userspace: too late for the connection. So before a connection is
//! handed over, the kernel is asked once whether it takes keys of that
//! connection's cipher, with keys of zeros on a loopback socket that
//! carries no data, and the answer is kept.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};

use browntls::crypto::cipher::{AeadKey, Iv};
use browntls::{CipherSuite, ConnectionTrafficSecrets, ProtocolVersion, SupportedCipherSuite};

use crate::crypto_info::CryptoInfo;
use crate::sys;

/// The record protections kernel TLS has a form for, by protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    Tls13Aes128Gcm,
    Tls13Aes256Gcm,
    Tls13ChaCha20Poly1305,
    Tls13Aes128Ccm,
    Tls12Aes128Gcm,
    Tls12Aes256Gcm,
    Tls12ChaCha20Poly1305,
}

impl Form {
    /// The forms of TLS 1.3, the version of a connection that sends or
    /// accepts 0-RTT data.
    const TLS13: [Self; 4] = [
        Self::Tls13Aes128Gcm,
        Self::Tls13Aes256Gcm,
        Self::Tls13ChaCha20Poly1305,
        Self::Tls13Aes128Ccm,
    ];
    #[cfg(test)]
    const TLS12: [Self; 3] = [
        Self::Tls12Aes128Gcm,
        Self::Tls12Aes256Gcm,
        Self::Tls12ChaCha20Poly1305,
    ];

    /// The form of `suite`'s records, if this module knows one. A suite
    /// without one is left to the handover, which refuses what has no
    /// kernel form before it takes anything.
    fn of(suite: SupportedCipherSuite) -> Option<Self> {
        Some(match suite.suite() {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Self::Tls13Aes128Gcm,
            CipherSuite::TLS13_AES_256_GCM_SHA384 => Self::Tls13Aes256Gcm,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => Self::Tls13ChaCha20Poly1305,
            CipherSuite::TLS13_AES_128_CCM_SHA256 => Self::Tls13Aes128Ccm,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => Self::Tls12Aes128Gcm,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => Self::Tls12Aes256Gcm,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            | CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
                Self::Tls12ChaCha20Poly1305
            }
            _ => return None,
        })
    }

    /// The option value that gives the kernel keys of zeros in this form.
    fn crypto_info(self) -> io::Result<CryptoInfo> {
        let key = |len| AeadKey::new(&[0; 32][..len]);
        let iv = Iv::new([0; 12]);
        let (version, secrets) = match self {
            Self::Tls13Aes128Gcm => (
                ProtocolVersion::TLSv1_3,
                ConnectionTrafficSecrets::Aes128Gcm { key: key(16), iv },
            ),
            Self::Tls13Aes256Gcm => (
                ProtocolVersion::TLSv1_3,
                ConnectionTrafficSecrets::Aes256Gcm { key: key(32), iv },
            ),
            Self::Tls13ChaCha20Poly1305 => (
                ProtocolVersion::TLSv1_3,
                ConnectionTrafficSecrets::Chacha20Poly1305 { key: key(32), iv },
            ),
            Self::Tls13Aes128Ccm => (
                ProtocolVersion::TLSv1_3,
                ConnectionTrafficSecrets::Aes128Ccm { key: key(16), iv },
            ),
            Self::Tls12Aes128Gcm => (
                ProtocolVersion::TLSv1_2,
                ConnectionTrafficSecrets::Aes128Gcm { key: key(16), iv },
            ),
            Self::Tls12Aes256Gcm => (
                ProtocolVersion::TLSv1_2,
                ConnectionTrafficSecrets::Aes256Gcm { key: key(32), iv },
            ),
            Self::Tls12ChaCha20Poly1305 => (
                ProtocolVersion::TLSv1_2,
                ConnectionTrafficSecrets::Chacha20Poly1305 { key: key(32), iv },
            ),
        };
        CryptoInfo::new(version, &secrets, 0).map_err(io::Error::other)
    }
}

/// What is known about each [`Form`], two bits each: nothing (zero),
/// `TAKEN` or `REFUSED`.
static KNOWN: AtomicU32 = AtomicU32::new(0);
const TAKEN: u32 = 1;
const REFUSED: u32 = 2;

/// Forgets the answers: the kernel's modules may have changed.
pub(super) fn forget() {
    KNOWN.store(0, Relaxed);
}

/// A connected loopback TCP socket, and the listener whose queue keeps it
/// connected (nothing has to accept it).
fn loopback() -> io::Result<(TcpListener, TcpStream)> {
    let mut last = None;
    for address in [
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
    ] {
        let connected = TcpListener::bind(address).and_then(|listener| {
            let socket = TcpStream::connect(listener.local_addr()?)?;
            Ok((listener, socket))
        });
        match connected {
            Ok(pair) => return Ok(pair),
            Err(err) => last = Some(err),
        }
    }
    Err(last.unwrap_or_else(|| io::ErrorKind::AddrNotAvailable.into()))
}

/// Asks the kernel to attach the `tls` upper layer protocol to one end of
/// a loopback connection, which it does only for a connected TCP socket.
pub(super) fn upper_layer_protocol() -> io::Result<()> {
    let (_listener, socket) = loopback()?;
    sys::set_ulp_tls(socket.as_fd())
}

/// Gives the kernel the option value `info` for both directions of a
/// loopback socket of its own. The outer error is that no such socket
/// with the upper layer protocol could be had, which says nothing about
/// `info`; the inner one is the kernel's refusal of it.
fn ask(info: &[u8]) -> io::Result<io::Result<()>> {
    let (_listener, socket) = loopback()?;
    sys::set_ulp_tls(socket.as_fd())?;
    Ok(sys::set_crypto_info(socket.as_fd(), false, info)
        .and_then(|()| sys::set_crypto_info(socket.as_fd(), true, info)))
}

/// The kernel's refusal of keys, as the reason a connection stays in
/// userspace.
fn refusal(error: Option<&io::Error>) -> io::Error {
    let what = "the kernel does not take keys of the connection's cipher";
    match error {
        Some(error) => io::Error::new(io::ErrorKind::Unsupported, format!("{what}: {error}")),
        None => io::Error::new(io::ErrorKind::Unsupported, what),
    }
}

/// What is known about `form`: zero, `TAKEN` or `REFUSED`.
fn known(form: Form) -> u32 {
    (KNOWN.load(Relaxed) >> (2 * form as u32)) & 3
}

/// Whether the kernel takes keys of `form`, asking it if that is not
/// known yet.
fn takes_form(form: Form) -> io::Result<()> {
    match known(form) {
        TAKEN => return Ok(()),
        REFUSED => return Err(refusal(None)),
        _ => {}
    }
    let answer = ask(form.crypto_info()?.as_bytes())?;
    let state = match &answer {
        Ok(()) => TAKEN,
        // No such cipher or version, or no implementation of it: the
        // kernel will say so again. Anything else (no memory, say) may
        // pass, and is this one connection's refusal only.
        Err(error) => match error.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported => {
                REFUSED
            }
            _ => return answer,
        },
    };
    // The first answer stays, should threads that ask at the same time
    // ever get different ones.
    let shift = 2 * form as u32;
    let _ = KNOWN.try_update(Relaxed, Relaxed, |known| {
        ((known >> shift) & 3 == 0).then_some(known | (state << shift))
    });
    answer.map_err(|error| refusal(Some(&error)))
}

/// The forms a connection with `suite` can have: its own or, while it has
/// no suite yet (a client in its 0-RTT phase), those of TLS 1.3. A suite
/// without a form here is left to the handover, which refuses what has no
/// kernel form before it takes anything.
fn forms(suite: Option<SupportedCipherSuite>) -> impl Iterator<Item = Form> {
    let (own, any) = match suite {
        Some(suite) => (Form::of(suite), &[][..]),
        None => (None, &Form::TLS13[..]),
    };
    own.into_iter().chain(any.iter().copied())
}

/// Readies `socket` for the handover of a connection with `suite`:
/// attaches the `tls` upper layer protocol and makes sure that the kernel
/// takes keys of the connection's record protection. A cipher known to be
/// refused leaves the socket untouched.
///
/// # Errors
///
/// What the kernel answered: the connection stays in userspace.
/// [`io::ErrorKind::Unsupported`] when it refused such keys.
pub(super) fn ready(suite: Option<SupportedCipherSuite>, socket: BorrowedFd<'_>) -> io::Result<()> {
    if forms(suite).any(|form| known(form) == REFUSED) {
        return Err(refusal(None));
    }
    sys::set_ulp_tls(socket)?;
    forms(suite).try_for_each(takes_form)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::common::{kernel_tls, offloadable_suites, tcp_pair};

    /// Every suite the tests hand over has a form, the forms make option
    /// values the kernel is given, and a kernel with the `tls` module
    /// takes each of them and refuses a cipher it does not know.
    #[test]
    fn the_kernel_is_asked_for_each_form() {
        for suite in offloadable_suites() {
            assert_eq!(forms(Some(suite)).count(), 1, "{suite:?}");
        }
        assert!(forms(None).eq(Form::TLS13));
        let all = || Form::TLS13.into_iter().chain(Form::TLS12);
        let mut lens: Vec<usize> = all()
            .map(|form| form.crypto_info().unwrap().as_bytes().len())
            .collect();
        lens.dedup();
        assert!(lens.len() > 1, "{lens:?}");

        let (socket, _peer) = tcp_pair();
        forget();
        if !kernel_tls()
            && let Err(error) = ready(None, socket.as_fd())
        {
            // Without the upper layer protocol nothing can be asked, and
            // nothing is concluded. (A process that may load the module
            // gets it loaded by asking.)
            assert_ne!(error.kind(), io::ErrorKind::Unsupported, "{error}");
            assert_eq!(KNOWN.load(Relaxed), 0);
            return;
        }
        for form in all() {
            takes_form(form).unwrap_or_else(|error| panic!("{form:?}: {error}"));
            // The answer is kept.
            assert_eq!(known(form), TAKEN);
            takes_form(form).unwrap();
        }
        ready(None, socket.as_fd()).unwrap();
        for suite in offloadable_suites() {
            ready(Some(suite), socket.as_fd()).unwrap();
        }

        // A cipher type no kernel has is refused as unsupported.
        let info = Form::Tls13Aes128Gcm.crypto_info().unwrap();
        let mut bytes = info.as_bytes().to_vec();
        bytes[2..4].copy_from_slice(&0xffffu16.to_ne_bytes());
        let error = ask(&bytes).unwrap().unwrap_err();
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
            ),
            "{error}"
        );

        // A refusal that was kept is reported without asking and is not
        // replaced by a later answer.
        let (untouched, _peer) = tcp_pair();
        let shift = 2 * Form::Tls13Aes128Ccm as u32;
        forget();
        KNOWN.fetch_or(REFUSED << shift, Relaxed);
        let error = takes_form(Form::Tls13Aes128Ccm).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        let error = ready(None, untouched.as_fd()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        takes_form(Form::Tls13Aes128Gcm).unwrap();
        assert_eq!(known(Form::Tls13Aes128Ccm), REFUSED);
        assert_eq!(known(Form::Tls13Aes128Gcm), TAKEN);
        forget();
    }
}
