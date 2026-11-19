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
use std::os::fd::AsFd;
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
    const ALL: [Self; 7] = [
        Self::Tls13Aes128Gcm,
        Self::Tls13Aes256Gcm,
        Self::Tls13ChaCha20Poly1305,
        Self::Tls13Aes128Ccm,
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

fn refusal(error: &io::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("the kernel does not take keys of the connection's cipher: {error}"),
    )
}

fn takes_form(form: Form) -> io::Result<()> {
    let shift = 2 * form as u32;
    match (KNOWN.load(Relaxed) >> shift) & 3 {
        TAKEN => return Ok(()),
        REFUSED => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the kernel does not take keys of the connection's cipher",
            ));
        }
        _ => {}
    }
    let answer = ask(form.crypto_info()?.as_bytes())?;
    let state = if answer.is_ok() { TAKEN } else { REFUSED };
    // Threads that ask at the same time store the same answer.
    KNOWN.fetch_or(state << shift, Relaxed);
    answer.map_err(|error| refusal(&error))
}

/// Whether the kernel takes keys of the record protection of `suite`, or
/// of every one it has a form for when the connection has no suite yet (a
/// client in its 0-RTT phase).
///
/// # Errors
///
/// [`io::ErrorKind::Unsupported`] when the kernel refused such keys;
/// another error when it could not be asked.
pub(super) fn takes(suite: Option<SupportedCipherSuite>) -> io::Result<()> {
    match suite {
        Some(suite) => Form::of(suite).map_or(Ok(()), takes_form),
        None => Form::ALL.into_iter().try_for_each(takes_form),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::common::{kernel_tls, offloadable_suites};

    /// Every suite the tests hand over has a form, the forms make option
    /// values the kernel is given, and a kernel with the `tls` module
    /// takes each of them and refuses a cipher it does not know.
    #[test]
    fn the_kernel_is_asked_for_each_form() {
        for suite in offloadable_suites() {
            assert!(Form::of(suite).is_some(), "{suite:?}");
        }
        let mut lens: Vec<usize> = Form::ALL
            .iter()
            .map(|form| form.crypto_info().unwrap().as_bytes().len())
            .collect();
        lens.dedup();
        assert!(lens.len() > 1, "{lens:?}");

        if !kernel_tls() {
            // Without the upper layer protocol nothing can be asked.
            let error = takes(None).unwrap_err();
            assert_ne!(error.kind(), io::ErrorKind::Unsupported, "{error}");
            return;
        }
        forget();
        for form in Form::ALL {
            takes_form(form).unwrap_or_else(|error| panic!("{form:?}: {error}"));
            // The answer is kept.
            assert_eq!((KNOWN.load(Relaxed) >> (2 * form as u32)) & 3, TAKEN);
            takes_form(form).unwrap();
        }
        takes(None).unwrap();
        for suite in offloadable_suites() {
            takes(Some(suite)).unwrap();
        }

        // A cipher type no kernel has.
        let info = Form::Tls13Aes128Gcm.crypto_info().unwrap();
        let mut bytes = info.as_bytes().to_vec();
        bytes[2..4].copy_from_slice(&0xffffu16.to_ne_bytes());
        let error = ask(&bytes).unwrap().unwrap_err();
        assert_eq!(refusal(&error).kind(), io::ErrorKind::Unsupported);
        // A refusal that was kept is reported without asking.
        let shift = 2 * Form::Tls13Aes128Ccm as u32;
        forget();
        KNOWN.fetch_or(REFUSED << shift, Relaxed);
        let error = takes_form(Form::Tls13Aes128Ccm).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(takes(None).unwrap_err().kind(), io::ErrorKind::Unsupported);
        forget();
    }
}
