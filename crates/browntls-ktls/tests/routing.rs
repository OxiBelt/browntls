//! Connections placed by the load-aware routing (`browntls_ktls::routing`):
//! in userspace while kernel TLS is not in the order, with the kernel
//! while it is, back in userspace when the kernel cannot take them or the
//! routing keeps them there, and timed in both places.
//!
//! The routing's state is process-wide, so everything runs in one test
//! function (each integration test file is its own process). The parts
//! that need kernel TLS are skipped without the `tls` module unless
//! `BROWNTLS_KTLS_REQUIRED=1`.

#![cfg(all(target_os = "linux", feature = "native"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;

use browntls::crypto::native::accel::load::{self, Config, Phase, kernel};
use browntls::{ClientConnection, ServerConnection, SupportedCipherSuite};
use browntls_ktls::routing::{self, Place, Records, RoutedStream};
use common::*;

/// One full record per write, so that every write is long enough to time.
const WRITE: usize = 16384;

/// What became of one end of a connection.
#[derive(Debug)]
struct End {
    place: Place,
    /// The kind of the kernel's refusal, for an end that was placed with
    /// the kernel and stayed in userspace.
    refusal: Option<io::ErrorKind>,
}

impl End {
    fn of<C: browntls_ktls::Offload>(tls: &RoutedStream<C, TcpStream>) -> Self {
        Self {
            place: tls.place(),
            refusal: match tls {
                RoutedStream::Kernel(_) => None,
                RoutedStream::Userspace(stream) => stream.kernel_refusal().map(io::Error::kind),
            },
        }
    }
}

/// Runs one connection with `suite` between two routed ends over loopback,
/// `writes` records of data in each direction and an orderly close, and
/// returns what became of the client's and the server's end.
fn connection(pki: &Pki, suite: SupportedCipherSuite, writes: usize, extraction: bool) -> [End; 2] {
    let (client_tcp, server_tcp) = tcp_pair();
    let up = pattern(writes * WRITE, 1);
    let down = pattern(writes * WRITE, 2);
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let mut config = pki.server_config(suite);
            config.enable_secret_extraction = extraction;
            let conn = ServerConnection::new(Arc::new(config)).unwrap();
            let mut tls = RoutedStream::new(conn, server_tcp).unwrap();
            let end = End::of(&tls);
            assert_eq!(read_n(&mut tls, up.len()).unwrap(), up, "{suite:?}");
            for chunk in down.chunks(WRITE) {
                tls.write_all(chunk).unwrap();
            }
            tls.flush().unwrap();
            let mut rest = Vec::new();
            tls.read_to_end(&mut rest).unwrap();
            assert!(rest.is_empty(), "{suite:?}");
            tls.send_close_notify().unwrap();
            end
        });
        let mut config = pki.client_config(suite);
        config.enable_secret_extraction = extraction;
        let conn = ClientConnection::new(Arc::new(config), localhost()).unwrap();
        let mut tls = RoutedStream::new(conn, client_tcp).unwrap();
        let end = End::of(&tls);
        for chunk in up.chunks(WRITE) {
            tls.write_all(chunk).unwrap();
        }
        tls.flush().unwrap();
        assert_eq!(read_n(&mut tls, down.len()).unwrap(), down, "{suite:?}");
        tls.send_close_notify().unwrap();
        let mut rest = Vec::new();
        tls.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "{suite:?}");
        [end, server.join().unwrap()]
    })
}

/// The stream that places connections with `suite`, by the suite's name.
fn records_of(suite: SupportedCipherSuite) -> Option<Records> {
    let name = format!("{:?}", suite.suite());
    if name.contains("AES_128_GCM") {
        Some(Records::Aes128Gcm)
    } else if name.contains("AES_256_GCM") {
        Some(Records::Aes256Gcm)
    } else if name.contains("CHACHA20_POLY1305") {
        Some(Records::ChaCha20Poly1305)
    } else {
        None
    }
}

#[test]
fn connections_go_where_the_routing_places_them() {
    let pki = Pki::new();
    let suites = offloadable_suites();
    let has_kernel_tls = kernel_tls();
    let routed: Vec<(SupportedCipherSuite, Records)> = suites
        .iter()
        .filter_map(|suite| Some((*suite, records_of(*suite)?)))
        .collect();
    assert!(routed.len() >= 3, "{suites:?}");
    assert!(
        routed.len() < suites.len(),
        "AES-CCM has no stream: {suites:?}"
    );

    // Kernel TLS is not in the order: every connection stays in
    // userspace and the kernel is not asked, with routing off or on.
    assert!(!routing::is_active());
    for enabled in [false, true] {
        if enabled {
            load::enable(Config::DEFAULT).unwrap();
        }
        for suite in &suites {
            for end in connection(&pki, *suite, 2, true) {
                assert_eq!(
                    (end.place, end.refusal),
                    (Place::Userspace, None),
                    "{suite:?}"
                );
            }
        }
        assert_eq!(kernel::status_all().count(), 0);
    }
    load::disable();

    // Activating asks the running kernel, which may load the `tls` module
    // for it.
    let has_kernel_tls = match routing::activate() {
        Ok(()) => true,
        Err(err) => {
            assert!(!has_kernel_tls && !routing::is_active(), "{err}");
            // Put it in the order all the same: a kernel that refuses.
            kernel::activate();
            false
        }
    };
    assert!(routing::is_active());

    // In the order: every connection goes to the kernel, or stays in
    // userspace with the kernel's refusal when it cannot go.
    for suite in &suites {
        for end in connection(&pki, *suite, 2, true) {
            if has_kernel_tls {
                assert_eq!((end.place, end.refusal), (Place::Kernel, None), "{suite:?}");
            } else {
                assert_eq!(end.place, Place::Userspace, "{suite:?}");
                assert!(end.refusal.is_some(), "{suite:?}");
            }
        }
        // A connection without a kernel form is refused before the kernel
        // is asked.
        for end in connection(&pki, *suite, 1, false) {
            assert_eq!(
                (end.place, end.refusal),
                (Place::Userspace, Some(io::ErrorKind::Unsupported)),
                "{suite:?}"
            );
        }
    }

    // With load-aware routing the writes are timed where they happen.
    load::enable(Config::DEFAULT).unwrap();
    // The streams whose kernel side was timed: suites of one key size
    // share a stream, and fixing a share keeps what was measured.
    let mut kernel_timed = Vec::new();
    for (suite, records) in &routed {
        // Kept in userspace by the routing: the kernel is not asked.
        kernel::set_fixed(*records, 100).unwrap();
        for end in connection(&pki, *suite, 400, true) {
            assert_eq!(
                (end.place, end.refusal),
                (Place::Userspace, None),
                "{suite:?}"
            );
        }
        let s = kernel::status(*records).unwrap();
        println!("{s}");
        assert_eq!((s.phase, s.shifted_percent), (Phase::Fixed, 100));
        assert!(s.alternate_cost.is_some_and(|ps| ps > 0), "{s}");
        assert_eq!(
            s.primary_cost.is_some(),
            kernel_timed.contains(records),
            "{s}"
        );

        // All with the kernel.
        kernel::set_fixed(*records, 0).unwrap();
        let ends = connection(&pki, *suite, 400, true);
        if has_kernel_tls {
            kernel_timed.push(*records);
        }
        let s = kernel::status(*records).unwrap();
        println!("{s}");
        for end in ends {
            if has_kernel_tls {
                assert_eq!((end.place, end.refusal), (Place::Kernel, None), "{suite:?}");
                assert!(s.primary_cost.is_some_and(|ps| ps > 0), "{s}");
            } else {
                // Refused connections are timed as what they are.
                assert_eq!(end.place, Place::Userspace, "{suite:?}");
                assert!(end.refusal.is_some(), "{suite:?}");
                assert_eq!(s.primary_cost, None, "{s}");
            }
        }

        // Half and half: ends in different places talk to each other.
        kernel::set_fixed(*records, 50).unwrap();
        let mut kept = 0;
        for _ in 0..16 {
            for end in connection(&pki, *suite, 2, true) {
                if end.refusal.is_none() && end.place == Place::Userspace {
                    kept += 1;
                } else {
                    assert_eq!(end.place == Place::Kernel, has_kernel_tls, "{suite:?}");
                }
            }
        }
        assert!((1..32).contains(&kept), "{suite:?}: {kept} of 32 ends");
        kernel::clear_fixed(*records);
    }
    // A suite without a stream follows the order.
    for suite in suites.iter().filter(|suite| records_of(**suite).is_none()) {
        for end in connection(&pki, *suite, 2, true) {
            assert_eq!(end.place == Place::Kernel, has_kernel_tls, "{suite:?}");
        }
    }

    // Out of the order again.
    routing::deactivate();
    assert!(!routing::is_active());
    for (suite, _) in &routed {
        for end in connection(&pki, *suite, 2, true) {
            assert_eq!(
                (end.place, end.refusal),
                (Place::Userspace, None),
                "{suite:?}"
            );
        }
    }
    load::disable();
}
