//! No `SIGPIPE` from files sent on a kernel TLS socket, against the running
//! kernel: not from `sendfile` on a connection that is closed for sending
//! (kernel TLS raises the signal there while it reports bytes as sent), and
//! not from closing the socket with such records still in the kernel.
//!
//! The deliveries are counted by a handler that takes the place of the test
//! harness's ignoring the signal, which is why these tests live with the
//! crate's `unsafe` code and not among the integration tests.
//!
//! Skipped without the `tls` module unless `BROWNTLS_KTLS_REQUIRED=1`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../tests/common/mod.rs"]
mod common;

use std::net::{Shutdown, TcpStream};
use std::os::fd::AsFd;
use std::sync::{Arc, mpsc};
use std::thread;

use browntls::{ClientConnection, ServerConnection, StreamOwned, SupportedCipherSuite};

use crate::KtlsStream;
use crate::sys::test_signals::{sigpipe_pending, sigpipes_delivered};
use common::{Pki, kernel_tls, localhost, offloadable_suites, pattern, tcp_pair, temp_file};

/// One TLS 1.3 and one TLS 1.2 suite, as far as the provider has them.
fn suites() -> Vec<SupportedCipherSuite> {
    let all = offloadable_suites();
    let mut picked: Vec<SupportedCipherSuite> = Vec::new();
    for suite in all {
        if picked
            .iter()
            .all(|other| other.version().version != suite.version().version)
        {
            picked.push(suite);
        }
    }
    picked
}

/// A userspace server that completes the handshake on `tcp` and then keeps
/// the connection open, reading nothing, until `done` is dropped.
fn idle_server(pki: &Pki, suite: SupportedCipherSuite, tcp: TcpStream, done: mpsc::Receiver<()>) {
    let conn = ServerConnection::new(Arc::new(pki.server_config(suite))).unwrap();
    let mut tls = StreamOwned::new(conn, tcp);
    while tls.conn.is_handshaking() || tls.conn.wants_write() {
        tls.conn.complete_io(&mut tls.sock).unwrap();
    }
    let _ = done.recv();
}

/// Closes the socket's write side behind the stream's back.
fn shut_write(socket: &impl AsFd) {
    let other = TcpStream::from(socket.as_fd().try_clone_to_owned().unwrap());
    other.shutdown(Shutdown::Write).unwrap();
}

/// Asserts that no `SIGPIPE` was delivered since the count was `before`
/// and that none is left pending for this thread.
#[track_caller]
fn assert_quiet(before: usize, what: &str) {
    assert_eq!(sigpipes_delivered(), before, "a SIGPIPE from {what}");
    assert!(!sigpipe_pending(), "a SIGPIPE left pending by {what}");
}

#[test]
fn files_sent_on_a_closed_connection_raise_no_sigpipe() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let file = temp_file(&pattern(1 << 20, 5));
    for suite in suites() {
        let (client_tcp, server_tcp) = tcp_pair();
        let (done, wait) = mpsc::channel();
        thread::scope(|scope| {
            scope.spawn(|| idle_server(&pki, suite, server_tcp, wait));
            let conn =
                ClientConnection::new(Arc::new(pki.client_config(suite)), localhost()).unwrap();
            let mut tls = KtlsStream::new(conn, client_tcp).unwrap();
            let before = sigpipes_delivered();

            assert_eq!(tls.sendfile(&file, 0, 100_000).unwrap(), 100_000);
            shut_write(tls.get_ref());
            // The kernel reports some of these as sent and fails others:
            // either way it raises the signal, which must not arrive.
            let mut outcomes = Vec::new();
            for _ in 0..4 {
                outcomes.push(
                    tls.sendfile(&file, 100_000, 100_000)
                        .map_err(|err| err.kind()),
                );
                assert_quiet(before, "`sendfile`");
            }
            eprintln!("{suite:?}: after the write side was closed: {outcomes:?}");

            // The records the kernel still holds are sent, and fail, when
            // the socket is closed.
            drop(tls);
            assert_quiet(before, "dropping the stream");
            drop(done);
        });
    }
}

#[cfg(feature = "tokio")]
#[test]
fn files_sent_by_the_async_stream_raise_no_sigpipe() {
    use browntls_tokio::{TlsAcceptor, TlsConnector};

    use crate::AsyncKtlsStream;

    if !kernel_tls() {
        return;
    }
    let to_tokio = |tcp: TcpStream| {
        tcp.set_nonblocking(true).unwrap();
        tokio::net::TcpStream::from_std(tcp).unwrap()
    };
    let pki = Pki::new();
    let file = temp_file(&pattern(1 << 20, 6));
    // One thread: the signal is counted and looked for where it is raised.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for suite in suites() {
        runtime.block_on(async {
            let (client_tcp, server_tcp) = tcp_pair();
            let (client, server) = tokio::join!(
                TlsConnector::from(Arc::new(pki.client_config(suite)))
                    .connect(localhost(), to_tokio(client_tcp)),
                TlsAcceptor::from(Arc::new(pki.server_config(suite))).accept(to_tokio(server_tcp)),
            );
            let _server = server.unwrap();
            let mut tls = AsyncKtlsStream::from_client(client.unwrap()).await.unwrap();
            let before = sigpipes_delivered();

            assert_eq!(tls.sendfile(&file, 0, 100_000).await.unwrap(), 100_000);
            shut_write(tls.get_ref());
            let mut outcomes = Vec::new();
            for _ in 0..4 {
                let sent = tls.sendfile(&file, 100_000, 100_000);
                let sent = tokio::time::timeout(std::time::Duration::from_secs(10), sent).await;
                outcomes.push(sent.map(|sent| sent.map_err(|err| err.kind())).ok());
                assert_quiet(before, "`sendfile`");
            }
            eprintln!("{suite:?}: after the write side was closed: {outcomes:?}");

            drop(tls);
            assert_quiet(before, "dropping the stream");
        });
    }
}
