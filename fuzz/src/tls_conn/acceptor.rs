//! The standalone `Acceptor` operation of the `tls_conn` target and the
//! `ClientHello` accessor calls.

use std::sync::Arc;

use browntls::ServerConfig;
use browntls::server::{Accepted, Acceptor};

use super::transport::Limited;

/// Calls every `ClientHello` accessor.
pub(super) fn check_client_hello(accepted: &Accepted) {
    let hello = accepted.client_hello();
    let _ = (
        hello.server_name().map(str::len),
        hello.signature_schemes().len(),
        hello.alpn().map(Iterator::count),
        hello.cipher_suites().len(),
        hello.certificate_authorities().map(<[_]>::len),
        hello.named_groups().map(<[_]>::len),
        hello.client_cert_types().map(<[_]>::len),
        hello.server_cert_types().map(<[_]>::len),
    );
    let _ = format!("{accepted:?}");
}

/// A standalone `Acceptor` fed `bytes` in `chunk`-byte pieces.
pub(super) fn acceptor(bytes: &[u8], chunk: usize, config: Option<Arc<ServerConfig>>) {
    let mut acceptor = Acceptor::default();
    let mut rest = bytes;
    let mut sink = Vec::new();
    for _ in 0..64 {
        let n = chunk.min(rest.len());
        let mut piece = &rest[..n];
        let _ = acceptor.read_tls(&mut piece);
        rest = &rest[n - piece.len()..];
        match acceptor.accept() {
            Ok(None) => {
                if n == 0 {
                    break;
                }
            }
            Ok(Some(accepted)) => {
                check_client_hello(&accepted);
                if let Some(config) = config {
                    match accepted.into_connection(config) {
                        Ok(mut conn) => {
                            let _ = conn.process_new_packets();
                            let _ = conn.write_tls(&mut sink);
                        }
                        Err((_, mut alert)) => {
                            let _ = alert.write(&mut Limited(&mut sink, 3));
                            let _ = alert.write_all(&mut sink);
                        }
                    }
                }
                // The acceptor is spent now.
                assert!(acceptor.read_tls(&mut &b"\x16"[..]).is_err());
                break;
            }
            Err((_, mut alert)) => {
                let _ = alert.write(&mut Limited(&mut sink, 3));
                let _ = alert.write_all(&mut sink);
                let _ = format!("{alert:?}");
                break;
            }
        }
    }
    if let Err((_, mut alert)) = acceptor.accept() {
        let _ = alert.write_all(&mut sink);
    }
    let _ = format!("{acceptor:?}");
}
