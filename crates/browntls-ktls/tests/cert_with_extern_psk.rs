//! Blocking and Tokio Linux kTLS handoff after RFC 8773 certificate
//! authentication with an external PSK.

#![cfg(all(target_os = "linux", any(feature = "native", feature = "rustcrypto")))]
#![deny(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use browntls_core::psk::ExternalPsk;
use browntls_core::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use browntls_ktls::KtlsStream;
use common::{Pki, kernel_tls, offloadable_suites, tcp_pair};

fn tls13_suite() -> browntls_core::SupportedCipherSuite {
    offloadable_suites()
        .into_iter()
        .find(|suite| suite.version().version == browntls_core::ProtocolVersion::TLSv1_3)
        .expect("provider has an offloadable TLS 1.3 suite")
}

fn client_config(pki: &Pki, suite: browntls_core::SupportedCipherSuite) -> ClientConfig {
    let mut config = pki.client_config(suite);
    config.external_psks = vec![Arc::new(
        ExternalPsk::new(
            b"ktls-certificate-psk".to_vec(),
            vec![0x6b; 32],
            suite.tls13().unwrap().common.hash_provider.algorithm(),
        )
        .unwrap(),
    )];
    config.cert_with_extern_psk = true;
    config.require_cert_with_extern_psk = true;
    config.require_external_psk = true;
    config
}

fn server_config(pki: &Pki, suite: browntls_core::SupportedCipherSuite) -> ServerConfig {
    let mut config = pki.server_config(suite);
    config.external_psks = Some(Arc::new(vec![Arc::new(
        ExternalPsk::new(
            b"ktls-certificate-psk".to_vec(),
            vec![0x6b; 32],
            suite.tls13().unwrap().common.hash_provider.algorithm(),
        )
        .unwrap(),
    )]));
    // Requiring the extension also opts the server in.
    config.require_cert_with_extern_psk = true;
    config
}

#[test]
fn blocking_connections_handoff_certificate_external_psk_sessions_to_kernel() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let suite = tls13_suite();
    let (client_tcp, server_tcp) = tcp_pair();

    std::thread::scope(|scope| {
        let server_pki = &pki;
        let server = scope.spawn(move || {
            let conn = ServerConnection::new(Arc::new(server_config(server_pki, suite))).unwrap();
            let mut tls = KtlsStream::new(conn, server_tcp).unwrap();
            let common = tls.kernel_connection().common_state();
            assert!(common.negotiated_cert_with_extern_psk());
            assert_eq!(
                common.external_psk_identity(),
                Some(&b"ktls-certificate-psk"[..])
            );
            let mut request = [0; 17];
            std::io::Read::read_exact(&mut tls, &mut request).unwrap();
            assert_eq!(&request, b"blocking kTLS PSK");
            std::io::Write::write_all(&mut tls, b"server reply").unwrap();
        });

        let conn = ClientConnection::new(Arc::new(client_config(&pki, suite)), common::localhost())
            .unwrap();
        let mut tls = KtlsStream::new(conn, client_tcp).unwrap();
        let common = tls.kernel_connection().common_state();
        assert!(common.negotiated_cert_with_extern_psk());
        assert_eq!(
            common.external_psk_identity(),
            Some(&b"ktls-certificate-psk"[..])
        );
        std::io::Write::write_all(&mut tls, b"blocking kTLS PSK").unwrap();
        let mut reply = [0; 12];
        std::io::Read::read_exact(&mut tls, &mut reply).unwrap();
        assert_eq!(&reply, b"server reply");
        server.join().unwrap();
    });
}

#[cfg(feature = "tokio")]
mod tokio_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::common::{localhost, tcp_pair};
    use super::{Pki, client_config, server_config, tls13_suite};
    use browntls_core::client::ClientConnectionData;
    use browntls_core::server::ServerConnectionData;
    use browntls_ktls::AsyncKtlsStream;
    use browntls_tokio::{TlsAcceptor, TlsConnector};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    const LIMIT: Duration = Duration::from_secs(30);

    fn to_tokio(tcp: std::net::TcpStream) -> TcpStream {
        tcp.set_nonblocking(true).unwrap();
        TcpStream::from_std(tcp).unwrap()
    }

    #[tokio::test]
    async fn tokio_streams_handoff_certificate_external_psk_sessions_to_kernel() {
        if !super::common::kernel_tls() {
            return;
        }
        let pki = Pki::new();
        let suite = tls13_suite();
        let (client_tcp, server_tcp) = tcp_pair();
        let (client_tcp, server_tcp) = (to_tokio(client_tcp), to_tokio(server_tcp));
        let (client_config, server_config) =
            (client_config(&pki, suite), server_config(&pki, suite));
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(
                TlsConnector::from(Arc::new(client_config)).connect(localhost(), client_tcp),
                TlsAcceptor::from(Arc::new(server_config)).accept(server_tcp),
            )
        })
        .await
        .unwrap();
        let (client, server) = (client.unwrap(), server.unwrap());
        assert!(client.get_ref().1.negotiated_cert_with_extern_psk());
        assert!(server.get_ref().1.negotiated_cert_with_extern_psk());
        assert_eq!(
            client.get_ref().1.external_psk_identity(),
            Some(&b"ktls-certificate-psk"[..])
        );
        assert_eq!(
            server.get_ref().1.external_psk_identity(),
            Some(&b"ktls-certificate-psk"[..])
        );

        let (client, server) = tokio::join!(
            timeout(LIMIT, AsyncKtlsStream::from_client(client)),
            timeout(LIMIT, AsyncKtlsStream::from_server(server)),
        );
        let mut client: AsyncKtlsStream<ClientConnectionData> =
            client.expect("client kTLS handoff timed out").unwrap();
        let mut server: AsyncKtlsStream<ServerConnectionData> =
            server.expect("server kTLS handoff timed out").unwrap();

        assert!(
            client
                .kernel_connection()
                .common_state()
                .negotiated_cert_with_extern_psk()
        );
        assert!(
            server
                .kernel_connection()
                .common_state()
                .negotiated_cert_with_extern_psk()
        );
        client.write_all(b"Tokio kTLS PSK").await.unwrap();
        let mut request = [0; 14];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"Tokio kTLS PSK");
        server.write_all(b"Tokio reply").await.unwrap();
        let mut reply = [0; 11];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"Tokio reply");
    }
}
