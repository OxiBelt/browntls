//! Stapled responses produced and served by OpenSSL.

use browntls::client::WebPkiServerVerifier;
use browntls::revocation::{RevocationDigests, RevocationPolicy, RevocationStatus};

use super::{
    Arc, ClientConfig, ClientConnection, KeyType, STEP, ServerName, SupportedProtocolVersion,
    TcpStream, TempDir, finish, native, openssl_or_skip, pki, run, start_s_server, version,
};

fn stapled(version: &'static SupportedProtocolVersion, tls_arg: &str, matching: bool) {
    let Some(openssl) = openssl_or_skip() else {
        return;
    };
    let issuer = pki(openssl, KeyType::EcdsaP256);
    let tmp = TempDir::new();
    let ca = issuer.path("ca.pem");
    let ca_key = issuer.path("ca.key");
    let server = issuer.path("server.pem");
    let server_key = issuer.path("server.key");
    let response_cert = if matching {
        server.clone()
    } else {
        issuer.path("client.pem")
    };
    let serial = if matching { "02" } else { "03" };
    std::fs::write(
        tmp.0.join("index"),
        format!("V\t490101000000Z\t\t{serial}\tunknown\t/CN=localhost\n"),
    )
    .unwrap();
    run(
        openssl,
        &tmp.0,
        &[
            "ocsp",
            "-index",
            "index",
            "-rsigner",
            &ca,
            "-rkey",
            &ca_key,
            "-CA",
            &ca,
            "-issuer",
            &ca,
            "-cert",
            &response_cert,
            "-ndays",
            "1",
            "-respout",
            "response.der",
        ],
    );
    let response = tmp.0.join("response.der").to_str().unwrap().to_owned();
    let (child, rx, port) = start_s_server(
        openssl,
        &|port| {
            [
                "s_server",
                "-accept",
                port,
                "-naccept",
                "1",
                "-rev",
                "-cert",
                &server,
                "-key",
                &server_key,
                "-status_file",
                &response,
                tls_arg,
            ]
            .into_iter()
            .map(String::from)
            .collect()
        },
        &[],
    )
    .unwrap();

    let provider = Arc::new(native::default_provider());
    let verifier = WebPkiServerVerifier::builder_with_provider(issuer.roots(), provider.clone())
        .with_revocation_policy(RevocationPolicy::new(RevocationDigests::native()))
        .build()
        .unwrap();
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let mut conn =
        ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
            .unwrap();
    let mut socket = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    socket.set_read_timeout(Some(STEP)).unwrap();
    socket.set_write_timeout(Some(STEP)).unwrap();
    let result = conn.complete_io(&mut socket);
    let status = conn.peer_revocation_status();
    if result.is_ok() {
        conn.send_close_notify();
        let _ = conn.complete_io(&mut socket);
    }
    drop(socket);
    let (_, out, err) = finish(child, Some(rx));
    if matching {
        assert!(result.is_ok(), "{result:?}\n{out}\n{err}");
        assert_eq!(status, Some(RevocationStatus::Good));
    } else {
        let tls = result.unwrap_err();
        assert_eq!(
            tls.get_ref()
                .and_then(|err| err.downcast_ref::<browntls::Error>()),
            Some(&browntls::Error::InvalidCertificate(
                browntls::CertificateError::InvalidOcspResponse
            )),
            "{tls:?}\n{out}\n{err}",
        );
    }
}

#[test]
fn openssl_generated_tls13_staple() {
    stapled(&version::TLS13, "-tls1_3", true);
}

#[cfg(feature = "tls12")]
#[test]
fn openssl_generated_tls12_staple() {
    stapled(&version::TLS12, "-tls1_2", true);
}

#[test]
fn openssl_generated_staple_for_another_certificate_is_rejected() {
    stapled(&version::TLS13, "-tls1_3", false);
}
