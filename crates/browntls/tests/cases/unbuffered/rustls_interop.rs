// Cases included by `cases/unbuffered.rs`, which holds the imports and the
// shared plumbing: unbuffered connections against rustls.

// ------------------------------------------------------------ rustls interop

mod interop {
    use super::*;
    use rustls_pki_types as rpki;

    /// A rustls 0.23 connection on the buffered API.
    struct Rustls<C> {
        conn: C,
        received: Vec<u8>,
        failed: bool,
    }

    impl<C, D> Endpoint for Rustls<C>
    where
        C: std::ops::DerefMut<Target = rustls::ConnectionCommon<D>>,
        D: rustls::SideData,
    {
        fn take_output(&mut self) -> Vec<u8> {
            let mut out = Vec::new();
            while self.conn.wants_write() {
                self.conn.write_tls(&mut out).unwrap();
            }
            out
        }

        fn give_input(&mut self, mut bytes: &[u8]) {
            while !bytes.is_empty() && !self.failed {
                self.conn.read_tls(&mut bytes).unwrap();
                if self.conn.process_new_packets().is_err() {
                    self.failed = true;
                }
                match self.conn.reader().read_to_end(&mut self.received) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("read: {e}"),
                }
            }
        }

        fn failed(&self) -> bool {
            self.failed
        }

        fn describe(&self) -> String {
            format!("rustls failed: {}", self.failed)
        }

        fn handshaking(&self) -> bool {
            self.conn.is_handshaking()
        }

        fn send(&mut self, data: &[u8]) {
            self.conn.writer().write_all(data).unwrap();
        }

        fn take_received(&mut self) -> Vec<u8> {
            std::mem::take(&mut self.received)
        }
    }

    static R_TLS12: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS12];
    static R_TLS13: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];

    fn r_versions(v: ProtocolVersion) -> &'static [&'static rustls::SupportedProtocolVersion] {
        match v {
            ProtocolVersion::TLSv1_2 => &R_TLS12,
            _ => &R_TLS13,
        }
    }

    fn r_provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    #[test]
    fn unbuffered_client_to_rustls_server() {
        init_logging();
        let chain = server_chain(KeyType::EcdsaP256);
        for v in VERSIONS {
            let certs = chain
                .cert_chain()
                .iter()
                .map(|c| rpki::CertificateDer::from(c.as_ref().to_vec()))
                .collect();
            let key = rpki::PrivateKeyDer::Pkcs8(rpki::PrivatePkcs8KeyDer::from(
                chain.end_entity_key.clone(),
            ));
            let rc = Arc::new(
                rustls::ServerConfig::builder_with_provider(r_provider())
                    .with_protocol_versions(r_versions(v))
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .unwrap(),
            );
            let cc = Arc::new(versioned_client(&chain, v));
            for feed in [Feed::Whole, Feed::ByteByByte] {
                let mut c = ub_client(&cc, feed);
                let mut s = Rustls {
                    conn: rustls::ServerConnection::new(rc.clone()).unwrap(),
                    received: Vec::new(),
                    failed: false,
                };
                handshake(&mut c, &mut s);
                exchange(&mut c, &mut s, &big_payload());
                if v == ProtocolVersion::TLSv1_3 {
                    c.refresh_requested = true;
                    c.run();
                    exchange(&mut c, &mut s, b"after key update");
                }
                c.close_requested = true;
                pump(&mut c, &mut s);
                s.conn.send_close_notify();
                pump(&mut c, &mut s);
                assert!(c.closed, "{:?}", c.states);
            }
        }
    }

    #[test]
    fn rustls_client_to_unbuffered_server() {
        init_logging();
        let chain = server_chain(KeyType::EcdsaP256);
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rpki::CertificateDer::from(chain.ca.as_ref().to_vec()))
            .unwrap();
        let roots = Arc::new(roots);
        for v in VERSIONS {
            let rc = Arc::new(
                rustls::ClientConfig::builder_with_provider(r_provider())
                    .with_protocol_versions(r_versions(v))
                    .unwrap()
                    .with_root_certificates(roots.clone())
                    .with_no_client_auth(),
            );
            let sc = Arc::new(versioned_server(&chain, v));
            for feed in [Feed::Whole, Feed::ByteByByte] {
                let mut c = Rustls {
                    conn: rustls::ClientConnection::new(
                        rc.clone(),
                        rpki::ServerName::try_from("localhost").unwrap(),
                    )
                    .unwrap(),
                    received: Vec::new(),
                    failed: false,
                };
                let mut s = ub_server(&sc, feed);
                handshake(&mut c, &mut s);
                exchange(&mut c, &mut s, &big_payload());
                if v == ProtocolVersion::TLSv1_3 {
                    c.conn.refresh_traffic_keys().unwrap();
                    exchange(&mut c, &mut s, b"after key update");
                }
            }
        }
    }
}
