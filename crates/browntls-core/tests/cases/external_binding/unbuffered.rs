// The unbuffered API (`UnbufferedClientConnection`,
// `UnbufferedServerConnection`): the same checks and accessors, through
// `CommonState`.

/// One end of an unbuffered connection and its buffers.
struct UbEnd<C> {
    conn: C,
    incoming: Vec<u8>,
    outgoing: Vec<u8>,
    error: Option<Error>,
}

impl<C, D> UbEnd<C>
where
    C: std::ops::DerefMut<Target = browntls_core::unbuffered::UnbufferedConnectionCommon<D>>,
    D: browntls_core::SideData,
{
    fn new(conn: C) -> Self {
        Self {
            conn,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            error: None,
        }
    }

    /// Runs `process_tls_records` until the connection needs input.
    fn run(&mut self) {
        use browntls_core::unbuffered::{ConnectionState, EncodeError, InsufficientSizeError};
        if self.error.is_some() {
            return;
        }
        for _ in 0..1000 {
            let status = self.conn.process_tls_records(&mut self.incoming);
            let discard = status.discard;
            let stop = match status.state {
                Ok(ConnectionState::EncodeTlsData(mut e)) => {
                    let mut buf = vec![0u8; 1];
                    let n = match e.encode(&mut buf) {
                        Ok(n) => n,
                        Err(EncodeError::InsufficientSize(InsufficientSizeError {
                            required_size,
                        })) => {
                            buf.resize(required_size, 0);
                            e.encode(&mut buf).unwrap()
                        }
                        Err(e) => panic!("{e:?}"),
                    };
                    self.outgoing.extend_from_slice(&buf[..n]);
                    false
                }
                Ok(ConnectionState::TransmitTlsData(t)) => {
                    t.done();
                    false
                }
                Ok(ConnectionState::ReadTraffic(_)) => false,
                Ok(_) => true,
                Err(e) => {
                    self.error = Some(e);
                    true
                }
            };
            self.incoming.drain(..discard);
            if stop {
                return;
            }
        }
        panic!("unbuffered connection did not settle");
    }

    fn take_output(&mut self) -> Vec<u8> {
        self.run();
        std::mem::take(&mut self.outgoing)
    }

    fn give_input(&mut self, bytes: &[u8]) {
        self.incoming.extend_from_slice(bytes);
        self.run();
    }
}

fn ub_client(
    config: &Arc<ClientConfig>,
) -> UbEnd<browntls_core::client::UnbufferedClientConnection> {
    UbEnd::new(
        browntls_core::client::UnbufferedClientConnection::new(config.clone(), server_name())
            .unwrap(),
    )
}

fn ub_server(
    config: &Arc<ServerConfig>,
) -> UbEnd<browntls_core::server::UnbufferedServerConnection> {
    UbEnd::new(browntls_core::server::UnbufferedServerConnection::new(config.clone()).unwrap())
}

/// Moves bytes both ways until neither side has anything to send; the alert
/// of a failed side is delivered too.
fn pump<A, B, DA, DB>(client: &mut UbEnd<A>, server: &mut UbEnd<B>)
where
    A: std::ops::DerefMut<Target = browntls_core::unbuffered::UnbufferedConnectionCommon<DA>>,
    B: std::ops::DerefMut<Target = browntls_core::unbuffered::UnbufferedConnectionCommon<DB>>,
    DA: browntls_core::SideData,
    DB: browntls_core::SideData,
{
    for _ in 0..32 {
        let to_server = client.take_output();
        server.give_input(&to_server);
        let to_client = server.take_output();
        client.give_input(&to_client);
        if to_server.is_empty() && to_client.is_empty() {
            return;
        }
    }
    panic!("pump did not settle");
}

#[test]
fn unbuffered_connections_check_and_report_the_binding() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let (c, s) = pair();
        let client_config = Arc::new(client_for(&chain, v, Some(c.clone())));
        let mut client = ub_client(&client_config);
        let mut server = ub_server(&Arc::new(server_for(&chain, v, Some(s.clone()))));
        pump(&mut client, &mut server);
        assert!(client.error.is_none(), "{:?}", client.error);
        assert!(server.error.is_none(), "{:?}", server.error);
        assert!(!client.conn.is_handshaking() && !server.conn.is_handshaking());
        assert_eq!(client.conn.peer_external_id_hash(), Some(&hash(2)));
        assert_eq!(
            client.conn.peer_external_session_id(),
            Some(&tls_id("server"))
        );
        assert_eq!(server.conn.peer_external_id_hash(), Some(&hash(1)));
        assert_eq!(
            server.conn.peer_external_session_id(),
            Some(&tls_id("client"))
        );

        // The server detects a mismatch...
        let mut other = s.clone();
        other.peer_session_id = Some(tls_id("someone else"));
        let mut client = ub_client(&client_config);
        let mut server = ub_server(&Arc::new(server_for(&chain, v, Some(other))));
        pump(&mut client, &mut server);
        assert_eq!(
            server.error,
            Some(Error::PeerMisbehaved(
                PeerMisbehaved::ExternalSessionIdMismatch
            ))
        );
        assert_eq!(client.error, Some(alert_for(v, false)));

        // ...the client too, and a missing answer it requires.
        let mut other = s.clone();
        other.id_hash = Some(hash(9));
        let mut client = ub_client(&client_config);
        let mut server = ub_server(&Arc::new(server_for(&chain, v, Some(other))));
        pump(&mut client, &mut server);
        assert_eq!(
            client.error,
            Some(Error::PeerMisbehaved(
                PeerMisbehaved::ExternalIdHashMismatch
            ))
        );
        assert_eq!(server.error, Some(alert_for(v, false)));

        let mut required = c.clone();
        required.require_peer_support = true;
        let mut client = ub_client(&Arc::new(client_for(&chain, v, Some(required))));
        let mut server = ub_server(&Arc::new(server_for(&chain, v, None)));
        pump(&mut client, &mut server);
        assert_eq!(
            client.error,
            Some(Error::PeerIncompatible(
                PeerIncompatible::ExternalIdHashExtensionRequired
            ))
        );
        assert_eq!(server.error, Some(alert_for(v, true)));
    }
}
