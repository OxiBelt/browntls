// The unbuffered (caller-buffer) API: the same evidence and status as the
// buffered one. Included by `cases/transparency.rs`.

/// Runs `conn` until it needs input, appending what it sends to `out`.
/// Returns whether the handshake is done.
fn run_unbuffered<D: browntls_core::SideData>(
    conn: &mut browntls_core::unbuffered::UnbufferedConnectionCommon<D>,
    incoming: &mut Vec<u8>,
    out: &mut Vec<u8>,
) -> Result<bool, Error> {
    use browntls_core::unbuffered::ConnectionState;

    loop {
        let status = conn.process_tls_records(incoming);
        let discard = status.discard;
        let done = match status.state? {
            ConnectionState::EncodeTlsData(mut e) => {
                let mut buf = vec![0u8; 1 << 16];
                let n = e.encode(&mut buf).unwrap();
                out.extend_from_slice(&buf[..n]);
                None
            }
            ConnectionState::TransmitTlsData(t) => {
                t.done();
                None
            }
            ConnectionState::BlockedHandshake => Some(false),
            ConnectionState::WriteTraffic(_) => Some(true),
            ConnectionState::ReadTraffic(_) => None,
            other => panic!("unexpected state {other:?}"),
        };
        incoming.drain(..discard);
        if let Some(done) = done {
            return Ok(done);
        }
    }
}

#[test]
fn unbuffered_connections_carry_the_list_and_status() {
    use browntls_core::client::UnbufferedClientConnection;
    use browntls_core::server::UnbufferedServerConnection;

    let fx = Fixture::new();
    let items = list(&[fx.sct(&fx.log_a)]);
    for v in VERSIONS {
        let client = fx.client(Some(fx.requirements(&[&fx.log_a])), v);
        let server = server(&fx.chain, Some(items.clone()), None, v);
        let mut c = UnbufferedClientConnection::new(client, server_name()).unwrap();
        let mut s = UnbufferedServerConnection::new(server).unwrap();
        let (mut to_server, mut to_client) = (Vec::new(), Vec::new());
        let mut done = (false, false);
        for _ in 0..20 {
            let mut sent = Vec::new();
            done.0 = run_unbuffered(&mut *c, &mut to_client, &mut sent).unwrap();
            to_server.extend(sent);
            let mut sent = Vec::new();
            done.1 = run_unbuffered(&mut *s, &mut to_server, &mut sent).unwrap();
            to_client.extend(sent);
            if done == (true, true) && to_client.is_empty() && to_server.is_empty() {
                break;
            }
        }
        assert_eq!(done, (true, true), "{v:?}");
        assert_eq!(c.peer_transparency_info(), Some(&items[..]), "{v:?}");
        assert_eq!(c.peer_transparency_status(), Some(status(1, 1, 0)));
    }
}

#[test]
fn unbuffered_client_refuses_insufficient_transparency() {
    use browntls_core::client::UnbufferedClientConnection;
    use browntls_core::server::UnbufferedServerConnection;

    let fx = Fixture::new();
    for v in VERSIONS {
        let client = fx.client(Some(fx.requirements(&[&fx.log_a])), v);
        let server = server(&fx.chain, None, None, v);
        let mut c = UnbufferedClientConnection::new(client, server_name()).unwrap();
        let mut s = UnbufferedServerConnection::new(server).unwrap();
        let (mut to_server, mut to_client) = (Vec::new(), Vec::new());
        let mut result = Ok(false);
        for _ in 0..20 {
            let mut sent = Vec::new();
            result = run_unbuffered(&mut *c, &mut to_client, &mut sent);
            to_server.extend(sent);
            if result.is_err() {
                break;
            }
            let mut sent = Vec::new();
            run_unbuffered(&mut *s, &mut to_server, &mut sent).unwrap();
            to_client.extend(sent);
        }
        assert_eq!(
            result,
            Err(Error::InvalidCertificate(insufficient(0, 0))),
            "{v:?}"
        );
        assert_eq!(c.peer_transparency_status(), None);
    }
}
