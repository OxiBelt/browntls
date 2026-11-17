// Cases included by `cases/unbuffered.rs`, which holds the imports and the
// shared plumbing: handing an unbuffered connection to the kernel.

#[test]
fn unbuffered_connections_hand_over_to_the_kernel() {
    use browntls::kernel::{KernelHandoffBlocker, KernelOutput};
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2] {
        let mut cc = versioned_client(&chain, v);
        cc.enable_secret_extraction = true;
        let mut sc = versioned_server(&chain, v);
        sc.enable_secret_extraction = true;
        let (cc, sc) = (Arc::new(cc), Arc::new(sc));

        let mut c = ub_client(&cc, Feed::Whole);
        let mut s = b_server(&sc);
        assert_eq!(
            c.conn.kernel_handoff_blocker(),
            Some(KernelHandoffBlocker::HandshakeIncomplete)
        );
        handshake(&mut c, &mut s);
        exchange(&mut c, &mut s, b"before the handover");
        assert!(c.incoming.is_empty() && c.outgoing.is_empty());
        assert_eq!(c.conn.kernel_handoff_blocker(), None, "{v:?}");

        let (client_secrets, mut kernel) = c.conn.dangerous_into_kernel_connection().unwrap();
        let server_secrets = s.conn.dangerous_extract_secrets().unwrap();
        assert_eq!(client_secrets.tx.0, server_secrets.rx.0, "{v:?}");
        assert_eq!(client_secrets.rx.0, server_secrets.tx.0, "{v:?}");
        assert_eq!(kernel.protocol_version(), v);
        if v == ProtocolVersion::TLSv1_3 {
            kernel
                .handle_record(browntls::ContentType::Handshake, &[24, 0, 0, 1, 0])
                .unwrap();
            assert!(matches!(kernel.pop_output(), Some(KernelOutput::RxKeys(_))));
        }
    }

    // A server too.
    let mut cc = versioned_client(&chain, ProtocolVersion::TLSv1_3);
    cc.enable_secret_extraction = true;
    let mut sc = versioned_server(&chain, ProtocolVersion::TLSv1_3);
    sc.enable_secret_extraction = true;
    let mut c = b_client(&Arc::new(cc));
    let mut s = ub_server(&Arc::new(sc), Feed::Whole);
    handshake(&mut c, &mut s);
    exchange(&mut c, &mut s, b"data");
    let (_, kernel) = s.conn.dangerous_into_kernel_connection().unwrap();
    assert_eq!(kernel.post_handshake_auth_status(), None);
}
