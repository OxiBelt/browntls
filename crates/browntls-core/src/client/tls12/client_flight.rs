//! TLS 1.2 client authentication of the server and emission of the client
//! flight.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{
    AlertDescription, ClientAuthDetails, ClientConnectionData, ClientContext, ConnectionSecrets,
    ContentType, Error, ExpectCcs, ExpectNewTicket, ExpectServerDone, HandshakeMessagePayload,
    HandshakePayload, HandshakeSignatureValid, HandshakeType, KxState, Message, MessagePayload,
    NextStateOrError, PeerMisbehaved, ProtocolVersion, ServerCertVerified, Side, State,
    emit_certificate, emit_certverify, emit_client_kx, emit_finished, mac_order, tls13,
};
use crate::msgs::codec::Codec;
use crate::revocation::finish_or_pause;

impl State<ClientConnectionData> for ExpectServerDone {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        let mut st = *self;
        match &m.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::ServerHelloDone),
                ..
            } => {}
            payload => {
                return Err(crate::check::inappropriate_handshake_message(
                    payload,
                    &[ContentType::Handshake],
                    &[HandshakeType::ServerHelloDone],
                ));
            }
        }
        st.transcript.add_message(&m);

        // 1. Verify the server's certificate chain.
        let (end_entity, intermediates) =
            st.server_cert.cert_chain.0.split_first().ok_or_else(|| {
                cx.common.send_fatal_alert(
                    AlertDescription::DecodeError,
                    Error::NoCertificatesPresented,
                )
            })?;
        let now = st.config.current_time()?;
        let (check, transparency_status) = st
            .config
            .verifier()
            .verify_server_cert_with_transparency(
                end_entity,
                intermediates,
                &st.server_name,
                &st.server_cert.evidence(),
                now,
            )
            .map_err(|err| tls13::send_cert_path_error_alert(cx.common, err))?;

        // 2. Verify the signature over the key exchange parameters
        //    (RFC 5246 §7.4.3: client_random || server_random || params).
        let sig = &st.server_kx.sig;
        if !st.hello.offered_sigschemes.contains(&sig.scheme)
            || !st.suite.sign.contains(&sig.scheme)
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SignedKxWithWrongAlgorithm,
            ));
        }
        let mut message = Vec::with_capacity(64 + 128);
        message.extend_from_slice(&st.randoms.client);
        message.extend_from_slice(&st.randoms.server);
        st.server_kx.params.encode(&mut message);
        let sig_verified = st
            .config
            .verifier()
            .verify_tls12_signature(&message, end_entity, sig)
            .map_err(|err| tls13::send_cert_verify_error_alert(cx.common, err))?;

        finish_or_pause(cx, check, move |cx, status| {
            cx.common.peer_revocation_status = status;
            cx.data.transparency.info = st.server_cert.transparency_info.take();
            cx.data.transparency.status = transparency_status;
            st.finish_client_flight(cx, sig_verified)
        })
    }
}

impl ExpectServerDone {
    fn finish_client_flight(
        self,
        cx: &mut ClientContext<'_>,
        sig_verified: HandshakeSignatureValid,
    ) -> NextStateOrError {
        let mut st = self;
        let cert_verified = ServerCertVerified::assertion();
        cx.common.peer_certificates = Some(st.server_cert.cert_chain);

        // 3. Client certificate, if requested.
        if let Some(client_auth) = &st.client_auth {
            match client_auth {
                ClientAuthDetails::Empty { .. } => {
                    emit_certificate(&mut st.transcript, None, cx.common)
                }
                ClientAuthDetails::Verify { certkey, .. } => {
                    emit_certificate(&mut st.transcript, Some(certkey), cx.common)
                }
            }
        }

        // 4. Our key exchange, and the master secret.
        let group = st
            .config
            .find_kx_group(
                st.server_kx.params.curve_params.named_group,
                ProtocolVersion::TLSv1_2,
            )
            .ok_or_else(|| {
                cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::SelectedUnofferedKxGroup,
                )
            })?;
        cx.common.kx_state = KxState::Started(group);
        let kx = group.start()?;
        emit_client_kx(&mut st.transcript, kx.pub_key(), cx.common);

        // RFC 7627 §4: the extended master secret uses the session hash,
        // which covers the transcript through ClientKeyExchange.
        let ems_seed = st.using_ems.then(|| st.transcript.current_hash());
        let secrets = ConnectionSecrets::from_key_exchange(
            kx,
            &st.server_kx.params.public.0,
            ems_seed,
            st.randoms,
            st.suite,
        )
        .map_err(|err| match err {
            Error::PeerMisbehaved(_) => cx
                .common
                .send_fatal_alert(AlertDescription::IllegalParameter, err),
            other => other,
        })?;
        cx.common.kx_state.complete();

        st.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            secrets.master_secret(),
        );
        cx.common
            .start_encryption_tls12(&secrets, Side::Client, mac_order(st.using_etm));

        // 5. CertificateVerify over every handshake message so far.
        if let Some(ClientAuthDetails::Verify { signer, .. }) = &st.client_auth {
            emit_certverify(&mut st.transcript, &**signer, cx.common)?;
        }

        // 6. ChangeCipherSpec and Finished.
        cx.common.send_change_cipher_spec();
        emit_finished(&secrets, &mut st.transcript, cx.common);

        let next = ExpectCcs {
            config: st.config,
            secrets,
            resuming_session: None,
            session_id: st.session_id,
            server_name: st.server_name,
            using_ems: st.using_ems,
            transcript: st.transcript,
            ticket: None,
            resuming: false,
            cert_verified,
            sig_verified,
            cached_info: st.hello.cached_info.take(),
        };
        Ok(if st.must_issue_new_ticket {
            Box::new(ExpectNewTicket { next })
        } else {
            Box::new(next)
        })
    }
}
