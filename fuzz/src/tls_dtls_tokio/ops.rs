//! Action dispatch and a model of whole, ordered application datagrams.

use browntls_tokio::dtls::Recv;
use tokio::time::Instant;

use super::*;

impl Session {
    // Each action consumes its own arguments; terminal actions end the
    // program so later mutations cannot invent traffic on a removed peer.
    pub(super) async fn action(&mut self, input: &mut Input<'_>) -> bool {
        match input.choose(16) {
            0 => self.send_to_server(input.short_field()).await,
            1 => self.send_to_client(input.short_field(), false).await,
            2 => self.send_to_client(input.short_field(), true).await,
            3 => {
                self.idle(Duration::from_millis(u64::from(input.byte() % 3)))
                    .await;
            }
            4 => {
                cancel_pending(self.client.recv(&mut [0; 256])).await;
                cancel_pending(self.server.next_event()).await;
                reached("receive cancellation");
                reached("event cancellation");
                self.send_to_server(b"after cancelled event").await;
                self.send_to_client(b"after cancelled receive", false).await;
            }
            5 => {
                self.server
                    .connection_mut(self.peer)
                    .expect("established peer")
                    .refresh_traffic_keys()
                    .expect("server key update");
                self.send_to_client(b"new keys", false).await;
                self.send_to_server(b"key update acknowledged").await;
                reached("key update");
            }
            6 => self.inspect(true),
            7 => {
                let max = usize::from(input.byte() % 4);
                self.server.set_max_handshakes(max);
                self.server.set_max_peers(max);
                self.server
                    .set_handshake_timeout(Duration::from_millis(u64::from(input.byte())));
                assert_eq!(self.server.handshakes(), 0);
                // Existing associations survive a reduction, including zero
                // (the API clamps both admission limits to at least one).
                self.send_to_server(b"after changing admission limits")
                    .await;
                reached("limits");
            }
            8 => self.oversized().await,
            9 => self.unknown().await,
            10 => {
                bounded(self.client.complete_handshake()).await.unwrap();
                reached("repeat handshake");
            }
            11 => {
                self.client_close(false).await;
                return false;
            }
            12 => {
                bounded(self.server.close(self.peer)).await.unwrap();
                assert_eq!(
                    bounded(self.client.recv(&mut [])).await.unwrap(),
                    Recv::Closed
                );
                assert_eq!(
                    bounded(self.client.recv(&mut [])).await.unwrap(),
                    Recv::Closed
                );
                self.inspect(false);
                reached("server close");
                return false;
            }
            13 => {
                let conn = self.server.remove(self.peer).expect("removed association");
                assert!(!conn.is_handshaking());
                assert!(self.server.remove(self.peer).is_none());
                self.inspect(false);
                self.unknown().await;
                reached("remove");
                return false;
            }
            14 => {
                self.client_close(true).await;
                return false;
            }
            _ => {
                // Queue two distinct records before receiving: comparing
                // each record separately detects merging and truncation.
                let data = input.short_field();
                let client_data = &data[..data.len().min(self.client_max())];
                bounded(self.client.send(client_data)).await.unwrap();
                bounded(self.client.send(b"second client datagram"))
                    .await
                    .unwrap();
                self.received(client_data).await;
                self.received(b"second client datagram").await;
                bounded(self.server.send_to(data, self.peer)).await.unwrap();
                bounded(self.server.send_to(b"second server datagram", self.peer))
                    .await
                    .unwrap();
                self.receive(data, false).await;
                self.receive(b"second server datagram", false).await;
                reached("datagram boundaries");
            }
        }
        true
    }

    fn client_max(&self) -> usize {
        self.client
            .connection()
            .max_application_data()
            .expect("data limit")
    }

    async fn send_to_server(&mut self, data: &[u8]) {
        let data = &data[..data.len().min(self.client_max())];
        bounded(self.client.send(data)).await.expect("client send");
        self.received(data).await;
    }

    async fn received(&mut self, expected: &[u8]) {
        match bounded(self.server.next_event()).await.expect("data event") {
            ServerEvent::Received(peer, data) => {
                assert_eq!(peer, self.peer);
                assert_eq!(data, expected);
            }
            event => panic!("expected one application datagram, got {event:?}"),
        }
        reached("client send");
        if expected.is_empty() {
            reached("empty to server");
        }
    }

    async fn send_to_client(&mut self, data: &[u8], short: bool) {
        bounded(self.server.send_to(data, self.peer))
            .await
            .expect("server send");
        self.receive(data, short).await;
    }

    async fn receive(&mut self, expected: &[u8], short: bool) {
        let mut buf = [0; 256];
        if short && !expected.is_empty() {
            assert_eq!(
                bounded(self.client.recv(&mut buf[..expected.len() - 1]))
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidInput
            );
            reached("short buffer retained");
        }
        assert_eq!(
            bounded(self.client.recv(&mut buf))
                .await
                .expect("client recv"),
            Recv::Data(expected.len())
        );
        assert_eq!(&buf[..expected.len()], expected);
        reached("server send");
        if expected.is_empty() {
            reached("empty to client");
        }
    }

    pub(super) async fn idle(&mut self, duration: Duration) {
        self.client.set_timeout(Some(duration));
        assert_eq!(self.client.timeout(), Some(duration));
        self.server.set_read_timeout(Some(duration));
        let start = Instant::now();
        let (client, server) =
            together(self.client.recv(&mut [0; 256]), self.server.next_event()).await;
        assert_eq!(client.unwrap_err().kind(), ErrorKind::TimedOut);
        assert_eq!(server.unwrap_err().kind(), ErrorKind::TimedOut);
        assert!(start.elapsed() >= duration);
        self.client.set_timeout(None);
        assert_eq!(self.client.timeout(), None);
        self.server.set_read_timeout(None);
        // None is bounded by the harness; cancelling these real waits must
        // leave both endpoints usable for the next action.
        cancel_pending(self.client.recv(&mut [0; 256])).await;
        cancel_pending(self.server.next_event()).await;
        self.client.set_timeout(Some(LIMIT));
        self.server.set_read_timeout(Some(LIMIT));
        reached(if duration.is_zero() {
            "zero deadline"
        } else {
            "elapsed deadline"
        });
    }

    async fn oversized(&mut self) {
        let data = vec![0x5a; self.client_max() + 1];
        assert_eq!(
            bounded(self.client.send(&data)).await.unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        let max = self
            .server
            .connection(self.peer)
            .unwrap()
            .max_application_data()
            .unwrap();
        assert_eq!(
            bounded(self.server.send_to(&vec![0xa5; max + 1], self.peer))
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
        // Rejections must neither enqueue data nor break the association.
        self.send_to_server(b"after rejected send").await;
        self.send_to_client(b"after rejected send", false).await;
        reached("oversized rejected");
    }

    async fn unknown(&mut self) {
        // Port zero cannot be one of our bound ephemeral sockets. These
        // calls must reject locally, before any network send.
        let unknown = SocketAddr::from(([127, 0, 0, 1], 0));
        assert!(self.server.connection(unknown).is_none());
        assert!(self.server.connection_mut(unknown).is_none());
        assert!(self.server.remove(unknown).is_none());
        assert_eq!(
            bounded(self.server.send_to(b"unknown", unknown))
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::NotConnected
        );
        bounded(self.server.close(unknown)).await.unwrap();
        reached("unknown peer");
    }

    async fn client_close(&mut self, cancel: bool) {
        if cancel {
            // A single real poll may complete on a writable socket. If it
            // yields, repeated close resumes; never assume backpressure.
            let mut closing = pin!(self.client.close());
            poll_fn(|cx| {
                if let Poll::Ready(result) = closing.as_mut().poll(cx) {
                    result.unwrap();
                }
                Poll::Ready(())
            })
            .await;
            reached("close polled once");
        }
        bounded(self.client.close()).await.unwrap();
        bounded(self.client.close()).await.unwrap();
        assert!(matches!(
            bounded(self.server.next_event()).await.unwrap(),
            ServerEvent::Closed(peer) if peer == self.peer
        ));
        assert_eq!(
            bounded(self.client.send(b"closed"))
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::BrokenPipe
        );
        self.inspect(false);
        reached("client close");
    }

    pub(super) fn inspect(&mut self, live: bool) {
        assert_eq!(self.client.socket().local_addr().unwrap(), self.peer);
        assert_eq!(self.client.socket().peer_addr().unwrap(), self.server_addr);
        assert_eq!(self.server.socket().local_addr().unwrap(), self.server_addr);
        assert!(!self.client.connection().is_handshaking());
        assert_eq!(
            self.client.connection().protocol_version(),
            Some(ProtocolVersion::DTLSv1_3)
        );
        assert_eq!(self.server.connection(self.peer).is_some(), live);
        assert_eq!(self.server.connection_mut(self.peer).is_some(), live);
        assert_eq!(
            self.server.peers().collect::<Vec<_>>(),
            if live { vec![self.peer] } else { vec![] }
        );
        assert_eq!(self.server.handshakes(), 0);
        if live {
            let conn = self.server.connection(self.peer).unwrap();
            assert!(!conn.is_handshaking());
            assert_eq!(conn.protocol_version(), Some(ProtocolVersion::DTLSv1_3));
            let mut client = [0; 32];
            let mut server = [0; 32];
            self.client
                .connection()
                .export_keying_material(&mut client, b"Tokio DTLS fuzz", None)
                .unwrap();
            conn.export_keying_material(&mut server, b"Tokio DTLS fuzz", None)
                .unwrap();
            assert_eq!(client, server);
        }
        reached("accessors");
    }
}
