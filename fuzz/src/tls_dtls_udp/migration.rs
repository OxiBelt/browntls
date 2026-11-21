//! Blocking loopback migration with one bounded server thread.

use std::time::{Duration, Instant};

use browntls_core::dtls::{self, ServerEvent, UdpClient, UdpServer, rrc::Selection};

use super::{BUDGET, configs, loopback};

pub(super) fn exercise(header: u8) {
    let configs = configs(header, true, false);
    let settings = |len| {
        dtls::Settings::default()
            .with_return_routability_checks(dtls::ConnectionIdPolicy::new(len, true).unwrap())
    };
    let mut server =
        UdpServer::new_with_settings(configs.server.unwrap(), loopback(), settings(8)).unwrap();
    server.set_path_selection(if header & 1 == 0 {
        Selection::Basic
    } else {
        Selection::Enhanced
    });
    server.set_read_timeout(Some(Duration::from_millis(10)));
    server.set_handshake_timeout(BUDGET);
    let remote = server.socket().local_addr().unwrap();
    let socket = loopback();
    socket.connect(remote).unwrap();
    socket.set_read_timeout(Some(BUDGET)).unwrap();
    let original = socket.local_addr().unwrap();
    let replacement = loopback();
    replacement.connect(remote).unwrap();
    let migrated = replacement.local_addr().unwrap();
    let thread = std::thread::spawn(move || {
        let deadline = Instant::now() + BUDGET;
        let mut announced = false;
        loop {
            assert!(Instant::now() < deadline, "migration server deadline");
            match server.next_event() {
                Ok(ServerEvent::Connected(peer)) => assert_eq!(peer, original),
                Ok(ServerEvent::Received(peer, data)) => {
                    assert_eq!(peer, original);
                    server.send_to(&data, peer).unwrap();
                }
                Ok(ServerEvent::Closed(peer)) => {
                    assert_eq!(peer, original);
                    break;
                }
                Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {}
                other => panic!("unexpected server event: {other:?}"),
            }
            if !announced && server.peer_addr(original) == Some(migrated) {
                server.send_to(b"validated", original).unwrap();
                announced = true;
            }
        }
        assert!(announced);
    });
    let connection = dtls::ClientConnection::new_with_settings(
        configs.client.unwrap(),
        super::setup::localhost(),
        settings(if header & 2 == 0 { 0 } else { 8 }),
    )
    .unwrap();
    let mut client = UdpClient::from_connection(connection, socket);
    client.set_read_timeout(Some(BUDGET));
    client.complete_handshake().unwrap();
    client.send(b"before").unwrap();
    let mut buffer = [0; 32];
    let len = client.recv(&mut buffer).unwrap();
    assert_eq!(&buffer[..len], b"before");
    drop(client.replace_socket(replacement).unwrap());
    client.send(b"candidate").unwrap();
    let len = client.recv(&mut buffer).unwrap();
    assert_eq!(&buffer[..len], b"validated");
    client.send(b"after").unwrap();
    let len = client.recv(&mut buffer).unwrap();
    assert_eq!(&buffer[..len], b"after");
    client.close().unwrap();
    thread.join().unwrap();
    super::reached("migration");
}
