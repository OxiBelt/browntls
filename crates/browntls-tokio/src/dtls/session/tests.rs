#![allow(clippy::unwrap_used, clippy::panic)]

use super::*;
use std::pin::Pin;
use std::task::{Context, Waker};

fn pending(future: Pin<&mut impl Future>) {
    assert!(
        future
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
}

async fn fixture(limits: SessionLimits) -> (UdpListener, SessionDriver) {
    #[cfg(feature = "native")]
    let provider = browntls_core::crypto::native::default_provider();
    #[cfg(not(feature = "native"))]
    let provider = browntls_core::crypto::rustcrypto::default_provider();
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&browntls_core::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(
            browntls_core::server::ResolvesServerCertUsingSni::new(),
        ));
    #[cfg(feature = "native")]
    let cookies = Arc::new(
        browntls_core::ticketer::TicketRotator::new(3600, || {
            Ok(Box::new(
                browntls_core::crypto::native::ticketer::AeadTicketProducer::new()?,
            ))
        })
        .unwrap(),
    );
    #[cfg(not(feature = "native"))]
    let cookies = browntls_core::crypto::rustcrypto::Ticketer::new().unwrap();
    config.hello_retry_cookies = Some(cookies);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    UdpListener::new(Arc::new(config), socket, limits).unwrap()
}

fn address(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[test]
fn validates_all_counts_and_checked_payload_budgets() {
    let defaults = SessionLimits::default();
    assert!(defaults.validate().is_ok());
    for limits in [
        SessionLimits {
            max_sessions: 0,
            ..defaults
        },
        SessionLimits {
            accept_queue: 0,
            ..defaults
        },
        SessionLimits {
            receive_queue: 0,
            ..defaults
        },
        SessionLimits {
            command_queue: 0,
            ..defaults
        },
        SessionLimits {
            max_sessions: 1025,
            ..defaults
        },
        SessionLimits {
            accept_queue: 129,
            ..defaults
        },
        SessionLimits {
            receive_queue: usize::MAX,
            ..defaults
        },
        SessionLimits {
            command_queue: usize::MAX,
            ..defaults
        },
        SessionLimits {
            receive_queue: 9,
            ..defaults
        },
        SessionLimits {
            command_queue: 64,
            ..defaults
        },
    ] {
        assert_eq!(
            limits.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    assert!(
        SessionLimits {
            max_sessions: 1,
            accept_queue: 1,
            receive_queue: 1024,
            command_queue: 63,
        }
        .validate()
        .is_ok()
    );
}

#[tokio::test]
async fn full_receive_queue_drops_newest_and_preserves_close_and_empty_data() {
    let limits = SessionLimits {
        max_sessions: 1,
        accept_queue: 1,
        receive_queue: 2,
        ..SessionLimits::default()
    };
    let (mut listener, mut driver) = fixture(limits).await;
    driver.event(ServerEvent::Connected(address(1)));
    let mut session = listener.accept().await.unwrap();
    driver.event(ServerEvent::Received(address(1), vec![]));
    driver.event(ServerEvent::Received(address(1), vec![1]));
    driver.event(ServerEvent::Received(address(1), vec![2]));
    driver.event(ServerEvent::Closed(address(1)));
    assert_eq!(session.recv().await.unwrap(), Some(vec![]));
    assert_eq!(session.recv().await.unwrap(), Some(vec![1]));
    assert_eq!(session.recv().await.unwrap(), None);
    // A closed retained handle still owns its receive-budget slot.
    driver.event(ServerEvent::Connected(address(2)));
    assert!(listener.accepted.try_recv().is_err());
    drop(session);
    driver.event(ServerEvent::Connected(address(2)));
    assert_eq!(listener.accept().await.unwrap().peer_addr(), address(2));
}

#[tokio::test]
async fn saturated_queue_cannot_hide_peer_or_driver_failure() {
    let limits = SessionLimits {
        receive_queue: 1,
        ..SessionLimits::default()
    };
    let (mut listener, mut driver) = fixture(limits).await;
    driver.event(ServerEvent::Connected(address(1)));
    let mut first = listener.accept().await.unwrap();
    driver.event(ServerEvent::Received(address(1), vec![1]));
    driver.event(ServerEvent::Failed(
        address(1),
        browntls_core::Error::General("test peer failure".into()),
    ));
    assert_eq!(first.recv().await.unwrap(), Some(vec![1]));
    assert_eq!(
        first.recv().await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    driver.event(ServerEvent::Connected(address(2)));
    let mut second = listener.accept().await.unwrap();
    driver.event(ServerEvent::Received(address(2), vec![2]));
    drop(driver);
    assert_eq!(second.recv().await.unwrap(), Some(vec![2]));
    assert_eq!(
        second.recv().await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(
        listener.accept().await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn a_queued_close_preserves_earlier_data_and_peer_failure() {
    let (mut listener, mut driver) = fixture(SessionLimits::default()).await;
    let peer = address(1);
    driver.event(ServerEvent::Connected(peer));
    let mut session = listener.accept().await.unwrap();
    {
        let mut closing = pin!(session.close());
        pending(closing.as_mut());

        driver.event_first = false;
        driver
            .server
            .queue_event_for_test(ServerEvent::Received(peer, vec![1]));
        driver.server.queue_event_for_test(ServerEvent::Failed(
            peer,
            browntls_core::Error::General("test peer failure".into()),
        ));
        for _ in 0..2 {
            let Work::Event(event) = driver.next_work().await else {
                panic!("already queued events precede close");
            };
            driver.event(event.unwrap());
        }
        let Work::Command(command) = driver.next_work().await else {
            panic!("close follows queued events");
        };
        driver.command(command).await;
        assert_eq!(
            closing.await.unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }
    assert_eq!(session.recv().await.unwrap(), Some(vec![1]));
    assert_eq!(
        session.recv().await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn queued_stale_close_cannot_retire_a_reused_address() {
    let (mut listener, mut driver) = fixture(SessionLimits::default()).await;
    driver.event(ServerEvent::Connected(address(1)));
    let old = listener.accept().await.unwrap();
    let mut closing = pin!(old.close());
    pending(closing.as_mut());
    let command = driver.commands.recv().await.unwrap();
    driver.event(ServerEvent::Closed(address(1)));
    driver.event(ServerEvent::Connected(address(1)));
    let mut new = listener.accept().await.unwrap();
    driver.command(command).await;
    assert_eq!(
        closing.await.unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
    assert!(driver.peers.contains_key(&address(1)));
    assert!(!Arc::ptr_eq(&old.identity, &new.identity));
    driver.event(ServerEvent::Received(address(1), vec![42]));
    assert_eq!(new.recv().await.unwrap(), Some(vec![42]));
}

#[tokio::test]
async fn send_backpressure_cancellation_and_oversize_are_bounded() {
    let limits = SessionLimits {
        command_queue: 1,
        ..SessionLimits::default()
    };
    let (mut listener, mut driver) = fixture(limits).await;
    driver.event(ServerEvent::Connected(address(1)));
    let session = listener.accept().await.unwrap();
    let mut first = Box::pin(session.send(&[1]));
    let mut second = Box::pin(session.send(&[2]));
    pending(first.as_mut());
    pending(second.as_mut());
    assert_eq!(driver.commands.len(), 1);
    let oversized = vec![0; MAX_DATAGRAM + 1];
    assert_eq!(
        session.send(&oversized).await.unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    drop(first);
    let cancelled = driver.commands.recv().await.unwrap();
    assert!(cancelled.reply.is_closed());
    driver.command(cancelled).await;
    pending(second.as_mut());
    let second_command = driver.commands.recv().await.unwrap();
    match &second_command.request {
        Request::Send(data) => assert_eq!(data, &[2]),
        Request::Close => panic!("expected a send request"),
    }
    drop(second);
    driver.command(second_command).await;
    assert!(driver.peers.contains_key(&address(1)));
}

#[tokio::test]
async fn terminal_state_wakes_senders_waiting_for_command_capacity() {
    let limits = SessionLimits {
        command_queue: 1,
        ..SessionLimits::default()
    };
    let (mut listener, mut driver) = fixture(limits).await;
    driver.event(ServerEvent::Connected(address(1)));
    let session = listener.accept().await.unwrap();
    let mut queued = Box::pin(session.send(&[1]));
    let mut waiting = Box::pin(session.send(&[2]));
    pending(queued.as_mut());
    pending(waiting.as_mut());
    assert_eq!(driver.commands.len(), 1);
    driver.event(ServerEvent::Closed(address(1)));
    assert_eq!(
        waiting.await.unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
    // No command was dequeued to release capacity for the waiter.
    assert_eq!(driver.commands.len(), 1);
    drop(queued);
}

#[tokio::test]
async fn accept_overflow_and_dropped_handles_are_pruned() {
    let limits = SessionLimits {
        accept_queue: 1,
        ..SessionLimits::default()
    };
    let (mut listener, mut driver) = fixture(limits).await;
    driver.event(ServerEvent::Connected(address(1)));
    driver.event(ServerEvent::Connected(address(2)));
    assert_eq!(driver.peers.len(), 1);
    let session = listener.accept().await.unwrap();
    assert_eq!(session.peer_addr(), address(1));
    drop(session);
    driver.prune();
    assert!(driver.peers.is_empty());
    driver.event(ServerEvent::Connected(address(2)));
    // Dropping a listener drops its unaccepted handles too.
    drop(listener);
    driver.run().await.unwrap();
}

#[tokio::test]
async fn shutdown_waits_for_closed_handles_and_driver_cancellation_wakes_them() {
    let (mut listener, mut driver) = fixture(SessionLimits::default()).await;
    driver.event(ServerEvent::Connected(address(1)));
    let session = listener.accept().await.unwrap();
    driver.event(ServerEvent::Closed(address(1)));
    drop(listener);
    let mut running = Box::pin(driver.run());
    pending(running.as_mut());
    drop(session);
    running.await.unwrap();

    let (mut listener, mut driver) = fixture(SessionLimits::default()).await;
    driver.event(ServerEvent::Connected(address(2)));
    let mut session = listener.accept().await.unwrap();
    let mut running = Box::pin(driver.run());
    pending(running.as_mut());
    drop(running);
    assert_eq!(
        session.recv().await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn cancelled_accept_and_receive_leave_data_for_the_next_call() {
    let (mut listener, mut driver) = fixture(SessionLimits::default()).await;
    {
        let mut accepting = pin!(listener.accept());
        pending(accepting.as_mut());
    }
    driver.event(ServerEvent::Connected(address(1)));
    let mut session = listener.accept().await.unwrap();
    {
        let mut receiving = pin!(session.recv());
        pending(receiving.as_mut());
    }
    driver.event(ServerEvent::Received(address(1), vec![3]));
    assert_eq!(session.recv().await.unwrap(), Some(vec![3]));
}

#[tokio::test]
async fn blocked_output_is_interruptible_for_lifecycle_cleanup() {
    let wake = Notify::new();
    let mut started = false;
    let operation = poll_fn(|_| {
        started = true;
        Poll::<io::Result<()>>::Pending
    });
    wake.notify_one();
    assert_eq!(
        interruptible(operation, &wake).await.unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert!(started);
}
