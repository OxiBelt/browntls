//! The `tls_conn` fuzz target: decodes the input and dispatches its
//! operations on the connected pair.

use std::io::{IoSlice, Write};

use browntls::{CommonState, Connection, ConnectionCommon};

use super::acceptor::acceptor;
use super::setup::Knobs;
use super::transport::{PipeArgs, chunk};
use super::{ALL_OPS, ConnectArgs, MAX_OPS, OPS, Op, World, damage};
use crate::input::Input;

/// The `tls_conn` fuzz target.
pub fn run(data: &[u8]) {
    crate::init();
    let mut input = Input::new(data);
    let knobs = Knobs::read(&mut input);
    let Some(mut world) = World::new(knobs) else {
        return;
    };
    let args = ConnectArgs::read(&mut input);
    world.connect(&args);

    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        match ALL_OPS[input.choose(OPS)] {
            Op::Transfer => {
                let side = usize::from(input.bool());
                let write_chunk = chunk(input.byte());
                let how = input.byte();
                let pos = usize::from(input.u16());
                let read_chunk = match input.u16() {
                    0 => usize::MAX,
                    n => usize::from(n),
                };
                let limit = match input.u16() {
                    0 => usize::MAX,
                    n => usize::from(n),
                };
                world.flush(side, write_chunk);
                world.corrupted |= damage(&mut world.wire[side], how, pos, &mut input);
                world.deliver(1 - side, read_chunk, limit);
            }
            Op::Pump => world.pump(),
            Op::Write => {
                let side = usize::from(input.bool());
                let method = input.byte();
                let data = input.short_field();
                let Some(conn) = world.conns[side].as_mut() else {
                    continue;
                };
                let accepted = if method & 1 == 0 {
                    conn.writer().write(data)
                } else {
                    let mid = usize::from(method >> 1).min(data.len());
                    let (a, b) = data.split_at(mid);
                    conn.writer()
                        .write_vectored(&[IoSlice::new(a), IoSlice::new(b)])
                };
                let _ = conn.writer().flush();
                if let Ok(n) = accepted {
                    assert!(n <= data.len());
                    world.sent[side].extend_from_slice(&data[..n]);
                }
            }
            Op::Read => {
                let side = usize::from(input.bool());
                let method = input.byte();
                let size = usize::from(input.byte());
                world.read_with(side, method, size);
            }
            Op::EarlyWrite => {
                let data = input.short_field();
                let Some(client) = world.client() else {
                    continue;
                };
                let Some(mut early) = client.early_data() else {
                    continue;
                };
                let left = early.bytes_left();
                let _ = format!("{early:?}");
                if let Ok(n) = early.write(data) {
                    assert!(n <= left && n <= data.len());
                    assert_eq!(early.bytes_left(), left - n);
                    world.early_sent.extend_from_slice(&data[..n]);
                }
            }
            Op::EarlyRead => {
                let size = usize::from(input.byte()).max(1);
                world.early_read(size);
            }
            Op::CloseNotify => {
                let side = usize::from(input.bool());
                if let Some(conn) = world.conns[side].as_mut() {
                    conn.send_close_notify();
                    world.closed[side] = true;
                }
            }
            Op::RefreshKeys => {
                let side = usize::from(input.bool());
                if let Some(conn) = world.conns[side].as_mut() {
                    let _ = conn.refresh_traffic_keys();
                }
            }
            Op::Export => {
                let label = input.short_field();
                let flags = input.byte();
                let context = input.short_field();
                let len = usize::from(input.u16()) % 1200;
                let context = (flags & 1 != 0).then_some(context);
                world.export(label, context, len, flags & 2 != 0);
            }
            Op::ChannelBinding => world.channel_binding(),
            Op::BufferLimit => {
                let side = usize::from(input.bool());
                let kind = input.byte();
                let limit = usize::from(input.u16());
                let limit = (kind & 1 != 0).then_some(limit);
                match (kind & 2 != 0, world.conns[side].as_mut()) {
                    (true, Some(conn)) => conn.set_buffer_limit(limit),
                    (false, Some(Connection::Client(c))) => {
                        let common: &mut CommonState = c;
                        common.set_buffer_limit(limit);
                    }
                    (false, Some(Connection::Server(s))) => {
                        let common: &mut ConnectionCommon<_> = s;
                        common.set_buffer_limit(limit);
                    }
                    _ => {}
                }
            }
            Op::PostHandshakeAuth => world.post_handshake_auth(),
            Op::Accessors => world.accessors(),
            Op::CompleteIo => {
                let side = usize::from(input.bool());
                let pipe = PipeArgs::read(&mut input);
                world.complete_io(side, pipe.read, pipe.write, pipe.would_block);
            }
            Op::Stream => {
                let side = usize::from(input.bool());
                let owned = input.bool();
                let action = input.byte();
                let data = input.short_field();
                let pipe = PipeArgs::read(&mut input);
                world.stream(side, owned, action, data, pipe);
            }
            Op::Reconnect => {
                let args = ConnectArgs::read(&mut input);
                world.connect(&args);
            }
            Op::Acceptor => {
                let chunk = chunk(input.byte());
                let config = input.bool().then(|| world.server_config.clone());
                acceptor(input.field(), chunk, config);
            }
            Op::Extract => {
                let via_enum = input.bool();
                world.extract(via_enum);
            }
            Op::Inject => {
                let side = usize::from(input.bool());
                let bytes = input.field();
                world.wire[1 - side].extend_from_slice(bytes);
                world.corrupted = true;
                world.deliver(side, usize::MAX, usize::MAX);
            }
            Op::Check => world.check(),
            Op::ResumptionData => {
                let data = input.short_field();
                if let Some(server) = world.server() {
                    server.set_resumption_data(data);
                    world.resumption_data.push(data.to_vec());
                }
            }
        }
    }
    world.accessors();
    world.check();
}
