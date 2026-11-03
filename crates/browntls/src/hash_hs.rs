//! The handshake transcript hash (RFC 8446 §4.4.1).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use crate::crypto::hash;
use crate::msgs::codec::Codec;
use crate::msgs::handshake::HandshakeMessagePayload;
use crate::msgs::message::{Message, MessagePayload};

/// The transcript before the hash algorithm is known: raw bytes are kept.
#[derive(Default)]
pub(crate) struct HandshakeHashBuffer {
    buffer: Vec<u8>,
    client_auth_enabled: bool,
}

impl HandshakeHashBuffer {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Keep the raw transcript for a TLS 1.2 client CertificateVerify.
    pub(crate) fn set_client_auth_enabled(&mut self) {
        self.client_auth_enabled = true;
    }

    pub(crate) fn add_message(&mut self, m: &Message<'_>) {
        if let MessagePayload::Handshake { encoded, .. } = &m.payload {
            self.buffer.extend_from_slice(encoded.bytes());
        }
    }

    pub(crate) fn add_raw(&mut self, buf: &[u8]) {
        self.buffer.extend_from_slice(buf);
    }

    /// Hashes the buffer followed by `extra` with `provider`.
    pub(crate) fn hash_given(
        &self,
        provider: &'static dyn hash::Hash,
        extra: &[u8],
    ) -> hash::Output {
        let mut ctx = provider.start();
        ctx.update(&self.buffer);
        ctx.update(extra);
        ctx.finish()
    }

    /// Commits to `provider` and continues incrementally.
    pub(crate) fn start_hash(self, provider: &'static dyn hash::Hash) -> HandshakeHash {
        let mut ctx = provider.start();
        ctx.update(&self.buffer);
        HandshakeHash {
            provider,
            ctx,
            client_auth: self.client_auth_enabled.then_some(self.buffer),
        }
    }
}

impl fmt::Debug for HandshakeHashBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeHashBuffer")
            .field("len", &self.buffer.len())
            .finish()
    }
}

/// The incremental transcript hash.
pub(crate) struct HandshakeHash {
    provider: &'static dyn hash::Hash,
    ctx: Box<dyn hash::Context>,
    client_auth: Option<Vec<u8>>,
}

impl HandshakeHash {
    pub(crate) fn add_message(&mut self, m: &Message<'_>) -> &mut Self {
        if let MessagePayload::Handshake { encoded, .. } = &m.payload {
            self.add(encoded.bytes());
        }
        self
    }

    pub(crate) fn add(&mut self, bytes: &[u8]) -> &mut Self {
        self.ctx.update(bytes);
        if let Some(buf) = &mut self.client_auth {
            buf.extend_from_slice(bytes);
        }
        self
    }

    /// Replaces the transcript so far with a `message_hash` message holding
    /// its hash (RFC 8446 §4.4.1), as required after a HelloRetryRequest.
    pub(crate) fn rollup_for_hrr(&mut self) {
        let old_hash = self.ctx.fork_finish();
        let old_handshake_hash_msg =
            HandshakeMessagePayload::build_handshake_hash(old_hash.as_ref());
        self.ctx = self.provider.start();
        self.ctx.update(&old_handshake_hash_msg.get_encoding());
        if let Some(buf) = &mut self.client_auth {
            buf.clear();
            buf.extend_from_slice(&old_handshake_hash_msg.get_encoding());
        }
    }

    /// The hash of the transcript so far.
    pub(crate) fn current_hash(&self) -> hash::Output {
        self.ctx.fork_finish()
    }

    /// The hash of the transcript so far followed by `extra`, without
    /// changing the transcript (used for PSK binders).
    pub(crate) fn hash_with(&self, extra: &[u8]) -> hash::Output {
        let mut ctx = self.ctx.fork();
        ctx.update(extra);
        ctx.finish()
    }

    /// Takes the raw transcript kept for client authentication, if any.
    pub(crate) fn take_handshake_buf(&mut self) -> Option<Vec<u8>> {
        self.client_auth.take()
    }

    pub(crate) fn algorithm(&self) -> hash::HashAlgorithm {
        self.provider.algorithm()
    }

    /// Returns to buffering mode (after a HelloRetryRequest that changes the
    /// hash) with the transcript replaced by its `message_hash`.
    pub(crate) fn into_hrr_buffer(self) -> HandshakeHashBuffer {
        let old_hash = self.ctx.fork_finish();
        let msg = HandshakeMessagePayload::build_handshake_hash(old_hash.as_ref());
        HandshakeHashBuffer {
            buffer: msg.get_encoding(),
            client_auth_enabled: self.client_auth.is_some(),
        }
    }
}

impl fmt::Debug for HandshakeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeHash")
            .field("algorithm", &self.provider.algorithm())
            .finish_non_exhaustive()
    }
}
