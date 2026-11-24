//! Shared RFC 9146 encoding, bounds and authenticated inner plaintext rules.
//! No socket, negotiation, replay or connection state belongs here.

use super::{
    InboundOpaqueMessage, InboundPlainMessage, OutboundChunks, OutboundOpaqueMessage,
    OutboundPlainMessage, seal_record,
};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::Error;
use crate::msgs::message::MAX_PLAINTEXT_LEN;

const TAG_LEN: usize = 16;
const AAD_PREFIX_LEN: usize = 8 + 1 + 1 + 1 + 2 + 8;
const MAX_CID_LEN: usize = 255;

/// Fixed-capacity AAD; only `as_ref()`'s exact prefix is authenticated.
pub(crate) struct CidAad {
    bytes: [u8; AAD_PREFIX_LEN + MAX_CID_LEN + 2],
    len: usize,
}

impl CidAad {
    fn new(version: ProtocolVersion, seq: u64, cid: &[u8], inner_len: usize) -> Option<Self> {
        if version != ProtocolVersion::DTLSv1_2
            || cid.is_empty()
            || cid.len() > MAX_CID_LEN
            || !(1..=MAX_PLAINTEXT_LEN).contains(&inner_len)
        {
            return None;
        }
        let mut aad = Self {
            bytes: [0; AAD_PREFIX_LEN + MAX_CID_LEN + 2],
            len: AAD_PREFIX_LEN + cid.len() + 2,
        };
        aad.bytes[..8].fill(0xff);
        aad.bytes[8] = ContentType::Tls12Cid.into();
        aad.bytes[9] = cid.len() as u8;
        aad.bytes[10] = ContentType::Tls12Cid.into();
        aad.bytes[11..13].copy_from_slice(&version.to_array());
        aad.bytes[13..21].copy_from_slice(&seq.to_be_bytes());
        aad.bytes[21..21 + cid.len()].copy_from_slice(cid);
        aad.bytes[21 + cid.len()..aad.len].copy_from_slice(&(inner_len as u16).to_be_bytes());
        Some(aad)
    }
}

impl AsRef<[u8]> for CidAad {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

fn valid_inner_type(typ: ContentType) -> bool {
    matches!(
        typ,
        ContentType::ChangeCipherSpec
            | ContentType::Alert
            | ContentType::Handshake
            | ContentType::ApplicationData
            | ContentType::Heartbeat
            | ContentType::ReturnRoutabilityCheck
    )
}

/// Builds only an encrypted body. The record layer owns DTLS framing.
pub(crate) fn seal_cid(
    msg: OutboundPlainMessage<'_>,
    seq: u64,
    cid: &[u8],
    padding_len: usize,
    explicit_len: usize,
    seal: impl FnOnce(&[u8], &mut [u8]) -> Result<(), Error>,
) -> Result<OutboundOpaqueMessage, Error> {
    // Unlike `OutboundChunks::len`, this also rejects reversed ranges.
    let content_len = match &msg.payload {
        OutboundChunks::Single(bytes) => bytes.len(),
        OutboundChunks::Multiple { start, end, .. } => {
            end.checked_sub(*start).ok_or(Error::EncryptError)?
        }
    };
    if !valid_inner_type(msg.typ) || (content_len == 0 && msg.typ != ContentType::ApplicationData) {
        return Err(Error::EncryptError);
    }
    let inner_len = content_len
        .checked_add(1)
        .and_then(|len| len.checked_add(padding_len))
        .ok_or(Error::EncryptError)?;
    let aad = CidAad::new(msg.version, seq, cid, inner_len).ok_or(Error::EncryptError)?;
    let body_len = explicit_len + inner_len + TAG_LEN;
    seal_record(
        ContentType::Tls12Cid,
        msg.version,
        &msg.payload,
        explicit_len,
        body_len,
        |body| {
            // seal_record checks that all claimed content bytes exist before
            // extending the body with the type, padding and tag space.
            body[explicit_len + content_len] = msg.typ.into();
            seal(aad.as_ref(), body)
        },
    )
}

/// Checks framing and the encoded inner bound before attempting decryption.
pub(crate) fn open_cid_aad(
    msg: &InboundOpaqueMessage<'_>,
    seq: u64,
    cid: &[u8],
    explicit_len: usize,
) -> Result<(usize, CidAad), Error> {
    if msg.typ != ContentType::Tls12Cid {
        return Err(Error::DecryptError);
    }
    let inner_len = msg
        .payload
        .len()
        .checked_sub(explicit_len + TAG_LEN)
        .ok_or(Error::DecryptError)?;
    let aad = CidAad::new(msg.version, seq, cid, inner_len).ok_or(Error::DecryptError)?;
    Ok((inner_len, aad))
}

/// Called only after a successful tag check and removal of nonce/tag bytes.
pub(crate) fn unpad_cid(
    mut msg: InboundOpaqueMessage<'_>,
) -> Result<InboundPlainMessage<'_>, Error> {
    let inner_len = msg.payload.len();
    let type_pos = msg
        .payload
        .iter()
        .rposition(|byte| *byte != 0)
        .ok_or(Error::DecryptError)?;
    let typ = ContentType::from(msg.payload[type_pos]);
    if !valid_inner_type(typ) || (type_pos == 0 && typ != ContentType::ApplicationData) {
        return Err(Error::DecryptError);
    }
    msg.payload.truncate(type_pos);
    Ok(InboundPlainMessage::with_record_plaintext_len(
        typ,
        msg.version,
        msg.payload.into_inner(),
        inner_len,
    ))
}

#[cfg(test)]
pub(crate) mod tests;
