//! NewSessionTicket messages (RFC 5077 §3.3, RFC 8446 §4.6.1).

use alloc::vec::Vec;

use super::extensions::{encode_extension, read_extensions};
use crate::error::InvalidMessage;
use crate::msgs::base::{PayloadU8, PayloadU16};
use crate::msgs::codec::{Codec, LengthPrefixedBuffer, ListLength, Reader};
use crate::msgs::enums::ExtensionType;

/// A TLS 1.2 NewSessionTicket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NewSessionTicketPayload {
    pub(crate) lifetime_hint: u32,
    pub(crate) ticket: PayloadU16,
}

impl NewSessionTicketPayload {
    pub(crate) fn new(lifetime_hint: u32, ticket: Vec<u8>) -> Self {
        Self {
            lifetime_hint,
            ticket: PayloadU16::new(ticket),
        }
    }
}

impl Codec<'_> for NewSessionTicketPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.lifetime_hint.encode(bytes);
        self.ticket.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            lifetime_hint: u32::read(r)?,
            ticket: PayloadU16::read(r)?,
        })
    }
}

/// Extensions of a TLS 1.3 NewSessionTicket.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct NewSessionTicketExtensions {
    pub(crate) max_early_data_size: Option<u32>,
    pub(crate) unknown: Vec<ExtensionType>,
}

impl Codec<'_> for NewSessionTicketExtensions {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let list = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        if let Some(size) = &self.max_early_data_size {
            encode_extension(ExtensionType::EarlyData, list.buf, |b| size.encode(b));
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let mut out = Self::default();
        read_extensions(r, |typ, body| {
            match typ {
                ExtensionType::EarlyData => out.max_early_data_size = Some(u32::read(body)?),
                other => {
                    out.unknown.push(other);
                    body.rest();
                }
            }
            Ok(())
        })?;
        Ok(out)
    }
}

/// A TLS 1.3 NewSessionTicket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NewSessionTicketPayloadTls13 {
    pub(crate) lifetime: u32,
    pub(crate) age_add: u32,
    pub(crate) nonce: PayloadU8,
    pub(crate) ticket: PayloadU16,
    pub(crate) exts: NewSessionTicketExtensions,
}

impl NewSessionTicketPayloadTls13 {
    pub(crate) fn new(lifetime: u32, age_add: u32, nonce: Vec<u8>, ticket: Vec<u8>) -> Self {
        Self {
            lifetime,
            age_add,
            nonce: PayloadU8::new(nonce),
            ticket: PayloadU16::new(ticket),
            exts: NewSessionTicketExtensions::default(),
        }
    }
}

impl Codec<'_> for NewSessionTicketPayloadTls13 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.lifetime.encode(bytes);
        self.age_add.encode(bytes);
        self.nonce.encode(bytes);
        self.ticket.encode(bytes);
        self.exts.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let lifetime = u32::read(r)?;
        let age_add = u32::read(r)?;
        let nonce = PayloadU8::read(r)?;
        let ticket = PayloadU16::read(r)?;
        if ticket.0.is_empty() {
            return Err(InvalidMessage::EmptyTicketValue);
        }
        let exts = NewSessionTicketExtensions::read(r)?;
        Ok(Self {
            lifetime,
            age_add,
            nonce,
            ticket,
            exts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls12_ticket() {
        let t = NewSessionTicketPayload::new(300, alloc::vec![1, 2]);
        assert_eq!(
            NewSessionTicketPayload::read_bytes(&t.get_encoding()).unwrap(),
            t
        );
    }

    #[test]
    fn tls13_ticket() {
        let mut t = NewSessionTicketPayloadTls13::new(
            7200,
            0xdead_beef,
            alloc::vec![0],
            alloc::vec![9; 40],
        );
        t.exts.max_early_data_size = Some(1024);
        let enc = t.get_encoding();
        assert_eq!(NewSessionTicketPayloadTls13::read_bytes(&enc).unwrap(), t);
        let empty = NewSessionTicketPayloadTls13 {
            ticket: PayloadU16::empty(),
            ..t
        };
        assert_eq!(
            NewSessionTicketPayloadTls13::read_bytes(&empty.get_encoding()),
            Err(InvalidMessage::EmptyTicketValue)
        );
    }
}
