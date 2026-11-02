//! Splitting outgoing messages into records no larger than the fragment limit.

use super::message::{HEADER_SIZE, MAX_PLAINTEXT_LEN, OutboundChunks, OutboundPlainMessage, PlainMessage};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::Error;

/// The smallest `max_fragment_size` (including header) we accept.
const MINIMUM_MAX_FRAGMENT_SIZE: usize = 32;

/// Splits plaintext into fragments.
#[derive(Debug)]
pub(crate) struct MessageFragmenter {
    max_frag: usize,
}

impl Default for MessageFragmenter {
    fn default() -> Self {
        Self {
            max_frag: MAX_PLAINTEXT_LEN,
        }
    }
}

impl MessageFragmenter {
    /// Yields `msg` as one or more fragments, each at most `max_frag` bytes.
    pub(crate) fn fragment_message<'a>(
        &self,
        msg: &'a PlainMessage,
    ) -> impl Iterator<Item = OutboundPlainMessage<'a>> + 'a {
        self.fragment_payload(msg.typ, msg.version, msg.payload.bytes().into())
    }

    /// Yields `payload` as one or more fragments. An empty payload yields one
    /// empty fragment.
    pub(crate) fn fragment_payload<'a>(
        &self,
        typ: ContentType,
        version: ProtocolVersion,
        payload: OutboundChunks<'a>,
    ) -> impl Iterator<Item = OutboundPlainMessage<'a>> + 'a {
        Fragments {
            max_frag: self.max_frag,
            typ,
            version,
            remaining: Some(payload),
        }
    }

    /// Sets the limit on record size including the header, as RFC 6066's
    /// `max_fragment_length` and rustls's `max_fragment_size` define it.
    pub(crate) fn set_max_fragment_size(&mut self, new: Option<usize>) -> Result<(), Error> {
        self.max_frag = match new {
            Some(sz) => {
                if !(MINIMUM_MAX_FRAGMENT_SIZE..=MAX_PLAINTEXT_LEN + HEADER_SIZE).contains(&sz) {
                    return Err(Error::BadMaxFragmentSize);
                }
                sz - HEADER_SIZE
            }
            None => MAX_PLAINTEXT_LEN,
        };
        Ok(())
    }

    pub(crate) fn max_fragment_len(&self) -> usize {
        self.max_frag
    }
}

struct Fragments<'a> {
    max_frag: usize,
    typ: ContentType,
    version: ProtocolVersion,
    remaining: Option<OutboundChunks<'a>>,
}

impl<'a> Iterator for Fragments<'a> {
    type Item = OutboundPlainMessage<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = self.remaining.take()?;
        let (this, rest) = remaining.split_at(self.max_frag);
        if !rest.is_empty() {
            self.remaining = Some(rest);
        }
        Some(OutboundPlainMessage {
            typ: self.typ,
            version: self.version,
            payload: this,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::base::Payload;

    fn msg(len: usize) -> PlainMessage {
        PlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: Payload::new(alloc::vec![0xabu8; len]),
        }
    }

    #[test]
    fn splits_at_limit() {
        let f = MessageFragmenter::default();
        let m = msg(MAX_PLAINTEXT_LEN * 2 + 1);
        let frags: alloc::vec::Vec<_> = f.fragment_message(&m).collect();
        assert_eq!(frags.len(), 3);
        assert_eq!(frags[0].payload.len(), MAX_PLAINTEXT_LEN);
        assert_eq!(frags[1].payload.len(), MAX_PLAINTEXT_LEN);
        assert_eq!(frags[2].payload.len(), 1);
        assert!(frags.iter().all(|f| f.typ == ContentType::ApplicationData));
    }

    #[test]
    fn small_message_is_one_fragment() {
        let f = MessageFragmenter::default();
        let m = msg(10);
        assert_eq!(f.fragment_message(&m).count(), 1);
        let empty = msg(0);
        let frags: alloc::vec::Vec<_> = f.fragment_message(&empty).collect();
        assert_eq!(frags.len(), 1);
        assert!(frags[0].payload.is_empty());
    }

    #[test]
    fn custom_limit() {
        let mut f = MessageFragmenter::default();
        assert_eq!(f.set_max_fragment_size(Some(31)), Err(Error::BadMaxFragmentSize));
        assert_eq!(
            f.set_max_fragment_size(Some(MAX_PLAINTEXT_LEN + HEADER_SIZE + 1)),
            Err(Error::BadMaxFragmentSize)
        );
        f.set_max_fragment_size(Some(32)).unwrap();
        assert_eq!(f.max_fragment_len(), 27);
        let m = msg(100);
        let frags: alloc::vec::Vec<_> = f.fragment_message(&m).collect();
        assert_eq!(frags.len(), 4);
        assert_eq!(frags[3].payload.len(), 100 - 27 * 3);
        f.set_max_fragment_size(None).unwrap();
        assert_eq!(f.max_fragment_len(), MAX_PLAINTEXT_LEN);
    }
}
