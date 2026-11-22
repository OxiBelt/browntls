//! Bounded BER cursor for HPKE private-key containers.
//!
//! The caller shares one budget across the outer container, string segments,
//! attribute values and ASN.1 encapsulated in the privateKey OCTET STRING.

use crate::Error;
use crate::der::tag;
use crate::zeroize::Zeroizing;

pub(super) const MAX_BYTES: usize = 16 * 1024;
const MAX_DEPTH: usize = 16;
const MAX_TLVS: usize = 4096;
const CONSTRUCTED: u8 = 0x20;

#[derive(Default)]
pub(super) struct Budget {
    tlvs: usize,
    flattened: usize,
}

impl Budget {
    fn charge_tlv(&mut self, depth: usize) -> Result<(), Error> {
        if depth >= MAX_DEPTH || self.tlvs >= MAX_TLVS {
            return Err(Error::InvalidEncoding);
        }
        self.tlvs += 1;
        Ok(())
    }

    fn charge_flattened(&mut self, size: usize) -> Result<(), Error> {
        let available = MAX_BYTES - self.flattened;
        if size > available {
            return Err(Error::InvalidEncoding);
        }
        self.flattened += size;
        Ok(())
    }
}

pub(super) struct Reader<'a> {
    input: &'a [u8],
    depth: usize,
    indefinite: bool,
}

impl<'a> Reader<'a> {
    pub(super) fn new(input: &'a [u8], depth: usize) -> Self {
        Self {
            input,
            depth,
            indefinite: false,
        }
    }

    pub(super) fn peek(&self) -> Option<u8> {
        if self.at_end() {
            None
        } else {
            self.input.first().copied()
        }
    }

    pub(super) fn at_end(&self) -> bool {
        if self.indefinite {
            self.input.starts_with(&[0, 0])
        } else {
            self.input.is_empty()
        }
    }

    pub(super) fn finish(&self) -> Result<(), Error> {
        if self.at_end() {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let (value, rest) = self
            .input
            .split_at_checked(len)
            .ok_or(Error::InvalidEncoding)?;
        self.input = rest;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn identifier(&mut self) -> Result<u8, Error> {
        let first = self.byte()?;
        // EOC is consumed only by the enclosing indefinite-length reader.
        // Universal tag number 15 is reserved.
        if matches!(first, 0x00 | 0x20 | 0x0f | 0x2f) {
            return Err(Error::InvalidEncoding);
        }
        if first & 0x1f == 0x1f {
            // High-tag-number form can occur in opaque attribute values.
            // Consume its minimally encoded number without storing it.
            let mut part = self.byte()?;
            if part < 31 || part == 0x80 {
                return Err(Error::InvalidEncoding);
            }
            while part & 0x80 != 0 {
                part = self.byte()?;
            }
        }
        Ok(first)
    }

    fn length(&mut self) -> Result<Option<usize>, Error> {
        match self.byte()? {
            first @ 0..=0x7f => Ok(Some(usize::from(first))),
            0x80 => Ok(None),
            0xff => Err(Error::InvalidEncoding),
            first => {
                let mut len = 0usize;
                for &byte in self.take(usize::from(first & 0x7f))? {
                    len = len
                        .checked_mul(256)
                        .and_then(|len| len.checked_add(usize::from(byte)))
                        .ok_or(Error::InvalidEncoding)?;
                    // Reject as soon as the value exceeds the bounded input.
                    if len > self.input.len() {
                        return Err(Error::InvalidEncoding);
                    }
                }
                Ok(Some(len))
            }
        }
    }

    // Each constructed value gets its own boundary. An indefinite child
    // resumes its parent immediately after its EOC, without scanning twice.
    fn read<T>(
        &mut self,
        budget: &mut Budget,
        visit: impl FnOnce(u8, &mut Reader<'a>, &mut Budget) -> Result<T, Error>,
    ) -> Result<T, Error> {
        budget.charge_tlv(self.depth)?;
        let t = self.identifier()?;
        let constructed = t & CONSTRUCTED != 0;
        let len = self.length()?;
        let mut value = match len {
            Some(len) => Self::new(self.take(len)?, self.depth + 1),
            None if constructed => Self {
                input: self.input,
                depth: self.depth + 1,
                indefinite: true,
            },
            None => return Err(Error::InvalidEncoding),
        };
        let result = visit(t, &mut value, budget)?;
        if constructed {
            value.finish()?;
        }
        if len.is_none() {
            self.input = &value.input[2..];
        }
        Ok(result)
    }

    pub(super) fn constructed<T>(
        &mut self,
        expected: u8,
        budget: &mut Budget,
        visit: impl FnOnce(&mut Reader<'a>, &mut Budget) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.read(budget, |t, value, budget| {
            if t != expected || t & CONSTRUCTED == 0 {
                return Err(Error::InvalidEncoding);
            }
            visit(value, budget)
        })
    }

    pub(super) fn primitive(
        &mut self,
        expected: u8,
        budget: &mut Budget,
    ) -> Result<&'a [u8], Error> {
        self.read(budget, |t, value, _| {
            if t != expected || t & CONSTRUCTED != 0 {
                return Err(Error::InvalidEncoding);
            }
            Ok(value.input)
        })
    }

    pub(super) fn oid(&mut self, budget: &mut Budget) -> Result<&'a [u8], Error> {
        let oid = self.primitive(tag::OID, budget)?;
        validate_oid(oid)?;
        Ok(oid)
    }

    pub(super) fn octets<const N: usize, T>(
        &mut self,
        budget: &mut Budget,
        visit: impl FnOnce(&[u8], usize, &mut Budget) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.read(budget, |t, value, budget| match t {
            tag::OCTET_STRING if value.input.len() <= N => visit(value.input, value.depth, budget),
            t if t == tag::OCTET_STRING | CONSTRUCTED => {
                joined_octets::<N, T>(t, value, budget, visit)
            }
            _ => Err(Error::InvalidEncoding),
        })
    }

    pub(super) fn bit_string(
        &mut self,
        primitive_tag: u8,
        budget: &mut Budget,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.read(budget, |t, value, budget| {
            if t & !CONSTRUCTED != primitive_tag {
                return Err(Error::InvalidEncoding);
            }
            let mut len = 0;
            let unused = visit_string(t, value, budget, tag::BIT_STRING, &mut |bytes, budget| {
                append(out, &mut len, bytes, t & CONSTRUCTED != 0, budget)
            })?;
            if unused != 0 {
                return Err(Error::InvalidEncoding);
            }
            Ok(len)
        })
    }

    // An attribute value is open-typed. Check its BER framing recursively
    // and the encoding of the basic universal types used by this reader.
    pub(super) fn skip_value(&mut self, budget: &mut Budget) -> Result<(), Error> {
        self.read(budget, |t, value, budget| {
            let primitive = t & !CONSTRUCTED;
            let segment_tag = match primitive {
                tag::BIT_STRING => Some(tag::BIT_STRING),
                // X.690 uses implicitly tagged OCTET STRING encodings for
                // these types, including ObjectDescriptor and both time
                // types.
                tag::OCTET_STRING | 7 | 12 | 18..=28 | 30 => Some(tag::OCTET_STRING),
                _ => None,
            };
            if let Some(segment_tag) = segment_tag {
                visit_string(t, value, budget, segment_tag, &mut |_, _| Ok(()))?;
                return Ok(());
            }
            if t & CONSTRUCTED != 0 {
                if matches!(
                    primitive,
                    tag::BOOLEAN | tag::INTEGER | tag::NULL | tag::OID | 9 | 10 | 13 | 14
                ) {
                    return Err(Error::InvalidEncoding);
                }
                while !value.at_end() {
                    value.skip_value(budget)?;
                }
                return Ok(());
            }
            match t {
                tag::BOOLEAN if value.input.len() != 1 => Err(Error::InvalidEncoding),
                tag::NULL if !value.input.is_empty() => Err(Error::InvalidEncoding),
                tag::OID | 13 => validate_oid(value.input),
                tag::INTEGER | 10 => validate_integer(value.input),
                8 | 11 | 16 | 17 | 29 => Err(Error::InvalidEncoding),
                _ => Ok(()),
            }
        })
    }
}

fn validate_oid(oid: &[u8]) -> Result<(), Error> {
    let mut start = true;
    for &byte in oid {
        if start && byte == 0x80 {
            return Err(Error::InvalidEncoding);
        }
        start = byte & 0x80 == 0;
    }
    if oid.is_empty() || !start {
        return Err(Error::InvalidEncoding);
    }
    Ok(())
}

fn validate_integer(value: &[u8]) -> Result<(), Error> {
    match value {
        [] => Err(Error::InvalidEncoding),
        [0, next, ..] if next & 0x80 == 0 => Err(Error::InvalidEncoding),
        [0xff, next, ..] if next & 0x80 != 0 => Err(Error::InvalidEncoding),
        _ => Ok(()),
    }
}

// The DER path borrows the original OCTET STRING. Only segmented BER needs
// the bounded, zeroising stack buffer.
#[inline(never)]
fn joined_octets<const N: usize, T>(
    t: u8,
    value: &mut Reader<'_>,
    budget: &mut Budget,
    visit: impl FnOnce(&[u8], usize, &mut Budget) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut out = Zeroizing([0u8; N]);
    let mut len = 0;
    visit_string(t, value, budget, tag::OCTET_STRING, &mut |bytes, budget| {
        append(&mut out[..], &mut len, bytes, true, budget)
    })?;
    visit(&out[..len], value.depth, budget)
}

fn append(
    out: &mut [u8],
    len: &mut usize,
    bytes: &[u8],
    flattened: bool,
    budget: &mut Budget,
) -> Result<(), Error> {
    if flattened {
        budget.charge_flattened(bytes.len())?;
    }
    let end = *len + bytes.len();
    out.get_mut(*len..end)
        .ok_or(Error::InvalidEncoding)?
        .copy_from_slice(bytes);
    *len = end;
    Ok(())
}

fn visit_string(
    t: u8,
    value: &mut Reader<'_>,
    budget: &mut Budget,
    segment_tag: u8,
    visit: &mut impl FnMut(&[u8], &mut Budget) -> Result<(), Error>,
) -> Result<u8, Error> {
    if t & CONSTRUCTED == 0 {
        if segment_tag == tag::BIT_STRING {
            let (&unused, bytes) = value.input.split_first().ok_or(Error::InvalidEncoding)?;
            if unused > 7 || (bytes.is_empty() && unused != 0) {
                return Err(Error::InvalidEncoding);
            }
            visit(bytes, budget)?;
            return Ok(unused);
        }
        visit(value.input, budget)?;
        return Ok(0);
    }
    let mut unused = 0;
    while !value.at_end() {
        if unused != 0 {
            return Err(Error::InvalidEncoding);
        }
        unused = value.read(budget, |t, child, budget| {
            if t & !CONSTRUCTED != segment_tag {
                return Err(Error::InvalidEncoding);
            }
            visit_string(t, child, budget, segment_tag, visit)
        })?;
    }
    Ok(unused)
}
