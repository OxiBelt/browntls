//! The `ech` SvcParam of DNS SVCB and HTTPS records (RFC 9848), which
//! carries a server's `ECHConfigList`.
//!
//! These helpers take record data the application already resolved; this
//! crate does no DNS lookups. Pass the result to
//! [`EchConfig::new`](super::EchConfig::new).

use alloc::vec::Vec;

use crate::error::{Error, InvalidMessage};

/// The `ech` SvcParamKey (RFC 9848 §3; IANA "key5").
pub const ECH_SVC_PARAM_KEY: u16 = 5;

fn invalid() -> Error {
    Error::InvalidMessage(InvalidMessage::InvalidEchConfig)
}

/// Finds the `ech` value in wire-format SvcParams (RFC 9460 §2.2: key,
/// length, value, keys strictly increasing), returning the `ECHConfigList`
/// (with its length prefix), or `None` if there is no `ech` key.
///
/// # Errors
///
/// [`InvalidMessage::InvalidEchConfig`] if the parameters are malformed or
/// out of order, or the `ech` value is not a well-formed `ECHConfigList`.
pub fn ech_config_list_from_svc_params(params: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let mut at = 0;
    let mut last: Option<u16> = None;
    let mut found = None;
    while at < params.len() {
        let header = params.get(at..at + 4).ok_or_else(invalid)?;
        let key = u16::from_be_bytes([header[0], header[1]]);
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let value = params.get(at + 4..at + 4 + len).ok_or_else(invalid)?;
        if last.is_some_and(|prev| key <= prev) {
            return Err(invalid());
        }
        last = Some(key);
        if key == ECH_SVC_PARAM_KEY {
            super::config::read_config_list(value).map_err(|_| invalid())?;
            found = Some(value.to_vec());
        }
        at += 4 + len;
    }
    Ok(found)
}

/// Finds the `ech` value in the wire-format RDATA of an SVCB or HTTPS
/// record (RFC 9460 §2.2: priority, uncompressed target name, then
/// SvcParams). An AliasMode record (priority 0) has none.
///
/// # Errors
///
/// As [`ech_config_list_from_svc_params`], and for a malformed target name.
pub fn ech_config_list_from_svcb_rdata(rdata: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let priority = rdata.get(..2).ok_or_else(invalid)?;
    let mut at = 2;
    // TargetName: labels, each a length byte (at most 63) and that many
    // bytes, ending with the root label.
    loop {
        let len = usize::from(*rdata.get(at).ok_or_else(invalid)?);
        if len > 63 {
            return Err(invalid());
        }
        at += 1 + len;
        if len == 0 {
            break;
        }
    }
    if at > rdata.len() {
        return Err(invalid());
    }
    if priority == [0, 0] {
        return Ok(None);
    }
    ech_config_list_from_svc_params(&rdata[at..])
}

/// Decodes the presentation-format value of an `ech` SvcParam (RFC 9848
/// §3): Base64 (RFC 4648 §4), optionally in double quotes, without escape
/// sequences. Returns the `ECHConfigList` with its length prefix.
///
/// # Errors
///
/// [`InvalidMessage::InvalidEchConfig`] for an escape sequence, whitespace,
/// invalid Base64, or a malformed `ECHConfigList`.
pub fn ech_config_list_from_presentation(value: &str) -> Result<Vec<u8>, Error> {
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    if value.is_empty()
        || value
            .bytes()
            .any(|b| b == b'\\' || b == b'"' || b.is_ascii_whitespace())
    {
        return Err(invalid());
    }
    let list = browntls_pki::pem::base64_decode(value.as_bytes()).map_err(|_| invalid())?;
    super::config::read_config_list(&list).map_err(|_| invalid())?;
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = "AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXNpdGVzLmV4YW1wbGUubmV0AAA=";

    fn example() -> Vec<u8> {
        browntls_pki::pem::base64_decode(EXAMPLE.as_bytes()).unwrap()
    }

    fn param(key: u16, value: &[u8]) -> Vec<u8> {
        let mut out = key.to_be_bytes().to_vec();
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    #[test]
    fn presentation_format() {
        let list = example();
        assert_eq!(ech_config_list_from_presentation(EXAMPLE).unwrap(), list);
        let quoted = alloc::format!("\"{EXAMPLE}\"");
        assert_eq!(ech_config_list_from_presentation(&quoted).unwrap(), list);
        for bad in ["", "\"\"", "AE\\j+", "AEj+ DQ", "!!!!", "AAA="] {
            assert!(ech_config_list_from_presentation(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn wire_format_params_and_rdata() {
        let list = example();
        // alpn=h2 (key 1), ech (key 5), ipv6hint (key 6).
        let mut params = param(1, b"\x02h2");
        params.extend(param(ECH_SVC_PARAM_KEY, &list));
        params.extend(param(6, &[0; 16]));
        assert_eq!(
            ech_config_list_from_svc_params(&params).unwrap(),
            Some(list.clone())
        );
        assert_eq!(
            ech_config_list_from_svc_params(&param(1, b"\x02h2")).unwrap(),
            None
        );
        // Out of order, repeated, truncated, malformed value.
        let mut swapped = param(6, &[0; 16]);
        swapped.extend(param(ECH_SVC_PARAM_KEY, &list));
        assert!(ech_config_list_from_svc_params(&swapped).is_err());
        let mut twice = param(ECH_SVC_PARAM_KEY, &list);
        twice.extend(param(ECH_SVC_PARAM_KEY, &list));
        assert!(ech_config_list_from_svc_params(&twice).is_err());
        assert!(ech_config_list_from_svc_params(&params[..params.len() - 1]).is_err());
        assert!(ech_config_list_from_svc_params(&param(5, &[0, 1, 2])).is_err());

        // priority 1, target "svc.example.", params.
        let mut rdata = alloc::vec![0, 1, 3, b's', b'v', b'c', 7];
        rdata.extend_from_slice(b"example");
        rdata.push(0);
        rdata.extend_from_slice(&params);
        assert_eq!(ech_config_list_from_svcb_rdata(&rdata).unwrap(), Some(list));
        // AliasMode, root target.
        assert_eq!(ech_config_list_from_svcb_rdata(&[0, 0, 0]).unwrap(), None);
        // Truncated target name.
        assert!(ech_config_list_from_svcb_rdata(&[0, 1, 5, b'a']).is_err());
        assert!(ech_config_list_from_svcb_rdata(&[0]).is_err());
    }
}
