//! HTTP request formatting for callers that supply an OCSP transport.

use alloc::string::String;
use core::fmt;

use super::RevocationQuery;
use crate::error::Error;

const GET_URL_LIMIT: usize = 255;
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// An OCSP request formatted for an application-owned HTTP transport.
#[non_exhaustive]
pub enum OcspHttpRequest<'a> {
    /// A GET request carrying a percent-encoded DER request in its path.
    Get {
        /// The URL to request.
        url: String,
    },
    /// A POST request with an `application/ocsp-request` body.
    Post {
        /// The responder endpoint.
        url: &'a str,
        /// The DER request body.
        body: &'a [u8],
    },
}

impl fmt::Debug for OcspHttpRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Get { .. } => f.debug_struct("Get").finish_non_exhaustive(),
            Self::Post { .. } => f.debug_struct("Post").finish_non_exhaustive(),
        }
    }
}

impl RevocationQuery {
    /// Formats a request to an endpoint authorized by the application.
    ///
    /// RFC 5019 uses GET when the encoded URL fits in 255 bytes, and POST
    /// otherwise. The application still validates and authorizes the endpoint
    /// and the address it dials. Send `Accept: application/ocsp-response` for
    /// either method, and `Content-Type: application/ocsp-request` for POST.
    pub fn http_request<'a>(&'a self, responder: &'a str) -> Result<OcspHttpRequest<'a>, Error> {
        let valid_endpoint = responder
            .strip_prefix("http://")
            .or_else(|| responder.strip_prefix("https://"))
            .and_then(|rest| rest.split(['/', '?']).next())
            .is_some_and(|authority| !authority.is_empty() && !authority.contains('@'));
        if !valid_endpoint
            || responder.contains(['#', '\\'])
            || !responder.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(Error::general("invalid OCSP responder endpoint"));
        }
        let post = || OcspHttpRequest::Post {
            url: responder,
            body: self.request_der(),
        };
        let encoded_len = self.request_der().len().div_ceil(3).saturating_mul(4);
        if responder.len().saturating_add(encoded_len) > GET_URL_LIMIT {
            return Ok(post());
        }
        let (base, query) = responder.split_once('?').unwrap_or((responder, ""));
        let mut url = String::from(base);
        if !base.ends_with('/') {
            url.push('/');
        }
        for chunk in self.request_der().chunks(3) {
            let first = chunk[0];
            let second = *chunk.get(1).unwrap_or(&0);
            let third = *chunk.get(2).unwrap_or(&0);
            push_base64(&mut url, first >> 2);
            push_base64(&mut url, ((first & 3) << 4) | (second >> 4));
            if chunk.len() >= 2 {
                push_base64(&mut url, ((second & 15) << 2) | (third >> 6));
            } else {
                url.push_str("%3D");
            }
            if chunk.len() == 3 {
                push_base64(&mut url, third & 63);
            } else {
                url.push_str("%3D");
            }
        }
        if responder.contains('?') {
            url.push('?');
            url.push_str(query);
        }
        if url.len() <= GET_URL_LIMIT {
            Ok(OcspHttpRequest::Get { url })
        } else {
            Ok(post())
        }
    }
}

fn push_base64(url: &mut String, index: u8) {
    match BASE64[usize::from(index)] {
        b'+' => url.push_str("%2B"),
        b'/' => url.push_str("%2F"),
        byte => url.push(char::from(byte)),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn encodes_path_and_retains_query() {
        let query = RevocationQuery::new([0; 32], vec![], vec![0xfb, 0xff]);
        let request = query
            .http_request("https://responder.example/status?a=b")
            .unwrap();
        assert!(matches!(
            request,
            OcspHttpRequest::Get { url } if url == "https://responder.example/status/%2B%2F8%3D?a=b"
        ));
    }

    #[test]
    fn select_method_after_percent_encoding() {
        let der = vec![0xff; 52];
        let query = RevocationQuery::new([0; 32], vec![], der.clone());
        let responder = "https://responder.example/padding";
        let request = query.http_request(responder).unwrap();
        assert!(matches!(
            request, OcspHttpRequest::Get { url } if url.len() <= GET_URL_LIMIT
        ));
        let longer = String::from(responder) + "/padding/long/path";
        assert!(matches!(
            query.http_request(&longer).unwrap(),
            OcspHttpRequest::Post { url, body } if url == longer && body == der
        ));
    }
}
