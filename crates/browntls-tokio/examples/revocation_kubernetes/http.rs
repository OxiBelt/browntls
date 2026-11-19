//! The smallest HTTP client an OCSP lookup needs: one request over a new
//! plain TCP connection, formatted by [`RevocationQuery::http_request`]
//! (`GET` or `POST`, RFC 5019 section 5), with a bounded response and no
//! redirects.

use std::io;

use browntls::revocation::{OcspHttpRequest, RevocationQuery};
use browntls_tokio::browntls;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Longest response header block accepted.
const MAX_HEADERS: usize = 8 * 1024;

/// The `host:port` and the request target of an `http://host:port/path`
/// URL.
pub(crate) fn split_url(url: &str) -> io::Result<(&str, &str)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| invalid("responder URL is not http://"))?;
    let (authority, target) = match rest.find('/') {
        Some(slash) => rest.split_at(slash),
        None => (rest, "/"),
    };
    let has_port = authority.rsplit_once(':').is_some_and(|(host, port)| {
        !host.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
    });
    let printable = |text: &str| text.bytes().all(|b| b.is_ascii_graphic());
    if !has_port || !printable(authority) || !printable(target) {
        return Err(invalid("responder URL needs host:port"));
    }
    Ok((authority, target))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn bad_response(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Sends `query` to `responder`, which the caller authorized, and returns
/// the body of a `200` answer of at most `max_response_len` bytes. The
/// caller bounds the time.
pub(crate) async fn fetch_ocsp(
    query: &RevocationQuery,
    responder: &str,
    max_response_len: usize,
) -> io::Result<Vec<u8>> {
    let request = query
        .http_request(responder)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let (url, body): (&str, &[u8]) = match &request {
        OcspHttpRequest::Get { url } => (url, &[]),
        OcspHttpRequest::Post { url, body } => (url, body),
        _ => return Err(invalid("unsupported OCSP request method")),
    };
    let (authority, target) = split_url(url)?;
    let head = if matches!(request, OcspHttpRequest::Get { .. }) {
        format!(
            "GET {target} HTTP/1.0\r\nHost: {authority}\r\n\
             Accept: application/ocsp-response\r\nConnection: close\r\n\r\n"
        )
    } else {
        format!(
            "POST {target} HTTP/1.0\r\nHost: {authority}\r\n\
             Accept: application/ocsp-response\r\nContent-Type: application/ocsp-request\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
    };
    let mut stream = TcpStream::connect(authority).await?;
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await?;

    let limit = MAX_HEADERS.saturating_add(max_response_len);
    let mut answer = Vec::new();
    let read = (&mut stream)
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut answer)
        .await?;
    if read > limit {
        return Err(bad_response("responder answer too long"));
    }
    let headers_end = answer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .filter(|end| *end <= MAX_HEADERS)
        .ok_or_else(|| bad_response("responder answer has no header block"))?;
    let headers = std::str::from_utf8(&answer[..headers_end])
        .map_err(|_| bad_response("responder headers are not text"))?;
    let mut lines = headers.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if status.split(' ').nth(1) != Some("200") {
        return Err(bad_response("responder did not answer 200"));
    }
    let body = &answer[headers_end + 4..];
    let declared = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>());
    match declared {
        Some(Ok(len)) if len == body.len() => {}
        None => {}
        Some(_) => return Err(bad_response("responder body length mismatch")),
    }
    if body.is_empty() || body.len() > max_response_len {
        return Err(bad_response("responder body out of bounds"));
    }
    Ok(body.to_vec())
}
