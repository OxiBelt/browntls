//! The server's checks of client certificate URLs before any reaches the
//! application (RFC 6066 §11.3), and of the policy itself.

use super::ClientCertificateUrlPolicy;
use crate::error::Error;

/// Whether `bytes` are printable ASCII without spaces.
pub(super) fn is_printable(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| (0x21..=0x7e).contains(b))
}

/// Whether `scheme` is an RFC 3986 §3.1 scheme: a letter, then letters,
/// digits, `+`, `-` and `.`.
fn is_scheme(scheme: &[u8]) -> bool {
    match scheme.split_first() {
        Some((first, rest)) => {
            first.is_ascii_alphabetic()
                && rest
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        }
        None => false,
    }
}

/// Refuses a policy that could accept nothing, or that names a scheme that
/// is none. Connection creation fails with it, like other invalid
/// configuration.
pub(crate) fn check_policy(policy: Option<&ClientCertificateUrlPolicy>) -> Result<(), Error> {
    let Some(policy) = policy else {
        return Ok(());
    };
    if policy.max_urls == 0 || policy.max_url_len == 0 || policy.max_fetched_len == 0 {
        return Err(Error::General(
            "client_certificate_url limits must not be zero".into(),
        ));
    }
    if policy.allowed_schemes.is_empty()
        || !policy
            .allowed_schemes
            .iter()
            .all(|scheme| is_scheme(scheme.as_bytes()))
    {
        return Err(Error::General(
            "client_certificate_url needs at least one valid URI scheme".into(),
        ));
    }
    Ok(())
}

/// Whether the server refuses to fetch `url` by its own policy: too long,
/// not printable ASCII, a backslash, a fragment, no scheme or one not
/// allowed, no `//` authority or an empty one, or userinfo in it.
///
/// RFC 6066 §11.3: the client chooses the URL, so the server only lets
/// through what it was configured for. The application still authorizes
/// the destination it dials.
pub(crate) fn refused_url(policy: &ClientCertificateUrlPolicy, url: &[u8]) -> bool {
    if url.len() > policy.max_url_len
        || !is_printable(url)
        || url.contains(&b'\\')
        || url.contains(&b'#')
    {
        return true;
    }
    let Some(colon) = url.iter().position(|b| *b == b':') else {
        return true;
    };
    let (scheme, rest) = (&url[..colon], &url[colon + 1..]);
    if !is_scheme(scheme)
        || !policy
            .allowed_schemes
            .iter()
            .any(|allowed| allowed.as_bytes().eq_ignore_ascii_case(scheme))
    {
        return true;
    }
    let Some(after) = rest.strip_prefix(b"//") else {
        return true;
    };
    let end = after
        .iter()
        .position(|b| matches!(b, b'/' | b'?'))
        .unwrap_or(after.len());
    let authority = &after[..end];
    authority.is_empty() || authority.contains(&b'@')
}
