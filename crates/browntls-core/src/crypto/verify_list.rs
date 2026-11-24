//! Compile-time concatenation of signature verification algorithm lists,
//! shared by the providers' opt-in tables (the ML-DSA lists of `native` and
//! `rustcrypto`), so that an opt-in list is computed from the default list
//! and cannot drift from it.

use browntls_pki::SignatureVerificationAlgorithm;

/// `a` followed by `b`, as an array of exactly `N` entries. A wrong `N` is
/// a compile-time error where the result initialises a static.
pub(crate) const fn concat<const N: usize>(
    a: &[&'static dyn SignatureVerificationAlgorithm],
    b: &[&'static dyn SignatureVerificationAlgorithm],
) -> [&'static dyn SignatureVerificationAlgorithm; N] {
    assert!(a.len() + b.len() == N && N > 0);
    let first = if a.is_empty() { b[0] } else { a[0] };
    let mut out = [first; N];
    let mut i = 0;
    while i < a.len() {
        out[i] = a[i];
        i += 1;
    }
    let mut j = 0;
    while j < b.len() {
        out[a.len() + j] = b[j];
        j += 1;
    }
    out
}
