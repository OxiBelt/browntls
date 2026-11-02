//! NIST P-384 (secp384r1): ECDH and ECDSA on portable 64-bit Montgomery arithmetic.

use super::params::P384;

super::api::curve_module! {
    name = "P-384",
    soft = P384,
    fast = P384,
    accel = false,
    limbs = 6,
    field_len = 48,
    tls_hash = Sha384
}
