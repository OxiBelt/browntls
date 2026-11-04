//! NIST P-521 (secp521r1): ECDH and ECDSA on portable 64-bit Montgomery arithmetic.

use super::params::P521;

super::api::curve_module! {
    name = "P-521",
    soft = P521,
    fast = P521,
    accel = false,
    limbs = 9,
    field_len = 66,
    tls_hash = Sha512
}
