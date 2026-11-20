// Test vectors for the `trusted_ca_keys` identifiers, included by
// `cases/trusted_ca_keys.rs`.
//
// The certificates are self-signed CA certificates made with OpenSSL 3.0.13:
//
//     openssl req -x509 -newkey rsa:1024 -nodes -subj "/CN=TCK RSA" \
//         -days 3650 -outform DER
//     openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
//         -nodes -subj "/CN=TCK P-256" -days 3650 -outform DER
//     openssl req -x509 -newkey ed25519 -nodes -subj "/CN=TCK Ed25519" \
//         -days 3650 -outform DER
//
// (private keys discarded). The expected values were computed apart from
// the library: `cert_sha1_hash` with `openssl dgst -sha1` over the DER;
// `key_sha1_hash` with Python `hashlib.sha1` over the RSA modulus as
// minimal big-endian bytes (`n.to_bytes((n.bit_length() + 7) // 8)` from
// the `cryptography` package), and over the last 65 (P-256) or 32 (Ed25519)
// bytes of `openssl pkey -pubin -outform DER`, the `subjectPublicKey`
// value; the subject names with `cryptography`'s
// `Name.public_bytes()`.

/// RSA 1024 CA; its modulus starts with 0xb5, so its DER INTEGER has a
/// leading zero byte.
const RSA_CA: &str = concat!(
    "3082020030820169a00302010202143bb7ccd484eba6c15406ccc0bc2f828ccf52bc25300d06092a",
    "864886f70d01010b050030123110300e06035504030c0754434b20525341301e170d323631313230",
    "3038323133365a170d3336313131373038323133365a30123110300e06035504030c0754434b2052",
    "534130819f300d06092a864886f70d010101050003818d0030818902818100b5eb5b81d3d5a83245",
    "bf81d009118dc541abcb2cf48888fcff1a6ff66f2fc286e6d97deb6388fde170706b567ccbb55a49",
    "43d545c7e8f8c0f24f1f0688373adc7427abf41016d19167f5b8895d362dce1708ec3269617b8438",
    "1e6f4558e97de27a78e2cdca2fb60961a15b61f0bc8e84159c6956b3988488ebc3c298b8fcfcdb02",
    "03010001a3533051301d0603551d0e041604142a0d72345701c076a0fc486214f103d29bc3e71230",
    "1f0603551d230418301680142a0d72345701c076a0fc486214f103d29bc3e712300f0603551d1301",
    "01ff040530030101ff300d06092a864886f70d01010b050003818100455a81f59d583385bb5383a0",
    "5b6cd91fc1ec3bf68876db6faf7e300739982b2fcf44f43453b8bf571f463bee5dbe61f926a520fd",
    "8e527ac9e04832287979046b663d29bb97a339fac2a7d35da8f2b36c2b873889580e37a023ad6de0",
    "a7358c5401e7a2979c405ed7c2c278699abd12acdc19bb7e2158f9ea081ecfac1ed5a5a6",
);
/// ECDSA P-256 CA.
const P256_CA: &str = concat!(
    "3082017d30820123a00302010202143c0c631972928d1a31d6685d4c5a7dea7dbda194300a06082a",
    "8648ce3d04030230143112301006035504030c0954434b20502d323536301e170d32363131323030",
    "38323133365a170d3336313131373038323133365a30143112301006035504030c0954434b20502d",
    "3235363059301306072a8648ce3d020106082a8648ce3d0301070342000408a1ea77ac4237aa5b6e",
    "1508eedaf630c39e9758a863372d181baf6176ad249b44565339dc68f9548c01b8f08d3cd63313ab",
    "91c184e3eed71eed1cb580767b52a3533051301d0603551d0e0416041438d2829b47cb2ebb055bb1",
    "07ba8d171a6923818a301f0603551d2304183016801438d2829b47cb2ebb055bb107ba8d171a6923",
    "818a300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022036cc",
    "4020fd9bd9703093c5af29f4c228f15285122ab7336523a90bc7a678e18d022100dabc6427a019b7",
    "6683aa37f988dbc7afa40c9ed806cc795f4cd98845dd88cef4",
);
/// Ed25519 CA.
const ED25519_CA: &str = concat!(
    "308201403081f3a00302010202145bbdc892cdb3ffc0b7582f1c1340fe35a32d1f98300506032b65",
    "7030163114301206035504030c0b54434b2045643235353139301e170d3236313132303038323133",
    "365a170d3336313131373038323133365a30163114301206035504030c0b54434b20456432353531",
    "39302a300506032b6570032100643c13619e984a3d2cea2c10b7f3b81e475659d6579f520f0e794c",
    "32e476f6bfa3533051301d0603551d0e04160414bec44c2428e7b0a3e6f8c50cdf970c9ebbb4359c",
    "301f0603551d23041830168014bec44c2428e7b0a3e6f8c50cdf970c9ebbb4359c300f0603551d13",
    "0101ff040530030101ff300506032b6570034100def705ea5aaf21bab6a8ad156c2c5324aeb53e24",
    "9aa5e531b121ad44ba443a305756d2a17ee7cc21ecf814fcbac057f5ecb44f60b4c84f0f1d39aea5",
    "7e185301",
);

/// SHA-1 of each certificate's DER.
const RSA_CERT_SHA1: &str = "aadecadb9b5eeaf166c86e288df8e729941f90ea";
const P256_CERT_SHA1: &str = "a930c50c909292855f278db077d9dd6f1c688a91";
const ED25519_CERT_SHA1: &str = "023869dc50427bc19e0b636b9c78bbd9ab534e06";

/// SHA-1 of the RSA modulus without leading zero bytes.
const RSA_KEY_SHA1: &str = "4f1253066b4c7b02897da07d78597625e8cfcdb5";
/// SHA-1 of the RSA modulus with the leading zero byte of its DER INTEGER:
/// what RFC 6066 section 6 rules out.
const RSA_KEY_SHA1_WITH_ZERO: &str = "e72977ce26271bbdda74d1136c8ee1bff4295757";
/// SHA-1 of the `subjectPublicKey` value (the uncompressed point).
const P256_KEY_SHA1: &str = "38d2829b47cb2ebb055bb107ba8d171a6923818a";
/// SHA-1 of the `subjectPublicKey` value (the 32-byte public key).
const ED25519_KEY_SHA1: &str = "bec44c2428e7b0a3e6f8c50cdf970c9ebbb4359c";

/// The subject names, DER with the outer SEQUENCE.
const RSA_SUBJECT: &str = "30123110300e06035504030c0754434b20525341";
const P256_SUBJECT: &str = "30143112301006035504030c0954434b20502d323536";
const ED25519_SUBJECT: &str = "30163114301206035504030c0b54434b2045643235353139";
