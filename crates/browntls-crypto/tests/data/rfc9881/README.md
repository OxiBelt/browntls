# RFC 9881 ML-DSA key examples

The example ML-DSA private and public keys of
[RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html) ("Internet X.509
Public Key Infrastructure -- Algorithm Identifiers for the Module-Lattice-Based
Digital Signature Algorithm (ML-DSA)"), Appendix C, used by
`tests/mldsa_pkcs8.rs`. They are specification examples, stored as the DER
that the RFC prints in the textual encoding of RFC 7468 (the Base64 lines
decoded, nothing else changed). The RFC text is "Copyright (c) 2025 IETF
Trust and the persons identified as the document authors" and is subject to
BCP 78 and the IETF Trust's Legal Provisions Relating to IETF Documents
(<https://trustee.ietf.org/license-info>).

The private keys are published examples, not secrets: every Appendix C.1 key
is derived from the seed `000102...1e1f`, and the Appendix C.4 keys are
deliberately malformed. Do not use any of them outside tests.

| File | Source |
| --- | --- |
| `ml-dsa-{44,65,87}-seed.der` | Appendix C.1.{1,2,3}.1, seed format |
| `ml-dsa-{44,65,87}-expanded.der` | Appendix C.1.{1,2,3}.2, expanded format |
| `ml-dsa-{44,65,87}-both.der` | Appendix C.1.{1,2,3}.3, both format |
| `ml-dsa-{44,65,87}-public-key.der` | Appendix C.2, `SubjectPublicKeyInfo` |
| `ml-dsa-44-inconsistent-{1,2,3}.der` | Appendix C.4, first to third example |

All private keys are PKCS #8 version 1 (`version` 0) without attributes or
public key. The public keys are identical to the copies in
`crates/browntls-pki/tests/data/rfc9881/`, which also holds the Appendix C.3
certificates.

The Appendix C.4 examples are ML-DSA-44 keys: the first is a `both` key whose
expanded key is not the one its seed derives; the second and third are
`expandedKey` keys that differ from the Appendix C.1 key in one byte, of `tr`
and of `t0` respectively.
