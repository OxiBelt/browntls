# Test certificates and CRLs

Public test vectors used by the `browntls-pki` integration tests. Nothing in
this directory is a private key; the tests that need signing keys generate
them at run time with `rcgen` or, for ML-DSA, from fixed seeds with the
`ml-dsa` crate.

## `webpki/`

A curated subset of the `tests/` directory of
[rustls/webpki](https://github.com/rustls/webpki), copied from commit
`4657021e5bd53b4393a3050cde52609b43b63f31` of the `main` branch. The files
are redistributed under that project's ISC-style licence:

> Copyright 2015 Brian Smith.
> Copyright 2023-2026 The rustls-webpki authors.
>
> Permission to use, copy, modify, and/or distribute this software for any
> purpose with or without fee is hereby granted, provided that the above
> copyright notice and this permission notice appear in all copies.
>
> THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
> WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
> MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
> ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
> WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
> ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
> OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

Only DER files, signature vectors and the message they sign were copied; the
generator scripts and annotation files were not. Directory names match the
upstream layout:

| Directory | Contents |
| --- | --- |
| `misc/` | serial-number edge cases, SAN edge cases, unique identifiers, custom EKU chain |
| `critical_extensions/` | a chain whose end entity carries an unknown extension, critical or not |
| `custom_ekus/` | end entities with no EKU or with both TLS EKUs |
| `crls/` | well-formed and deliberately malformed CRLs |
| `crl_distrib_point/` | certificates with unusual `cRLDistributionPoints` |
| `client_auth_revocation/` | chains and CRLs with distribution point variants |
| `ed25519/`, `wpt/`, `netflix/`, `sanofi/`, `cloudflare_dns/` | real or generated chains |
| `signatures/` | key and signature vectors for ECDSA with non-default hashes, plus an RSA certificate |
| `cert_v1.der`, `cert_with*_extensions.der` | version and extension-list edge cases |

The public certificates under `netflix/`, `sanofi/` and `cloudflare_dns/`
were issued to their respective owners and are included, as upstream does,
only as interoperability samples.

## `rfc9881/`

The example ML-DSA public keys and certificates of
[RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html) ("Internet X.509
Public Key Infrastructure -- Algorithm Identifiers for the Module-Lattice-Based
Digital Signature Algorithm (ML-DSA)"), Appendix C.2 (public keys) and
Appendix C.3 (certificates). They are specification examples, stored as the
DER that the RFC prints in the textual encoding of RFC 7468 (the Base64
lines decoded, nothing else changed). The RFC text is
"Copyright (c) 2025 IETF Trust and the persons identified as the document
authors" and is subject to BCP 78 and the IETF Trust's Legal Provisions
Relating to IETF Documents (<https://trustee.ietf.org/license-info>).

| File | Source |
| --- | --- |
| `ml-dsa-{44,65,87}-public-key.der` | Appendix C.2, `SubjectPublicKeyInfo` |
| `ml-dsa-{44,65,87}-certificate.der` | Appendix C.3, self-signed CA |

The certificates are self-signed v3 CA certificates for
"O=IETF, CN=LAMPS WG", valid from 2020-02-03T04:32:10Z to
2040-01-29T04:32:10Z, with critical `keyUsage` (digitalSignature,
keyCertSign, cRLSign), critical `basicConstraints` (cA TRUE) and a subject
key identifier. The Appendix C.1 private keys (seeds and expanded keys) were
deliberately not copied.
