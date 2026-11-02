# Test certificates and CRLs

Public test vectors used by the `browntls-pki` integration tests. Nothing in
this directory is a private key; the tests that need signing keys generate
them at run time with `rcgen`.

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
| `signatures/` | key/signature vectors and certificates with unusual algorithm identifiers |
| `cert_v1.der`, `cert_with*_extensions.der` | version and extension-list edge cases |

The public certificates under `netflix/`, `sanofi/` and `cloudflare_dns/`
were issued to their respective owners and are included, as upstream does,
only as interoperability samples.
