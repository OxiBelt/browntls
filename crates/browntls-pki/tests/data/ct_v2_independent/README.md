# Independently generated Certificate Transparency 2.0 fixtures

These synthetic vectors exercise browntls's public PKI verifier against
artifacts produced by [generate.py](generate.py). The producer uses Python's
standard library for the RFC 9162 encodings and SHA-256 Merkle tree, and
OpenSSL for X.509 issuance and log signatures. It verifies each log signature
with OpenSSL and checks the issued certificate's chain, name, and server usage
at the fixed test time. Generation was checked with Python 3.14.4 and
OpenSSL 3.5.5.

The hierarchy is a synthetic Ed25519 issuer and a leaf for
`ct-fixture.example`. A fixed serial, key, validity window, and extension
order let OpenSSL produce the precertificate's TBS before adding the
Transparency Information extension to the final certificate. The two test
log IDs end in `.1` and `.2` under the RFC 5612 example enterprise OID
`1.3.6.1.4.1.32473`. They are paired with ephemeral P-256 and Ed25519 keys,
respectively. All four private keys are generated inside a temporary
directory that the producer removes before writing the public files.

The logical clock starts at 2024-06-01T00:00:00Z. The precertificate SCT
uses that time, the X.509 SCTs use two seconds later, and the three- and
five-leaf tree heads use three and four seconds later, respectively. Both
logs sign heads over the same synthetic leaves. The X.509 entry and its
precertificate occupy indices 2 and 4 in the five-leaf tree. The five-leaf
head extends the three-leaf prefix.

## Expected results

- `leaf.der` contains one valid embedded Ed25519 precertificate SCT.
  `tls-list.bin` supplies one valid P-256 X.509 SCT and its inclusion
  evidence at index 2. `ocsp-list.bin` supplies one valid Ed25519 X.509
  SCT, a duplicate of the embedded precertificate SCT, and inclusion
  evidence at index 4 for that precertificate.
- The OCSP vector represents the extracted Transparency Information list
  passed to the PKI API after OCSP authentication. Coverage of this vector
  is at the CT API boundary. It supplies no signed OCSP response.
- The auditor APIs accept the SCT signatures, both algorithms' heads and
  proofs, the leaf hashes in `*-leaf-hash.bin`, and the roots in
  `root-3.bin` and `root-5.bin`. The signed
  `ed25519-stale-head.bin` has the correct five-leaf root but predates
  the precertificate SCT by one millisecond, so it supplies no acceptable
  inclusion evidence for it.
- The Rust test also checks signature and proof rejection, malformed and
  duplicate items, proof length limits, aggregate work limits, log
  validity windows, and future SCT timestamps.

See [RFC 9162 §2.1](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1)
for tree construction and proof paths,
[§§4.5–4.12](https://www.rfc-editor.org/rfc/rfc9162.html#section-4.5)
for signed artifacts, and
[§7.1](https://www.rfc-editor.org/rfc/rfc9162.html#section-7.1)
for the X.509 and OCSP extension. These vectors provide independent
fixture evidence. Public CT 2.0 log interoperability remains unverified.

## Verify or regenerate

From the repository root, verify the checked-in artifacts and run the
[standalone integration test](../../transparency_independent.rs).

```sh
fixture_dir=crates/browntls-pki/tests/data/ct_v2_independent
(cd "$fixture_dir" && sha256sum -c SHA256SUMS)
cargo test -p browntls-pki --locked --test transparency_independent
```

Generate a fresh set in a temporary directory to inspect it separately.

```sh
fixture_dir=crates/browntls-pki/tests/data/ct_v2_independent
output_dir=$(mktemp -d)
python3 -B "$fixture_dir/generate.py" "$output_dir"
(cd "$output_dir" && sha256sum -c SHA256SUMS)
```

Fresh keys and ECDSA randomness change the bytes, roots, and checksums
while the timestamps, tree topology, and expected verdicts stay fixed.
To refresh the checked-in set, pass `"$fixture_dir"` as the output directory
and rerun the standalone test. Review the public artifacts and manifest
together. Cargo tests read the checked-in files and require no OpenSSL
installation or network access.
