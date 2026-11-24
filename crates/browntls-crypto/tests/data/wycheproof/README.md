# Wycheproof test vectors

Test vectors from Project Wycheproof, used by the known-answer tests of this
crate.

## ML-DSA

The `mldsa_*` files are unmodified copies of the files of the same name in
`testvectors_v1/` of the upstream repository:

- Upstream repository: <https://github.com/C2SP/wycheproof>
- Commit: `65ca494727a52944c204441c860b039e6786b99b`
- Files: `mldsa_{44,65,87}_verify_test.json`,
  `mldsa_{44,65,87}_sign_seed_test.json` and
  `mldsa_{44,65,87}_sign_noseed_test.json`.
- Licence: Apache License 2.0 (the upstream `LICENSE` at that commit).

They are used by `src/mldsa/kat_tests.rs`.

## Other files

The other files in this directory were added before this note was written,
and their upstream commit was not recorded. They come from the same
upstream project.
