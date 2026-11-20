# Entropy checks

`browntls-entropy` is test tooling (not published) that looks for a class of
bug that ordinary tests miss: secret material that is generated with far less
entropy than its length suggests. Typical causes are a random buffer that is
only partly filled, a short read that is not retried, a key derived from a
counter or a timestamp, bits forced to a constant, a cached value returned
twice, or a seed truncated somewhere on the way to the key.

Each test draws millions of values from one public generator of
`browntls-crypto` or `browntls-core`, keeps only the bits that the specification
leaves free (clamped and range-limited bits are masked out), and runs the
checks below on every resulting stream.
[`entropy.yml`](../../.github/workflows/entropy.yml) runs every topic as its own
job on one x86-64 runner (`ubuntu-26.04`). `browntls-crypto` issues the
`getrandom(2)` system call with separate inline assembly on each architecture;
the aarch64 and riscv64 paths are checked only at smoke size, by
`cargo test --workspace` in the native aarch64 and riscv64 jobs of the
[Rust workflow](../../.github/workflows/rust.yml).

## Checks and thresholds

Every check computes a statistic whose distribution is known for an ideal
generator and fails when the observed value would occur with probability
below `ALPHA = 1e-9`, after a Bonferroni correction over the tests inside the
check (for example over the 256 bits of a 32-byte key). Thresholds are
therefore derived from the sample count rather than fixed, and a full CI run,
which evaluates a few hundred (stream, check) pairs, fails spuriously about
once in a million runs. Each threshold is printed next to the observed value,
and the GitHub job summary has a table per topic.

| Check | Statistic and threshold | Catches |
| --- | --- | --- |
| duplicates | Equal samples after sorting; any duplicate fails when the free bits make one implausible (expected count below 2^-30) | Entropy below about `2 log2(N)` bits per value (44 bits at `N = 2^22`), cached or replayed keys |
| bit frequency | `z = (2 ones - N) / sqrt(N)` per free bit, two-sided | Stuck, unfilled or biased bits |
| byte distribution | Chi-square (255 degrees of freedom, Wilson–Hilferty) and the largest count per byte position (Poisson upper tail, which bounds the binomial one; a normal approximation fails ideal generators far more often than `ALPHA` when samples are few) | Biased byte values. The two limits are reported as floors on the **Shannon entropy** and the **min-entropy** per byte; at `N = 2^22` they are about 7.99993 and 7.92 bits |
| window collisions | Collisions of 16- to 32-bit windows of free bits across samples against a Poisson law, both tails; reported as the **collision entropy** (Rényi order 2) per window | Values drawn from a small set, low entropy confined to part of a value, counters |
| window repeats | Equal windows inside one sample (Poisson, upper tail) | Halves or blocks copied within a value |
| byte lags | Equal bytes at distance 1 to 16 within a sample (normal approximation over pairwise independent indicators) | Periodic or repeated byte patterns |
| consecutive distance | Mean Hamming distance between consecutive samples | Slowly changing state, near-duplicates, counters |

The detectors are tested themselves (`src/tests.rs`): deterministic ideal
input must pass, and each known-bad generator (a stuck bit, an unfilled tail,
a biased byte, a 20-bit seed, words drawn from 2^12 values, a copied half or
block, a byte period, state that changes one byte per draw, a counter) must
fail the intended check. CI runs these first on every runner.

## Topics

| Test | Generators | Streams | CI samples (x86-64) |
| --- | --- | --- | --- |
| `os_rng` | `OsRng` (32-byte, one-byte and odd-length fills, both ends of 64 KiB fills), the native and RustCrypto providers' `secure_random` | raw output | 2^22 (64 KiB fills: 2^16) |
| `curve25519` | X25519 `PrivateKey::generate`, Ed25519 `SigningKey::generate` | private keys and seeds, public keys | 2^22 |
| `curve448` | X448 and Ed448 key generation | private keys and seeds, public keys | 2^21 |
| `nist` | P-256, P-384, P-521 `SecretKey::generate` | private scalars, public `x \|\| y` | 2^22, 2^21, 2^20 |
| `mlkem` | ML-KEM-512, -768, -1024 `generate` and `encapsulate` | seed `d \|\| z`, `rho`, encapsulated shared secret | 2^22 |
| `hpke` | `generate_key_pair` and `setup_sealer` of every native DHKEM | private keys, `enc`, a sealed zero block | 2^19 to 2^22 |
| `ffdhe` | ffdhe2048 and ffdhe3072 `PrivateKey::generate` | public values (the exponent is not exportable) | 2^20, 2^18 |
| `rsa` | RSA-2048 `RsaPrivateKey::generate` | primes `p \|\| q`; no prime may repeat across the run | 2^13 keys |
| `tls_kx` | `start`, `start_and_complete` and `complete` of every native key-exchange group up to FFDHE3072 | client share, server share, shared secret | 2^18 to 2^22 (FFDHE: 2^17, 2^15) |
| `tls_ticketer` | `AeadTicketProducer` of both providers | nonces under one key; nonce, keystream and tag of a fresh key per sample (and fresh keys must not open each other's tickets) | 2^22 |
| `tls_handshake` | full in-memory TLS 1.3 and TLS 1.2 handshakes, native client and server, default configuration | both `random`s, session IDs, key shares, every TLS 1.3 traffic and exporter secret, the TLS 1.2 master secret | 2^20 handshakes per version |

## Running locally

```sh
cargo test -p browntls-entropy --lib                       # detector self-tests
cargo test -p browntls-entropy                             # every topic, smoke size
BROWNTLS_ENTROPY_SAMPLES=4194304 \
  cargo test -p browntls-entropy --test nist -- --nocapture --test-threads=1
```

`BROWNTLS_ENTROPY_SAMPLES` sets the base sample count (default 2^14, so the
workspace test run stays fast); costly generators divide it, with a minimum
per test. `BROWNTLS_ENTROPY_THREADS` overrides the number of worker threads.
At 2^22 samples a topic needs up to a few GiB of memory, since every sample is
kept for the duplicate and window checks.

## Limits

Statistical tests bound only visible structure. A generator that expands a
64-bit seed through a hash or a block cipher passes every check here at any
feasible sample count; the duplicate check only proves more than about
`2 log2(N)` bits. Likewise these checks say nothing about whether the
operating system's entropy pool was seeded. They complement, and do not
replace, review of how each generator obtains its randomness. Values that are
not uniform by design (ML-KEM coefficient encodings and ciphertexts, the
exponent inside FFDHE) are examined only through derived values that are.
