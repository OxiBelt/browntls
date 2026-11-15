# Performance

Throughput of `browntls-crypto` compared with OpenSSL on one machine. These
numbers describe this CPU, this OpenSSL build and this revision only; they are
not a general ranking. Reproduce with:

```sh
python3 -B scripts/bench-vs-openssl.py --seconds 2
```

The script builds `crates/browntls-crypto/examples/speed.rs` in release mode
for x86-64-v3, runs it with the default acceleration policy and with portable
code only (`accel::Policy::NONE`), runs the matching `openssl speed -elapsed`
commands, and prints the table below. For focused A/B comparisons of two
builds, run their `speed` binaries alternately with `--only <names>`.

## Method

- Single thread, wall-clock time, about 2 s per row; the table averages two
  complete runs.
- AEADs: one seal per record with a fresh nonce, 13 bytes of AAD and a tag,
  at the record lengths of `openssl speed -aead` (2 to 16384 bytes).
- Hashes: one-shot digest per message (`openssl speed -evp`).
- X25519 and X448: one shared-secret derivation (X448 also one public key).
  Ed25519 and Ed448: 20-byte messages. ECDSA:
  pre-hashed digest with randomised (hedged) nonces. ECDH: one derivation.
  RSA: PKCS #1 v1.5 with SHA-256, CRT signing with blinding and a
  verify-before-release check.
- Machine: a cloud VM, otherwise idle during the runs (load average about
  1); the two runs differed by 5.1% per row (median), 12.8% at the 90th
  percentile and 21% at most, so differences below roughly 10% are not
  meaningful.
- The X448, Ed448, P-384 and P-521 rows were measured for the revision that
  added their fast paths, with the `speed` binary and `openssl speed` run
  three times at about 1 s (browntls) and 2 s (OpenSSL) per row; they show
  the medians. The other rows are from the two complete runs above.

## Results (x86-64)

- CPU: Intel(R) Xeon(R) Processor @ 2.10GHz (x86_64), 4 logical CPUs, with
  AVX-512 (F/DQ/BW/VL/IFMA/VBMI), VAES, VPCLMULQDQ, SHA-NI, BMI2 and ADX
- OpenSSL: OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)
- rustc: rustc 1.99.1 (58cf8f9c3 2026-10-13)
- Measurement: single thread, wall clock, ~2 s per row

| Algorithm | Size / operation | browntls (accelerated) | browntls (portable) | OpenSSL | browntls / OpenSSL |
|---|---|---:|---:|---:|---:|
| AES-128-GCM | 2 B | 46 MB/s | 2 MB/s | 12 MB/s | 3.72× |
| AES-128-GCM | 31 B | 748 MB/s | 22 MB/s | 172 MB/s | 4.35× |
| AES-128-GCM | 136 B | 2,553 MB/s | 65 MB/s | 768 MB/s | 3.33× |
| AES-128-GCM | 1024 B | 9,360 MB/s | 114 MB/s | 4,002 MB/s | 2.34× |
| AES-128-GCM | 8192 B | 12,485 MB/s | 116 MB/s | 10,007 MB/s | 1.25× |
| AES-128-GCM | 16384 B | 12,149 MB/s | 121 MB/s | 12,571 MB/s | 0.97× |
| AES-256-GCM | 2 B | 42 MB/s | 2 MB/s | 12 MB/s | 3.54× |
| AES-256-GCM | 31 B | 688 MB/s | 17 MB/s | 182 MB/s | 3.77× |
| AES-256-GCM | 136 B | 2,378 MB/s | 54 MB/s | 812 MB/s | 2.93× |
| AES-256-GCM | 1024 B | 7,934 MB/s | 87 MB/s | 3,842 MB/s | 2.06× |
| AES-256-GCM | 8192 B | 10,924 MB/s | 96 MB/s | 9,764 MB/s | 1.12× |
| AES-256-GCM | 16384 B | 11,202 MB/s | 93 MB/s | 10,540 MB/s | 1.06× |
| ChaCha20-Poly1305 | 2 B | 6 MB/s | 6 MB/s | 3 MB/s | 2.00× |
| ChaCha20-Poly1305 | 31 B | 84 MB/s | 92 MB/s | 42 MB/s | 2.00× |
| ChaCha20-Poly1305 | 136 B | 281 MB/s | 241 MB/s | 174 MB/s | 1.61× |
| ChaCha20-Poly1305 | 1024 B | 1,575 MB/s | 440 MB/s | 1,164 MB/s | 1.35× |
| ChaCha20-Poly1305 | 8192 B | 2,426 MB/s | 457 MB/s | 2,725 MB/s | 0.89× |
| ChaCha20-Poly1305 | 16384 B | 2,550 MB/s | 440 MB/s | 2,914 MB/s | 0.87× |
| SHA-256 | 16 B | 216 MB/s | 55 MB/s | 116 MB/s | 1.85× |
| SHA-256 | 64 B | 626 MB/s | 120 MB/s | 404 MB/s | 1.55× |
| SHA-256 | 256 B | 1,131 MB/s | 206 MB/s | 865 MB/s | 1.31× |
| SHA-256 | 1024 B | 1,408 MB/s | 252 MB/s | 1,292 MB/s | 1.09× |
| SHA-256 | 8192 B | 1,498 MB/s | 264 MB/s | 1,578 MB/s | 0.95× |
| SHA-256 | 16384 B | 1,546 MB/s | 260 MB/s | 1,552 MB/s | 1.00× |
| SHA-512 | 16 B | 44 MB/s | 49 MB/s | 45 MB/s | 0.99× |
| SHA-512 | 64 B | 181 MB/s | 193 MB/s | 188 MB/s | 0.96× |
| SHA-512 | 256 B | 250 MB/s | 250 MB/s | 353 MB/s | 0.71× |
| SHA-512 | 1024 B | 374 MB/s | 354 MB/s | 522 MB/s | 0.72× |
| SHA-512 | 8192 B | 428 MB/s | 387 MB/s | 626 MB/s | 0.68× |
| SHA-512 | 16384 B | 476 MB/s | 379 MB/s | 676 MB/s | 0.71× |
| SHA3-256 | 16 B | 50 MB/s | 56 MB/s | 34 MB/s | 1.47× |
| SHA3-256 | 64 B | 166 MB/s | 177 MB/s | 136 MB/s | 1.22× |
| SHA3-256 | 256 B | 347 MB/s | 359 MB/s | 340 MB/s | 1.02× |
| SHA3-256 | 1024 B | 467 MB/s | 442 MB/s | 391 MB/s | 1.19× |
| SHA3-256 | 8192 B | 510 MB/s | 496 MB/s | 400 MB/s | 1.27× |
| SHA3-256 | 16384 B | 486 MB/s | 504 MB/s | 414 MB/s | 1.18× |
| X25519 | derive | 27,204/s | 27,472/s | 28,587/s | 0.95× |
| Ed25519 | sign | 73,706/s | 69,480/s | 24,551/s | 3.00× |
| Ed25519 | verify | 26,524/s | 27,194/s | 8,978/s | 2.95× |
| X448 | keygen | 18,211/s | 18,352/s | — | — |
| X448 | derive | 6,605/s | 7,306/s | 5,648/s | 1.17× |
| Ed448 | sign | 17,077/s | 17,849/s | 5,545/s | 3.08× |
| Ed448 | verify | 6,598/s | 6,135/s | 5,164/s | 1.28× |
| P-256 | sign | 52,902/s | 35,270/s | 42,682/s | 1.24× |
| P-256 | verify | 16,626/s | 11,285/s | 13,656/s | 1.22× |
| P-256 | ecdh | 15,309/s | 10,640/s | 17,458/s | 0.88× |
| P-384 | sign | 11,259/s | 9,436/s | 1,362/s | 8.27× |
| P-384 | verify | 4,054/s | 3,084/s | 1,534/s | 2.64× |
| P-384 | ecdh | 3,935/s | 3,065/s | 1,431/s | 2.75× |
| P-521 | sign | 7,352/s | 6,188/s | 3,976/s | 1.85× |
| P-521 | verify | 2,594/s | 2,106/s | 2,070/s | 1.25× |
| P-521 | ecdh | 2,397/s | 1,995/s | 3,344/s | 0.72× |
| RSA-2048 | sign | 2,468/s | 794/s | 3,094/s | 0.80× |
| RSA-2048 | verify | 79,754/s | 28,810/s | 55,100/s | 1.45× |
| RSA-3072 | sign | 956/s | 266/s | 972/s | 0.98× |
| RSA-3072 | verify | 44,322/s | 13,630/s | 25,845/s | 1.71× |
| ML-KEM-768 | keygen | 84,148/s | 34,714/s | — | — |
| ML-KEM-768 | encaps | 99,750/s | 40,008/s | — | — |
| ML-KEM-768 | decaps | 58,558/s | 32,772/s | — | — |

Backends selected for the accelerated column:

- SHA-256: SHA-NI [uses dedicated] (policy: SIMD preferred, dedicated preferred; available: SIMD+dedicated)
- SHA-512: x86-64-v3 (AVX2+BMI2) [uses SIMD+dedicated] (policy: SIMD preferred, dedicated preferred; available: SIMD+dedicated)
- Keccak: BMI1/BMI2 [uses dedicated] (policy: SIMD preferred, dedicated preferred; available: dedicated)
- Keccak x4: AVX-512VL [uses SIMD] (policy: SIMD preferred, dedicated preferred; available: SIMD)
- AES: VAES (AVX-512) [uses SIMD+dedicated] (policy: SIMD preferred, dedicated preferred; available: SIMD+dedicated)
- GHASH: VPCLMULQDQ (AVX-512) [uses SIMD+dedicated] (policy: SIMD preferred, dedicated preferred; available: SIMD+dedicated)
- ChaCha20: AVX-512 [uses SIMD] (policy: SIMD preferred, dedicated preferred; available: SIMD)
- Poly1305: AVX2 + BMI2/ADX [uses SIMD+dedicated] (policy: SIMD preferred, dedicated preferred; available: SIMD+dedicated)
- X25519: BMI2/ADX [uses dedicated] (policy: SIMD preferred, dedicated preferred; available: dedicated)
- P-256: BMI2/ADX [uses dedicated] (policy: SIMD preferred, dedicated preferred; available: dedicated)
- RSA: AVX-512 IFMA + BMI2/ADX [uses SIMD+dedicated] (policy: SIMD preferred, dedicated preferred; available: SIMD+dedicated)
- ML-KEM: AVX2 [uses SIMD] (policy: SIMD preferred, dedicated preferred; available: SIMD)
- P-384: BMI2/ADX [uses dedicated] (policy: SIMD preferred, dedicated preferred; available: dedicated)
- P-521: BMI2/ADX [uses dedicated] (policy: SIMD preferred, dedicated preferred; available: dedicated)

## Observations

Evidence from the table above; explanations marked as such are inferences
from the implementations, not profiles.

- **Faster than OpenSSL 3.0.13 here**: AES-GCM records up to 8 KiB
  (1.1–4.4×), ChaCha20-Poly1305 records up to 1 KiB (1.35–2.0×), SHA-256
  up to 1 KiB (1.1–1.85×), SHA3-256 (1.0–1.5×), Ed25519 (about 3×), P-256
  signing and verification (1.2×), P-384 (2.6–8.3×), P-521 signing and
  verification (1.25–1.85×), Ed448 (1.3–3.1×), X448 (1.17×) and RSA
  verification (1.45–1.7×). Inference: OpenSSL 3.0 uses generic code for
  Ed25519 and P-384, and has higher per-call overhead for short inputs.
- **Comparable**: AES-GCM at 16 KiB (0.97–1.06×), SHA-256 at 8–16 KiB,
  SHA-512 up to 64 bytes, X25519 (0.95×), RSA-3072 signing (0.98×).
- **Slower**:
  - SHA-512 from 256 bytes (0.68–0.72×). Inference: OpenSSL's AVX2/RORX
    assembly interleaves the message schedule with the rounds; browntls
    computes the schedule for two blocks with AVX2 and runs the rounds in
    Rust. Unrolling the rounds and reusing `a ^ b` for `Maj` measured no
    gain, so the remaining step is hand-scheduled assembly.
  - RSA-2048 signing (0.80×), P-256 ECDH (0.88×) and P-521 ECDH (0.72×).
    Inference for P-521 (not profiled): OpenSSL's 64-bit `nistp521` code
    keeps unreduced 58-bit limbs across several additions, while browntls
    reduces fully after every field operation and forms the product and
    its reduction in two steps through memory.
  - ChaCha20-Poly1305 records of 8–16 KiB (0.87–0.89×).
- **Accelerated versus portable in browntls**: no accelerated backend is
  slower than the portable code beyond the noise level. Some show no gain
  here: X25519 with BMI2/ADX (0.99×), the BMI1/BMI2 Keccak behind SHA3-256,
  and ChaCha20-Poly1305 records below 136 bytes; short SHA-512 messages take
  the portable compression on purpose. Ed25519, X448 and Ed448 have no
  accelerated backend; their two columns differ only by noise and by the
  SHA-512 and SHAKE backends. The BMI2/ADX kernels of P-384 and P-521 gain
  1.2–1.3× over their portable code.
- ML-KEM-768 has no OpenSSL 3.0 counterpart (OpenSSL added ML-KEM in 3.5).

## Changes in this revision

Interleaved A/B runs of the `speed` example (medians of three runs of about
1 s per row, x86-64-v3 build) against the preceding revision, on the same
machine, with the default policy and with portable code only:

| Change | Row | Before | After | Ratio | Portable before | Portable after | Ratio |
|---|---|---:|---:|---:|---:|---:|---:|
| P-521: fold-and-rotate reduction for the Mersenne prime, add-one-and-test addition, safegcd inversions, BMI2/ADX kernels | P-521 sign | 2,564/s | 7,352/s | 2.87× | 2,521/s | 6,188/s | 2.45× |
| | P-521 verify | 1,069/s | 2,594/s | 2.43× | 1,129/s | 2,106/s | 1.87× |
| | P-521 ECDH | 1,057/s | 2,397/s | 2.27× | 1,104/s | 1,995/s | 1.81× |
| P-384: Montgomery rounds specialised to the prime, safegcd inversions, BMI2/ADX kernels | P-384 sign | 6,132/s | 11,259/s | 1.84× | 6,239/s | 9,436/s | 1.51× |
| | P-384 verify | 2,949/s | 4,054/s | 1.37× | 2,958/s | 3,084/s | 1.04× |
| | P-384 ECDH | 2,898/s | 3,935/s | 1.36× | 2,858/s | 3,065/s | 1.07× |
| Curve448: Karatsuba field multiplication | X448 derive | 5,222/s | 6,605/s | 1.26× | 5,250/s | 7,306/s | 1.39× |
| Ed448: fixed-base comb for `[k]B`, width-8 NAF table for B in verification (plus the field change) | Ed448 sign | 4,281/s | 17,077/s | 3.99× | 4,172/s | 17,849/s | 4.28× |
| | Ed448 verify | 4,004/s | 6,598/s | 1.65× | 4,036/s | 6,135/s | 1.52× |
| X448 public keys through the Ed448 comb and the 4-isogeny | X448 keygen | 5,115/s | 18,211/s | 3.56× | 4,640/s | 18,352/s | 3.96× |

The curve448 code has no accelerated backend, so its two pairs of columns
measure the same code and differ by noise (and, for Ed448, by the SHAKE
backend). The portable P-384 gain is small outside signing: its six
reduction rounds form one dependency chain, which the assembly version
shortens. No BMI2/ADX backend was added for curve448: its reduced-radix
(56-bit limb) arithmetic has no carry chains, and the equivalent radix-2^64
X25519 ladder measures no faster than the portable one on this CPU.

## Changes in earlier revisions

Interleaved A/B runs of the `speed` example (medians of three, x86-64-v3
build) against the revision before each change, on the same machine:

| Change | Row | Before | After | Ratio |
|---|---|---:|---:|---:|
| SHA-512: no two-lane schedule for a lone block | SHA-512, 64 B | 156 MB/s | 181 MB/s | 1.16× |
| AES-GCM: AVX-512 VAES + VPCLMULQDQ with a fused CTR+GHASH loop | AES-128-GCM, 2 B | 15 MB/s | 50 MB/s | 3.31× |
| | AES-128-GCM, 16 KiB | 6,847 MB/s | 11,747 MB/s | 1.72× |
| | AES-256-GCM, 16 KiB | 6,468 MB/s | 10,817 MB/s | 1.67× |
| P-256: specialised BMI2/ADX and portable field arithmetic, safegcd inversion, Jacobian verification and ladder doubling, width-6 comb | P-256 sign | 20,685/s | 50,787/s | 2.46× |
| | P-256 verify | 6,722/s | 18,847/s | 2.80× |
| | P-256 ECDH | 7,934/s | 16,048/s | 2.02× |
| | P-384 verify | 1,964/s | 3,013/s | 1.53× |
| RSA: safegcd unblinding, fused Montgomery kernels, AVX-512 IFMA CRT exponentiation | RSA-2048 sign | 542/s | 2,492/s | 4.60× |
| | RSA-2048 verify | 45,173/s | 81,763/s | 1.81× |
| | RSA-3072 sign | 184/s | 956/s | 5.19× |
| | RSA-3072 verify | 21,322/s | 44,717/s | 2.10× |

The portable P-256 path gained 1.6–2.0× and portable RSA signing 2.3–2.4×.
Loading P-256's `p[3]` from an immediate instead of a static (so the crate
links into shared objects) cost at most a few percent in A/B runs.

## Improvement candidates

- SHA-512 rounds in hand-scheduled x86-64 assembly with the schedule
  interleaved.
- P-256 ECDH: the variable-base ladder still uses complete additions for
  every digit; RSA-2048 signing: further IFMA tuning (the dual-CRT
  variant choice was tuned on this CPU only).
- ChaCha20-Poly1305 bulk records (Poly1305 with AVX-512 IFMA or a wider
  vector hash).
- P-521 ECDH (0.72× OpenSSL): fuse the product and its reduction in one
  assembly block, and delay reductions across additions in the point
  formulas. P-384: a reduction with a shorter dependency chain for the
  portable code.
- X448: a vectorised ladder (AVX2 with four 2^28-radix lanes, or AVX-512
  IFMA) is the remaining route to an accelerated backend; aarch64 and
  riscv64 kernels for the NIST curves (`umulh`/`adcs`, `mulhu`) would need
  measurements on real hardware.
- X25519: the BMI2/ADX ladder shows no gain over the portable code here;
  an AVX-512 IFMA field or a preference change would need measurements on
  more CPUs.
