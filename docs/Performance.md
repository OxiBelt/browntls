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
commands, and prints the table below.

## Method

- Single thread, wall-clock time, about 2 s per row; the table averages two
  complete runs.
- AEADs: one seal per record with a fresh nonce, 13 bytes of AAD and a tag,
  at the record lengths of `openssl speed -aead` (2 to 16384 bytes).
- Hashes: one-shot digest per message (`openssl speed -evp`).
- X25519: one shared-secret derivation. Ed25519: 20-byte messages. ECDSA:
  pre-hashed digest with randomised (hedged) nonces. ECDH: one derivation.
  RSA: PKCS #1 v1.5 with SHA-256, CRT signing with blinding and a
  verify-before-release check.
- Machine: a shared cloud VM; the two runs differed by 5.6% per row (median)
  and by up to about 30% on a few rows, so differences below roughly 10%
  are not meaningful.

## Results (x86-64)

- CPU: Intel(R) Xeon(R) Processor @ 2.10GHz (x86_64), 4 logical CPUs
- OpenSSL: OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)
- rustc: rustc 1.99.1 (58cf8f9c3 2026-10-13)
- Measurement: single thread, wall clock, ~2 s per row

| Algorithm | Size / operation | browntls (accelerated) | browntls (portable) | OpenSSL | browntls / OpenSSL |
|---|---|---:|---:|---:|---:|
| AES-128-GCM | 2 B | 16 MB/s | 2 MB/s | 12 MB/s | 1.28× |
| AES-128-GCM | 31 B | 238 MB/s | 22 MB/s | 180 MB/s | 1.32× |
| AES-128-GCM | 136 B | 920 MB/s | 66 MB/s | 742 MB/s | 1.24× |
| AES-128-GCM | 1024 B | 4,460 MB/s | 112 MB/s | 3,838 MB/s | 1.16× |
| AES-128-GCM | 8192 B | 7,310 MB/s | 112 MB/s | 10,896 MB/s | 0.67× |
| AES-128-GCM | 16384 B | 7,302 MB/s | 112 MB/s | 11,724 MB/s | 0.62× |
| AES-256-GCM | 2 B | 14 MB/s | 2 MB/s | 12 MB/s | 1.17× |
| AES-256-GCM | 31 B | 217 MB/s | 17 MB/s | 167 MB/s | 1.30× |
| AES-256-GCM | 136 B | 779 MB/s | 52 MB/s | 701 MB/s | 1.11× |
| AES-256-GCM | 1024 B | 3,930 MB/s | 82 MB/s | 3,532 MB/s | 1.11× |
| AES-256-GCM | 8192 B | 5,960 MB/s | 88 MB/s | 9,702 MB/s | 0.61× |
| AES-256-GCM | 16384 B | 6,120 MB/s | 94 MB/s | 10,122 MB/s | 0.60× |
| ChaCha20-Poly1305 | 2 B | 6 MB/s | 6 MB/s | 3 MB/s | 1.83× |
| ChaCha20-Poly1305 | 31 B | 88 MB/s | 84 MB/s | 44 MB/s | 2.01× |
| ChaCha20-Poly1305 | 136 B | 256 MB/s | 210 MB/s | 169 MB/s | 1.52× |
| ChaCha20-Poly1305 | 1024 B | 1,368 MB/s | 418 MB/s | 1,111 MB/s | 1.23× |
| ChaCha20-Poly1305 | 8192 B | 2,344 MB/s | 447 MB/s | 2,639 MB/s | 0.89× |
| ChaCha20-Poly1305 | 16384 B | 2,678 MB/s | 448 MB/s | 2,800 MB/s | 0.96× |
| SHA-256 | 16 B | 223 MB/s | 56 MB/s | 112 MB/s | 2.00× |
| SHA-256 | 64 B | 636 MB/s | 131 MB/s | 338 MB/s | 1.88× |
| SHA-256 | 256 B | 1,084 MB/s | 204 MB/s | 930 MB/s | 1.17× |
| SHA-256 | 1024 B | 1,432 MB/s | 262 MB/s | 1,348 MB/s | 1.06× |
| SHA-256 | 8192 B | 1,573 MB/s | 258 MB/s | 1,456 MB/s | 1.08× |
| SHA-256 | 16384 B | 1,578 MB/s | 260 MB/s | 1,494 MB/s | 1.06× |
| SHA-512 | 16 B | 40 MB/s | 44 MB/s | 46 MB/s | 0.87× |
| SHA-512 | 64 B | 157 MB/s | 176 MB/s | 175 MB/s | 0.90× |
| SHA-512 | 256 B | 278 MB/s | 258 MB/s | 347 MB/s | 0.80× |
| SHA-512 | 1024 B | 392 MB/s | 354 MB/s | 544 MB/s | 0.72× |
| SHA-512 | 8192 B | 474 MB/s | 398 MB/s | 648 MB/s | 0.73× |
| SHA-512 | 16384 B | 458 MB/s | 422 MB/s | 639 MB/s | 0.72× |
| SHA3-256 | 16 B | 56 MB/s | 54 MB/s | 26 MB/s | 2.09× |
| SHA3-256 | 64 B | 174 MB/s | 166 MB/s | 124 MB/s | 1.40× |
| SHA3-256 | 256 B | 350 MB/s | 369 MB/s | 288 MB/s | 1.22× |
| SHA3-256 | 1024 B | 487 MB/s | 424 MB/s | 377 MB/s | 1.29× |
| SHA3-256 | 8192 B | 508 MB/s | 468 MB/s | 413 MB/s | 1.23× |
| SHA3-256 | 16384 B | 516 MB/s | 457 MB/s | 356 MB/s | 1.45× |
| X25519 | derive | 27,150/s | 27,781/s | 24,802/s | 1.09× |
| Ed25519 | sign | 66,267/s | 69,812/s | 22,872/s | 2.90× |
| Ed25519 | verify | 25,942/s | 26,960/s | 8,247/s | 3.15× |
| P-256 | sign | 20,488/s | 17,582/s | 41,418/s | 0.49× |
| P-256 | verify | 7,461/s | 6,394/s | 13,398/s | 0.56× |
| P-256 | ecdh | 7,934/s | 6,911/s | 17,256/s | 0.46× |
| P-384 | sign | 5,757/s | 5,746/s | 1,378/s | 4.18× |
| P-384 | verify | 1,907/s | 1,905/s | 1,618/s | 1.18× |
| P-384 | ecdh | 2,181/s | 2,272/s | 1,433/s | 1.52× |
| RSA-2048 | sign | 504/s | 370/s | 2,554/s | 0.20× |
| RSA-2048 | verify | 44,828/s | 23,402/s | 53,502/s | 0.84× |
| RSA-3072 | sign | 187/s | 112/s | 948/s | 0.20× |
| RSA-3072 | verify | 22,126/s | 9,880/s | 25,398/s | 0.87× |
| ML-KEM-768 | keygen | 80,250/s | 33,608/s | — | — |
| ML-KEM-768 | encaps | 84,874/s | 40,367/s | — | — |
| ML-KEM-768 | decaps | 51,902/s | 31,375/s | — | — |

Backends selected for the accelerated column:

- SHA-256: SHA-NI [uses dedicated] (policy: SIMD preferred, dedicated preferred; available: SIMD+dedicated)
- SHA-512: x86-64-v3 (AVX2+BMI2) [uses SIMD+dedicated] (policy: SIMD preferred, dedicated preferred; available: SIMD+dedicated)
- Keccak: BMI1/BMI2 [uses dedicated] (policy: SIMD preferred, dedicated preferred; available: dedicated)
- Keccak x4: AVX-512VL [uses SIMD] (policy: SIMD preferred, dedicated preferred; available: SIMD)
- AES: VAES (AVX2) [uses SIMD+dedicated] (policy: SIMD preferred, dedicated preferred; available: SIMD+dedicated)
- GHASH: PCLMULQDQ [uses dedicated] (policy: SIMD preferred, dedicated preferred; available: dedicated)
- ChaCha20: AVX-512 [uses SIMD] (policy: SIMD preferred, dedicated preferred; available: SIMD)
- Poly1305: AVX2 + BMI2/ADX [uses SIMD+dedicated] (policy: SIMD preferred, dedicated preferred; available: SIMD+dedicated)
- X25519: BMI2/ADX [uses dedicated] (policy: SIMD preferred, dedicated preferred; available: dedicated)
- P-256: BMI2/ADX [uses dedicated] (policy: SIMD preferred, dedicated preferred; available: dedicated)
- RSA: BMI2/ADX [uses dedicated] (policy: SIMD preferred, dedicated preferred; available: dedicated)
- ML-KEM: AVX2 [uses SIMD] (policy: SIMD preferred, dedicated preferred; available: SIMD)

## Observations

Evidence from the table above; explanations marked as such are inferences
from the implementations, not profiles.

- **Faster than OpenSSL 3.0.13 here**: AES-GCM and ChaCha20-Poly1305 records
  up to 1 KiB (1.1–2.0×), SHA-256 with SHA-NI (1.06–2.0×, most at short
  messages), SHA3-256 (1.2–2.1×), Ed25519 (about 3×) and P-384 (1.2–4.2×).
  Inference: OpenSSL 3.0 uses generic code for Ed25519 and P-384, and has
  higher per-call overhead for short inputs.
- **Comparable**: X25519 (1.09×), ChaCha20-Poly1305 bulk records (0.89–0.96×),
  RSA verification (0.84–0.87×).
- **Slower**:
  - AES-GCM records of 8–16 KiB (0.60–0.67×). Inference: OpenSSL uses
    AVX-512 VAES with VPCLMULQDQ in one fused pass; browntls uses 256-bit VAES
    for CTR and a separate 128-bit PCLMULQDQ GHASH pass.
  - SHA-512 (0.72–0.90×).
  - P-256 (0.46–0.56×). Inference: OpenSSL's dedicated P-256 assembly versus
    browntls's generic Montgomery code with Fermat inversion.
  - RSA signing (0.20×). Inference: OpenSSL 3.0 has an AVX-512 IFMA RSA path,
    and browntls unblinds with two Fermat exponentiations per signature.
- **Accelerated versus portable in browntls**: the SHA-512 x86-64-v3 backend
  is slower than the portable code for messages up to 64 bytes, and the
  X25519 BMI2/ADX ladder shows no gain over the portable code on this CPU.
  Ed25519 and P-384 have no accelerated backend; their two columns differ
  only by noise and by the SHA-512 backend.
- ML-KEM-768 has no OpenSSL 3.0 counterpart (OpenSSL added ML-KEM in 3.5).

## Improvement candidates

- AVX-512 VAES/VPCLMULQDQ AES-GCM with a fused CTR+GHASH loop (this CPU can
  now execute and test it).
- Specialised P-256 reduction and inversion; an AVX-512 IFMA path for RSA
  and P-256; cheaper RSA unblinding (cached blinding pairs).
- Faster SHA-512 for x86-64 and a length threshold below which the portable
  code is selected.
- Benchmark-driven backend preference, so a backend that is slower on a CPU
  is not selected by default.
