# CRLite test vectors

Synthetic CRLite filters for `tests/crlite_reference.rs`. No real certificate,
issuer, CT log or key is involved: issuer and log identifiers are a single
repeated byte and serial numbers are counters.

The files are output of Mozilla's reference implementation, the
[`clubcard`](https://github.com/mozilla/clubcard) 0.3.4 and
[`clubcard-crlite`](https://github.com/mozilla/clubcard-crlite) 0.6.2 crates
(both MPL-2.0), driven by a throwaway program outside this repository. None of
that code is included here. The reference builder draws random bits while it
solves, so rebuilding the same sets gives different, equally valid bytes.

| File | Contents |
| --- | --- |
| `full-v3.clubcard` | Full filter in encoding V3. |
| `full-v4.clubcard` | The same filter in encoding V4. |
| `delta-v4.clubcard` | Delta filter in encoding V4. |
| `expected.txt` | Queries and the reference implementation's answer for each. |

The full filter covers log `a1` for timestamps 1000 to 2000000 and log `b2`
for 0 to 500000, with five issuers:

| Issuer | Serials | Revoked | Encoding of the block |
| --- | --- | --- | --- |
| `11` | 120 | every 17th, offset 3 | plain, and serial `110003` is listed as an exception |
| `22` | 90 | all but every 5th | inverted |
| `33` | 40 | none | empty |
| `44` | 30 | all | empty and inverted |
| `55` | 60 | two thirds | plain with rank 0 |

The delta filter covers log `a1` as above and log `c3` for 2000001 to
3000000. It repeats issuer `11` with additional revocations (every 29th,
offset 7) and adds issuer `66` (50 serials, every 7th revoked).

Each line of `expected.txt` is one query:

```text
issuer serial log timestamp-ms full-status delta-status
```

`issuer` and `log` are the byte that is repeated 32 times, in hexadecimal.
`serial` is hexadecimal, or `-` for the empty serial. The two statuses are the
answers of the full filter (identical for both encodings) and of the delta
filter. The query key is derived as CRLite defines it: SHA-256 of the issuer
identifier followed by the serial.
