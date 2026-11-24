# NIST ACVP ML-DSA vectors

These files are trimmed copies of the ML-DSA test vectors of the NIST
Automated Cryptographic Validation Protocol server, used by the known-answer
tests in `src/mldsa/kat_tests.rs`.

- Upstream repository: <https://github.com/usnistgov/ACVP-Server>
- Commit: `975de31eb83d87039ec88934fdc47d8c312b892d`
- Source files (each `internalProjection.json`, which holds the prompts
  together with the expected results):
  - `gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json`
  - `gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json`
  - `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json`
- Local files: `ML-DSA-keyGen-FIPS204.json`, `ML-DSA-sigGen-FIPS204.json`,
  `ML-DSA-sigVer-FIPS204.json`.

## Trimming

The files were modified (November 2026) to keep the repository small. The
JSON structure, field names and values are unchanged; only groups, cases and
fields were removed:

- Every `preHash` group (HashML-DSA, which browntls does not implement) is
  dropped from `sigGen` and `sigVer`. All other groups are kept, including
  the `internal` and `externalMu` ones.
- `keyGen`: unchanged apart from formatting (all 75 cases).
- `sigGen`: the first two cases of each group; the `pk` field is removed
  (signing uses `sk`, and the tests derive the public key from it).
- `sigVer`: the first case of each distinct `reason` in each group (one valid
  signature, a modified message, and modified commitment, `z` and hint); the
  `sk` field is removed (verification does not use it).

The trimmed files are reproduced exactly with Python 3, given the directory
holding the three upstream files saved as
`ML-DSA-{keyGen,sigGen,sigVer}-FIPS204.internalProjection.json`:

```python
import json, pathlib, sys

src, dst = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
for mode in ("keyGen", "sigGen", "sigVer"):
    name = f"ML-DSA-{mode}-FIPS204"
    data = json.loads((src / f"{name}.internalProjection.json").read_text())
    groups = []
    for group in data["testGroups"]:
        if group.get("preHash") == "preHash":
            continue  # HashML-DSA is not implemented.
        tests = group["tests"]
        if mode == "sigGen":
            # The first two cases of each group, without the public key.
            tests = [{k: v for k, v in t.items() if k != "pk"} for t in tests[:2]]
        elif mode == "sigVer":
            # The first case of each "reason", without the private key.
            seen = set()
            kept = []
            for t in tests:
                if t["reason"] not in seen:
                    seen.add(t["reason"])
                    kept.append({k: v for k, v in t.items() if k != "sk"})
            tests = kept
        groups.append(dict(group, tests=tests))
    data["testGroups"] = groups
    (dst / f"{name}.json").write_text(json.dumps(data, indent=1) + "\n")
```

## Licence

The upstream repository states the NIST software licence in its `README.md`
(it has no separate licence file); the notice is reproduced here in full, as
it requires:

> NIST-developed software is provided by NIST as a public service. You may
> use, copy, and distribute copies of the software in any medium, provided
> that you keep intact this entire notice. You may improve, modify, and
> create derivative works of the software or any portion of the software, and
> you may copy and distribute such modifications or works. Modified works
> should carry a notice stating that you changed the software and should note
> the date and nature of any such change. Please explicitly acknowledge the
> National Institute of Standards and Technology as the source of the
> software.
>
> NIST-developed software is expressly provided "AS IS." NIST MAKES NO
> WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF
> LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST
> NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE
> UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST
> DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE
> SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE
> CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
>
> You are solely responsible for determining the appropriateness of using and
> distributing the software and you assume all risks associated with its use,
> including but not limited to the risks and costs of program errors,
> compliance with applicable laws, damage to or loss of data, programs or
> equipment, and the unavailability or interruption of operation. This
> software is not intended to be used in any situation where a failure could
> cause risk of injury or damage to property. The software developed by NIST
> employees is not subject to copyright protection within the United States.

The vectors are the work of the National Institute of Standards and
Technology.
