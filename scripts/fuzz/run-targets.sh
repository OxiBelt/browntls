#!/usr/bin/env bash
# Build and run fuzz targets for a fixed time each, as the fuzz workflow does.
#
#   scripts/fuzz/run-targets.sh SECONDS TARGET...
#
# Environment:
#   FUZZ_TOOLCHAIN   toolchain for cargo-fuzz (default: nightly)
#   FUZZ_SANITIZER   cargo-fuzz sanitizer: address (default) or none
#   FUZZ_FINDINGS    directory for crash inputs and logs (default: fuzz/findings)
#   FUZZ_MINIMIZE    1 to minimize each corpus after a clean run (cargo fuzz
#                    cmin), for runs that keep their corpus; default 0
#
# Runs from the repository root. Seeds come from `cargo run --example
# seed_corpus` (fuzz/corpus/<target>/, merged with whatever corpus is already
# there). Every target runs even if an earlier one fails; the exit status is
# non-zero if any failed.
#
# A crash is a potential vulnerability (SECURITY.md): libFuzzer's output and
# the crashing input stay in FUZZ_FINDINGS and are not printed, because CI
# logs of this repository are public (on a CI runner they are discarded with
# the runner). Only the target, the exit status, the
# kind of finding, libFuzzer's random seed, its final statistics and the
# input's SHA-256 are printed.
#
# A failing input may be an entry of the target's corpus (restored from an
# earlier run or generated as a seed) rather than a new mutation, so a failing
# target's corpus is moved into FUZZ_FINDINGS too (<target>/corpus.XXXXXX/),
# and nothing that later publishes fuzz/corpus, such as the fuzz workflow's
# corpus cache, can carry the input. Only targets that ran clean keep a corpus
# under fuzz/corpus.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 SECONDS TARGET..." >&2
  exit 2
fi
seconds="$1"
shift
toolchain="${FUZZ_TOOLCHAIN:-nightly}"
sanitizer="${FUZZ_SANITIZER:-address}"
repo="$(cd "$(dirname "$0")/../.." && pwd)"
findings="${FUZZ_FINDINGS:-${repo}/fuzz/findings}"
mkdir -p "${findings}"
cd "${repo}/fuzz"

# Debug assertions also enable overflow checks in the fuzzed code.
build=(cargo "+${toolchain}" fuzz build --release --debug-assertions --sanitizer "${sanitizer}")

echo "::group::Generate seeds"
cargo "+${toolchain}" run --locked --example seed_corpus
echo "::endgroup::"

failed=()
for target in "$@"; do
  echo "::group::Build ${target}"
  "${build[@]}" "${target}"
  echo "::endgroup::"

  read -r -a extra <<< "$(python3 -B "${repo}/scripts/fuzz/plan.py" matrix --args "${target}")"
  log="${findings}/${target}.log"
  artifacts="${findings}/${target}/"
  mkdir -p "${artifacts}"
  echo "Fuzzing ${target} for ${seconds}s"
  set +e
  cargo "+${toolchain}" fuzz run --release --debug-assertions --sanitizer "${sanitizer}" \
    "${target}" "corpus/${target}" -- \
    -max_total_time="${seconds}" \
    -timeout=60 \
    -rss_limit_mb=2048 \
    -print_final_stats=1 \
    -artifact_prefix="${artifacts}" \
    "${extra[@]}" > "${log}" 2>&1
  status=$?
  set -e

  # Statistics are safe to show; the rest of the log is not.
  grep -E '^(INFO: Seed:|stat::|#[0-9]+[[:space:]]+DONE)' "${log}" || true
  if [[ ${status} -eq 0 ]]; then
    rm -f "${log}"
    rmdir "${artifacts}" 2>/dev/null || true
    if [[ "${FUZZ_MINIMIZE:-0}" == 1 ]]; then
      echo "::group::Minimize the ${target} corpus"
      cargo "+${toolchain}" fuzz cmin --release --debug-assertions --sanitizer "${sanitizer}" \
        "${target}" "corpus/${target}" -- -timeout=60 -rss_limit_mb=2048 "${extra[@]}" \
        > /dev/null 2>&1 \
        || echo "corpus minimization failed; keeping the corpus as it is"
      echo "::endgroup::"
    fi
    continue
  fi

  failed+=("${target}")
  kind="unknown"
  for prefix in crash oom timeout leak slow-unit; do
    if compgen -G "${artifacts}${prefix}-*" > /dev/null; then
      kind="${prefix}"
      break
    fi
  done
  echo "::error title=Fuzz finding in ${target}::${target} failed (exit ${status}, ${kind}). The input and log are withheld from the public log; see fuzz/README.md, Continuous fuzzing."
  quarantine="$(mktemp -d "${artifacts}corpus.XXXXXX")"
  mv "corpus/${target}" "${quarantine}/"
  echo "The ${target} corpus was moved to the findings directory."
  for input in "${artifacts}"*; do
    [[ -f "${input}" ]] && echo "input SHA-256: $(sha256sum "${input}" | cut -d' ' -f1)"
  done
done

if [[ ${#failed[@]} -gt 0 ]]; then
  echo "Failed targets: ${failed[*]}" >&2
  exit 1
fi
