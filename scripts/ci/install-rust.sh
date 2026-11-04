#!/usr/bin/env bash
# Ensure rustup and the toolchain pinned in rust-toolchain.toml are installed.
#
# If rustup is missing, download the official rustup-init for the host and
# verify it against the SHA-256 published next to it on static.rust-lang.org
# before running it. Extra arguments are rustup target triples to add.
set -euo pipefail

if ! command -v rustup >/dev/null 2>&1; then
  case "$(uname -m)" in
    x86_64) host=x86_64-unknown-linux-gnu ;;
    aarch64) host=aarch64-unknown-linux-gnu ;;
    riscv64) host=riscv64gc-unknown-linux-gnu ;;
    *) echo "unsupported host $(uname -m)" >&2; exit 1 ;;
  esac
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' EXIT
  base="https://static.rust-lang.org/rustup/dist/${host}"
  curl --fail --silent --show-error --location --retry 3 --proto '=https' --tlsv1.2 \
    "${base}/rustup-init" --output "${tmp}/rustup-init"
  curl --fail --silent --show-error --location --retry 3 --proto '=https' --tlsv1.2 \
    "${base}/rustup-init.sha256" --output "${tmp}/rustup-init.sha256"
  printf '%s  %s\n' "$(cut -d' ' -f1 < "${tmp}/rustup-init.sha256")" "${tmp}/rustup-init" \
    | sha256sum --check --strict
  chmod +x "${tmp}/rustup-init"
  "${tmp}/rustup-init" -y --no-modify-path --profile minimal --default-toolchain none
  export PATH="${HOME}/.cargo/bin:${PATH}"
  if [[ -n "${GITHUB_PATH:-}" ]]; then
    echo "${HOME}/.cargo/bin" >> "${GITHUB_PATH}"
  fi
fi

# Installs the channel, components and targets listed in rust-toolchain.toml.
rustup toolchain install
for target in "$@"; do
  rustup target add "${target}"
done
rustc --version --verbose
