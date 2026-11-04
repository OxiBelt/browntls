#!/usr/bin/env bash
# Run cargo tests for a non-host CPU profile under QEMU user-mode emulation.
#
# Usage: scripts/cross-test.sh <profile> [cargo test arguments...]
#
# Profiles exercise distinct backend tiers:
#   x86_64-max         QEMU "max" x86-64 CPU: SHA-NI, VAES (YMM), GFNI; the ZMM
#                      AES-GCM, VPCLMULQDQ GHASH and IFMA RSA backends run only
#                      if the QEMU version reports VPCLMULQDQ and AVX-512
#                      (QEMU 8.2 does not)
#   aarch64-max        all Armv8/v9 crypto extensions (AES, PMULL, SHA2, SHA3, SHA512)
#   aarch64-a53        Cortex-A53 model (AES/PMULL/SHA2, no SHA3/SHA512)
#                      (CI runs aarch64 natively on the GitHub Arm runner; the
#                      aarch64 profiles are for hosts without one)
#   host-soft          native host build with --cfg browntls_force_soft
#                      (portable backends only)
#   riscv64-scalar     RV64GC without vector or scalar-crypto extensions
#   riscv64-zk         scalar Zbb/Zbc/Zbkb/Zbkc/Zknh/Zkne/Zknd, no vector
#   riscv64-rvv128     RVV 1.0, VLEN=128, no vector crypto
#   riscv64-rvv128-zvk RVV 1.0, VLEN=128 (minimum) with vector crypto
#   riscv64-rvv256-zvk RVV 1.0, VLEN=256, Zvkned/Zvknhb/Zvkg/Zvbc/Zvbb/Zvkb
#   riscv64-rvv1024-zvk RVV 1.0, VLEN=1024 with vector crypto
#
# The riscv64 profiles build static musl binaries (riscv64gc-unknown-linux-musl,
# linked by rust-lld against the RV64GC musl that ships with the Rust target)
# rather than linking the distribution's cross glibc: from Ubuntu 25.10 on that
# glibc, its dynamic loader included, is built for RVA23U64 (V, Zvbb, Zicond,
# Zcb, ...), so it traps on every emulated CPU that lacks those extensions,
# which is what most profiles are for. These profiles therefore cover crates
# without C dependencies (browntls-crypto, browntls-pki).
#
# Requirements (Ubuntu 26.04): qemu-user-static or qemu-user,
# gcc-aarch64-linux-gnu for the aarch64 profiles, and the matching rustup
# targets (x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu,
# riscv64gc-unknown-linux-musl).
set -euo pipefail

profile="${1:?usage: $0 <profile> [cargo test args...]}"
shift

zvk_cfg=()
for ext in v zvkned zvknhb zvkg zvbc zvbb zvkb; do
  zvk_cfg+=("--cfg" "browntls_assume_riscv=\"${ext}\"")
done
zk_cfg=()
for ext in zbb zbc zbkb zbkc zknh zkne zknd; do
  zk_cfg+=("--cfg" "browntls_assume_riscv=\"${ext}\"")
done

# The user-mode emulator for an architecture: the statically linked build
# where installed (qemu-user-static), else the dynamically linked one
# (qemu-user); both work, since the runner is invoked directly.
qemu() {
  if command -v "qemu-$1-static" >/dev/null 2>&1; then
    echo "qemu-$1-static"
  else
    echo "qemu-$1"
  fi
}

extra_rustflags=()
variant=plain
case "${profile}" in
  x86_64-max)
    target=x86_64-unknown-linux-gnu
    runner="$(qemu x86_64) -cpu max"
    linker=""
    ;;
  aarch64-max)
    target=aarch64-unknown-linux-gnu
    runner="$(qemu aarch64) -L /usr/aarch64-linux-gnu -cpu max"
    linker=aarch64-linux-gnu-gcc
    ;;
  aarch64-a53)
    target=aarch64-unknown-linux-gnu
    runner="$(qemu aarch64) -L /usr/aarch64-linux-gnu -cpu cortex-a53"
    linker=aarch64-linux-gnu-gcc
    ;;
  host-soft)
    export RUSTFLAGS="${RUSTFLAGS:-} --cfg browntls_force_soft"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}/cross-soft"
    echo "profile=${profile} (host, portable backends only)" >&2
    exec cargo test "$@"
    ;;
  riscv64-scalar)
    target=riscv64gc-unknown-linux-musl
    runner="$(qemu riscv64) -cpu rv64,v=false"
    linker=rust-lld
    ;;
  riscv64-zk)
    target=riscv64gc-unknown-linux-musl
    runner="$(qemu riscv64) -cpu rv64,v=false,zbb=true,zbc=true,zbkb=true,zbkc=true,zknh=true,zkne=true,zknd=true"
    linker=rust-lld
    extra_rustflags=("${zk_cfg[@]}")
    variant=zk
    ;;
  riscv64-rvv128)
    target=riscv64gc-unknown-linux-musl
    runner="$(qemu riscv64) -cpu rv64,v=true,vlen=128,zbb=true"
    linker=rust-lld
    ;;
  riscv64-rvv128-zvk)
    target=riscv64gc-unknown-linux-musl
    runner="$(qemu riscv64) -cpu rv64,v=true,vlen=128,zbb=true,zvkned=true,zvknha=true,zvknhb=true,zvkg=true,zvbc=true,zvbb=true,zvkb=true,zvkt=true"
    linker=rust-lld
    extra_rustflags=("${zvk_cfg[@]}")
    variant=zvk
    ;;
  riscv64-rvv256-zvk)
    target=riscv64gc-unknown-linux-musl
    runner="$(qemu riscv64) -cpu rv64,v=true,vlen=256,zbb=true,zvkned=true,zvknha=true,zvknhb=true,zvkg=true,zvbc=true,zvbb=true,zvkb=true,zvkt=true"
    linker=rust-lld
    extra_rustflags=("${zvk_cfg[@]}")
    variant=zvk
    ;;
  riscv64-rvv1024-zvk)
    target=riscv64gc-unknown-linux-musl
    runner="$(qemu riscv64) -cpu rv64,v=true,vlen=1024,zbb=true,zvkned=true,zvknha=true,zvknhb=true,zvkg=true,zvbc=true,zvbb=true,zvkb=true,zvkt=true"
    linker=rust-lld
    extra_rustflags=("${zvk_cfg[@]}")
    variant=zvk
    ;;
  *)
    echo "unknown profile: ${profile}" >&2
    exit 2
    ;;
esac

if [[ "${target}" == *-musl ]]; then
  # riscv64gc-unknown-linux-musl links dynamically unless asked otherwise.
  # Doctests are built by rustdoc, which reads RUSTDOCFLAGS only (with
  # --target these apply to the target, not to build scripts).
  extra_rustflags=("-C" "target-feature=+crt-static" "${extra_rustflags[@]}")
  export RUSTDOCFLAGS="${RUSTDOCFLAGS:-} -C target-feature=+crt-static"
fi

triple_env="$(echo "${target}" | tr '[:lower:]-' '[:upper:]_')"
export "CARGO_TARGET_${triple_env}_RUNNER=${runner}"
if [[ -n "${linker}" ]]; then
  export "CARGO_TARGET_${triple_env}_LINKER=${linker}"
fi
if [[ ${#extra_rustflags[@]} -gt 0 ]]; then
  export "CARGO_TARGET_${triple_env}_RUSTFLAGS=${extra_rustflags[*]}"
fi
# Profiles that share RUSTFLAGS share a target directory (cargo already
# separates artefacts per target triple), which bounds disk use.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}/cross-${variant}"

echo "profile=${profile} target=${target} runner=${runner}" >&2
exec cargo test --target "${target}" "$@"
