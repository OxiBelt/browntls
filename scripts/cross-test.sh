#!/usr/bin/env bash
# Run cargo tests for a non-host CPU profile under QEMU user-mode emulation.
#
# Usage: scripts/cross-test.sh <profile> [cargo test arguments...]
#
# Profiles exercise distinct backend tiers:
#   x86_64-max         QEMU "max" x86-64 CPU: SHA-NI, VAES (YMM), GFNI; QEMU 8.2
#                      reports no VPCLMULQDQ or AVX-512, so the ZMM AES-GCM and
#                      VPCLMULQDQ GHASH backends run only on native hardware
#   aarch64-max        all Armv8/v9 crypto extensions (AES, PMULL, SHA2, SHA3, SHA512)
#   aarch64-a53        Cortex-A53 model (AES/PMULL/SHA2, no SHA3/SHA512)
#   host-soft          native host build with --cfg browntls_force_soft
#                      (portable backends only)
#   riscv64-scalar     RV64GC without vector or scalar-crypto extensions
#   riscv64-zk         scalar Zbb/Zbc/Zbkb/Zbkc/Zknh/Zkne/Zknd, no vector
#   riscv64-rvv128     RVV 1.0, VLEN=128, no vector crypto
#   riscv64-rvv128-zvk RVV 1.0, VLEN=128 (minimum) with vector crypto
#   riscv64-rvv256-zvk RVV 1.0, VLEN=256, Zvkned/Zvknhb/Zvkg/Zvbc/Zvbb/Zvkb
#   riscv64-rvv1024-zvk RVV 1.0, VLEN=1024 with vector crypto
#
# Requirements (Ubuntu 24.04): qemu-user-static, gcc-aarch64-linux-gnu,
# gcc-riscv64-linux-gnu, and the matching rustup targets.
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

extra_rustflags=()
variant=plain
case "${profile}" in
  x86_64-max)
    target=x86_64-unknown-linux-gnu
    runner="qemu-x86_64-static -cpu max"
    linker=""
    ;;
  aarch64-max)
    target=aarch64-unknown-linux-gnu
    runner="qemu-aarch64-static -L /usr/aarch64-linux-gnu -cpu max"
    linker=aarch64-linux-gnu-gcc
    ;;
  aarch64-a53)
    target=aarch64-unknown-linux-gnu
    runner="qemu-aarch64-static -L /usr/aarch64-linux-gnu -cpu cortex-a53"
    linker=aarch64-linux-gnu-gcc
    ;;
  host-soft)
    export RUSTFLAGS="${RUSTFLAGS:-} --cfg browntls_force_soft"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}/cross-soft"
    echo "profile=${profile} (host, portable backends only)" >&2
    exec cargo test "$@"
    ;;
  riscv64-scalar)
    target=riscv64gc-unknown-linux-gnu
    runner="qemu-riscv64-static -L /usr/riscv64-linux-gnu -cpu rv64,v=false"
    linker=riscv64-linux-gnu-gcc
    ;;
  riscv64-zk)
    target=riscv64gc-unknown-linux-gnu
    runner="qemu-riscv64-static -L /usr/riscv64-linux-gnu -cpu rv64,v=false,zbb=true,zbc=true,zbkb=true,zbkc=true,zknh=true,zkne=true,zknd=true"
    linker=riscv64-linux-gnu-gcc
    extra_rustflags=("${zk_cfg[@]}")
    variant=zk
    ;;
  riscv64-rvv128)
    target=riscv64gc-unknown-linux-gnu
    runner="qemu-riscv64-static -L /usr/riscv64-linux-gnu -cpu rv64,v=true,vlen=128,zbb=true"
    linker=riscv64-linux-gnu-gcc
    ;;
  riscv64-rvv128-zvk)
    target=riscv64gc-unknown-linux-gnu
    runner="qemu-riscv64-static -L /usr/riscv64-linux-gnu -cpu rv64,v=true,vlen=128,zbb=true,zvkned=true,zvknha=true,zvknhb=true,zvkg=true,zvbc=true,zvbb=true,zvkb=true,zvkt=true"
    linker=riscv64-linux-gnu-gcc
    extra_rustflags=("${zvk_cfg[@]}")
    variant=zvk
    ;;
  riscv64-rvv256-zvk)
    target=riscv64gc-unknown-linux-gnu
    runner="qemu-riscv64-static -L /usr/riscv64-linux-gnu -cpu rv64,v=true,vlen=256,zbb=true,zvkned=true,zvknha=true,zvknhb=true,zvkg=true,zvbc=true,zvbb=true,zvkb=true,zvkt=true"
    linker=riscv64-linux-gnu-gcc
    extra_rustflags=("${zvk_cfg[@]}")
    variant=zvk
    ;;
  riscv64-rvv1024-zvk)
    target=riscv64gc-unknown-linux-gnu
    runner="qemu-riscv64-static -L /usr/riscv64-linux-gnu -cpu rv64,v=true,vlen=1024,zbb=true,zvkned=true,zvknha=true,zvknhb=true,zvkg=true,zvbc=true,zvbb=true,zvkb=true,zvkt=true"
    linker=riscv64-linux-gnu-gcc
    extra_rustflags=("${zvk_cfg[@]}")
    variant=zvk
    ;;
  *)
    echo "unknown profile: ${profile}" >&2
    exit 2
    ;;
esac

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
