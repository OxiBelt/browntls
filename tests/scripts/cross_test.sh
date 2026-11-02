#!/bin/sh
# Builds and tests the workspace for AArch64 and RISC-V under QEMU user-mode
# emulation. Requires qemu-user, the matching GNU cross linkers and sysroots
# (Debian/Ubuntu: qemu-user gcc-aarch64-linux-gnu gcc-riscv64-linux-gnu), and
# the Rust targets aarch64-unknown-linux-gnu and riscv64gc-unknown-linux-gnu.
#
# Usage: tests/scripts/cross_test.sh [aarch64|riscv64|all] [extra cargo args]
set -eu

target_set="${1:-all}"
[ "$#" -gt 0 ] && shift

aarch64_sysroot="${AARCH64_SYSROOT:-/usr/aarch64-linux-gnu}"
riscv64_sysroot="${RISCV64_SYSROOT:-/usr/riscv64-linux-gnu}"
# Emulated RISC-V CPU: RVV 1.0 with 256-bit vectors plus the vector crypto and
# scalar bit-manipulation extensions used by accelerated backends.
riscv64_cpu="${RISCV64_QEMU_CPU:-rv64,v=true,vlen=256,zvkned=true,zvknhb=true,zvkg=true,zvbc=true,zvkb=true,zbc=true,zbkb=true}"

export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER:-aarch64-linux-gnu-gcc}"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER:-qemu-aarch64 -L ${aarch64_sysroot} -cpu max}"
export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER:-riscv64-linux-gnu-gcc}"
export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER="${CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER:-qemu-riscv64 -L ${riscv64_sysroot} -cpu ${riscv64_cpu}}"

run() {
    echo "== cargo test --target $1" >&2
    shift_target="$1"
    shift
    cargo test --workspace --target "${shift_target}" "$@"
}

case "${target_set}" in
    aarch64) run aarch64-unknown-linux-gnu "$@" ;;
    riscv64) run riscv64gc-unknown-linux-gnu "$@" ;;
    all)
        run aarch64-unknown-linux-gnu "$@"
        run riscv64gc-unknown-linux-gnu "$@"
        ;;
    *)
        echo "unknown target set: ${target_set}" >&2
        exit 2
        ;;
esac
