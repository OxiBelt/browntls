#!/usr/bin/env python3
"""Compare browntls-crypto throughput with `openssl speed` on this machine.

Usage: python3 scripts/bench-vs-openssl.py [--seconds N] [--output FILE]

Builds `crates/browntls-crypto/examples/speed.rs` in release mode for
x86-64-v3 (the supported baseline) when run on x86-64, runs it with the
default policy and with portable code only, runs the equivalent
`openssl speed -elapsed -mr` commands, and prints a Markdown table of
results and ratios (browntls / OpenSSL). Everything is single-threaded.
"""

import argparse
import os
import platform
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OPENSSL_EVP = [
    ("AES-128-GCM", ["-aead", "-evp", "aes-128-gcm"]),
    ("AES-256-GCM", ["-aead", "-evp", "aes-256-gcm"]),
    ("ChaCha20-Poly1305", ["-aead", "-evp", "chacha20-poly1305"]),
    ("SHA-256", ["-evp", "sha256"]),
    ("SHA-512", ["-evp", "sha512"]),
    ("SHA3-256", ["-evp", "sha3-256"]),
]
OPENSSL_PK = ["rsa2048", "rsa3072", "ecdsap256", "ecdsap384", "ecdhp256", "ecdhp384",
              "ecdhx25519", "ed25519"]


def run(cmd, env=None):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, cwd=REPO,
                          env=env).stdout


def ours(seconds, policy, binary):
    out = {}
    for line in run([binary, "--policy", policy, "--seconds", str(seconds)]).splitlines():
        if line.startswith("#"):
            continue
        kind, alg, key, value = line.split("\t")
        out[(alg, key if kind == "ops" else int(key))] = float(value)
    return out


def openssl(seconds):
    out = {}
    base = ["openssl", "speed", "-elapsed", "-mr", "-seconds", str(seconds)]
    for name, args in OPENSSL_EVP:
        lengths = []
        for line in run(base + args).splitlines():
            parts = line.split(":")
            if parts[0] == "+H":
                lengths = [int(x) for x in parts[1:]]
            elif parts[0] == "+F":
                for length, value in zip(lengths, parts[3:]):
                    out[(name, length)] = float(value)
    for line in run(base + OPENSSL_PK).splitlines():
        p = line.split(":")
        if p[0] == "+F2":  # RSA: bits, sign/s, verify/s
            out[(f"RSA-{p[2]}", "sign")] = float(p[3])
            out[(f"RSA-{p[2]}", "verify")] = float(p[4])
        elif p[0] == "+F4":  # ECDSA: bits, sign/s, verify/s
            out[(f"P-{p[2]}", "sign")] = float(p[3])
            out[(f"P-{p[2]}", "verify")] = float(p[4])
        elif p[0] == "+F5":  # ECDH: bits, op/s
            name = "X25519" if p[2] == "253" else f"P-{p[2]}"
            out[(name, "derive" if name == "X25519" else "ecdh")] = float(p[3])
        elif p[0] == "+F6":  # EdDSA: bits, name, sign/s, verify/s
            out[(p[3], "sign")] = float(p[4])
            out[(p[3], "verify")] = float(p[5])
    return out


def fmt(value, unit):
    if value is None:
        return "—"
    if unit == "bytes":
        return f"{value / 1e6:,.0f} MB/s"
    return f"{value:,.0f}/s"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=2.0)
    ap.add_argument("--output")
    args = ap.parse_args()

    env = dict(os.environ)
    target_dir = os.path.join(REPO, "target", "bench")
    env["CARGO_TARGET_DIR"] = target_dir
    if platform.machine() == "x86_64":
        env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + " -C target-cpu=x86-64-v3").strip()
    run(["cargo", "build", "--release", "--locked", "-p", "browntls-crypto",
         "--example", "speed"], env=env)
    binary = os.path.join(target_dir, "release", "examples", "speed")

    status = [l[2:] for l in run([binary, "--seconds", "0"]).splitlines()
              if l.startswith("# ")]
    seconds = args.seconds
    fast = ours(seconds, "preferred", binary)
    portable = ours(seconds, "none", binary)
    ossl = openssl(max(1, round(seconds)))

    lines = []
    cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo")
                if l.startswith("model name")), platform.processor())
    lines.append(f"- CPU: {cpu} ({platform.machine()}), {os.cpu_count()} logical CPUs")
    lines.append(f"- OpenSSL: {run(['openssl', 'version']).strip()}")
    lines.append(f"- rustc: {run(['rustc', '--version']).strip()}")
    lines.append(f"- Measurement: single thread, wall clock, ~{seconds:g} s per row")
    lines.append("")
    lines.append("| Algorithm | Size / operation | browntls (accelerated) | browntls (portable) "
                 "| OpenSSL | browntls / OpenSSL |")
    lines.append("|---|---|---:|---:|---:|---:|")
    for key in fast:
        alg, sub = key
        unit = "bytes" if isinstance(sub, int) else "ops"
        o = ossl.get(key)
        ratio = f"{fast[key] / o:.2f}×" if o else "—"
        label = f"{sub} B" if unit == "bytes" else sub
        lines.append(f"| {alg} | {label} | {fmt(fast[key], unit)} "
                     f"| {fmt(portable.get(key), unit)} | {fmt(o, unit)} | {ratio} |")
    lines.append("")
    lines.append("Selected backends (accelerated column):")
    lines.append("")
    lines.extend(f"- {s}" for s in status)
    text = "\n".join(lines) + "\n"
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
