#!/usr/bin/env python3
"""Plan the fuzzing matrix of .github/workflows/fuzz.yml from fuzz/targets.toml.

    plan.py check
        Checks that fuzz/targets.toml, the `[[bin]]` targets of fuzz/Cargo.toml,
        fuzz/fuzz_targets/*.rs and the TARGETS table of fuzz/src/seeds.rs name
        the same targets, and that every entry is well formed.

    plan.py matrix [--granularity target|topic] [--changed-files FILE]
                   [--targets a,b]
        Prints a GitHub Actions matrix as JSON: {"include": [...]}, one entry
        per target or, with `topic`, per topic running that topic's targets
        one after another. Every entry runs on the workflow's single x86-64
        runner, so the matrix has no architecture axis. With --changed-files
        (one repository-relative path per line, as `git diff --name-only`
        prints them) only the targets whose sources, harness or target file
        changed are planned; a change to the shared fuzz infrastructure plans
        every target. An empty selection prints {"include": []}.

    plan.py matrix --args TARGET
        Prints TARGET's extra libFuzzer arguments instead (used by
        scripts/fuzz/run-targets.sh).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from fnmatch import fnmatchcase
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FUZZ = REPO / "fuzz"
# Changes here can affect every target.
SHARED = (
    "fuzz/Cargo.toml",
    "fuzz/Cargo.lock",
    "fuzz/targets.toml",
    "fuzz/src/lib.rs",
    "fuzz/src/input.rs",
    "fuzz/src/seeds.rs",
    "fuzz/examples/**",
    "scripts/fuzz/**",
    "scripts/ci/install-rust.sh",
    ".github/workflows/fuzz.yml",
    "rust-toolchain.toml",
    "Cargo.toml",
    "Cargo.lock",
)
KEYS = {"topic", "sources", "args", "harness"}


def glob_match(path: str, pattern: str) -> bool:
    """fnmatch with `**` spanning directories and `*` staying inside one."""
    regex = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            regex += ".*"
            i += 2
        elif pattern[i] == "*":
            regex += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            regex += "[^/]"
            i += 1
        else:
            regex += re.escape(pattern[i])
            i += 1
    return re.fullmatch(regex, path) is not None


def load_targets(path: Path = FUZZ / "targets.toml") -> dict[str, dict]:
    with path.open("rb") as f:
        targets = tomllib.load(f).get("targets", {})
    for name, spec in targets.items():
        spec.setdefault("args", [])
        spec.setdefault("harness", [f"fuzz/src/{name}.rs", f"fuzz/src/{name}/**"])
        spec["harness"] = [*spec["harness"], f"fuzz/fuzz_targets/{name}.rs"]
    return targets


def cargo_bins() -> list[str]:
    with (FUZZ / "Cargo.toml").open("rb") as f:
        manifest = tomllib.load(f)
    return [b["name"] for b in manifest.get("bin", [])]


def seeds_targets() -> list[str]:
    text = (FUZZ / "src" / "seeds.rs").read_text(encoding="utf-8")
    table = text.split("pub const TARGETS", 1)[1].split("];", 1)[0]
    return re.findall(r'^\s*\(\s*"([a-z0-9_]+)"', table, re.MULTILINE)


def check() -> list[str]:
    errors = []
    targets = load_targets()
    files = [
        p.relative_to(REPO).as_posix()
        for top in ("crates", "fuzz")
        for p in (REPO / top).rglob("*")
        if p.is_file() and "target" not in p.relative_to(REPO).parts
    ]
    names = set(targets)
    for label, other in (
        ("fuzz/Cargo.toml [[bin]]", cargo_bins()),
        ("fuzz/fuzz_targets/*.rs", [p.stem for p in (FUZZ / "fuzz_targets").glob("*.rs")]),
        ("fuzz/src/seeds.rs TARGETS", seeds_targets()),
    ):
        if len(other) != len(set(other)):
            errors.append(f"{label} lists a target twice")
        for missing in sorted(names - set(other)):
            errors.append(f"{missing}: in fuzz/targets.toml but not in {label}")
        for extra in sorted(set(other) - names):
            errors.append(f"{extra}: in {label} but not in fuzz/targets.toml")
    for name, spec in targets.items():
        unknown = set(spec) - KEYS
        if unknown:
            errors.append(f"{name}: unknown keys {sorted(unknown)}")
        if not isinstance(spec.get("topic"), str) or not spec["topic"]:
            errors.append(f"{name}: topic must be a non-empty string")
        if not spec.get("sources") or not all(isinstance(s, str) for s in spec["sources"]):
            errors.append(f"{name}: sources must be a non-empty list of globs")
        if not all(isinstance(a, str) and a.startswith("-") for a in spec["args"]):
            errors.append(f"{name}: args must be libFuzzer flags")
        for pattern in spec.get("sources", []) + spec["harness"][:1]:
            if not any(glob_match(f, pattern) for f in files):
                errors.append(f"{name}: pattern {pattern!r} matches no file")
    return errors


def selected(targets: dict[str, dict], changed: list[str] | None) -> list[str]:
    if changed is None:
        return list(targets)
    if any(glob_match(path, pattern) for path in changed for pattern in SHARED):
        return list(targets)
    # A crate manifest (features, dependencies) affects every target with
    # sources in that crate.
    crates = {
        path.rsplit("/", 1)[0] + "/"
        for path in changed
        if re.fullmatch(r"crates/[^/]+/(Cargo\.toml|build\.rs)", path)
    }
    harness_files = {p for spec in targets.values() for p in spec["harness"]}
    # A harness module no target claims (a shared helper) affects all.
    for path in changed:
        if path.startswith("fuzz/") and path.endswith(".rs") and not any(
            glob_match(path, p) for p in harness_files
        ):
            return list(targets)
    return [
        name
        for name, spec in targets.items()
        if any(glob_match(path, p) for path in changed for p in spec["sources"] + spec["harness"])
        or any(p.startswith(c) for c in crates for p in spec["sources"])
    ]


def matrix(granularity: str, changed: list[str] | None, only: set[str] | None) -> dict:
    targets = load_targets()
    if only:
        unknown = only - set(targets)
        if unknown:
            raise SystemExit(f"unknown targets: {', '.join(sorted(unknown))}")
    names = [n for n in selected(targets, changed) if not only or n in only]
    groups: dict[str, list[str]] = {}
    for name in names:
        label = targets[name]["topic"] if granularity == "topic" else name
        groups.setdefault(label, []).append(name)
    include = [{"name": label, "targets": " ".join(group)} for label, group in groups.items()]
    return {"include": include}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check")
    p = sub.add_parser("matrix")
    p.add_argument("--granularity", choices=("target", "topic"), default="target")
    p.add_argument("--changed-files", type=Path)
    p.add_argument("--targets", default="", help="comma-separated target names")
    p.add_argument("--args", metavar="TARGET", help="print TARGET's extra libFuzzer arguments instead")
    args = parser.parse_args()
    if args.command == "check":
        errors = check()
        for error in errors:
            print(error, file=sys.stderr)
        return 1 if errors else 0
    if args.args:
        print(" ".join(load_targets()[args.args]["args"]))
        return 0
    changed = None
    if args.changed_files:
        changed = [line.strip() for line in args.changed_files.read_text().splitlines() if line.strip()]
    only = {t for t in args.targets.replace(" ", ",").split(",") if t} or None
    print(json.dumps(matrix(args.granularity, changed, only), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
