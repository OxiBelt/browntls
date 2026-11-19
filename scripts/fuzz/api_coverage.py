#!/usr/bin/env python3
"""Check that the fuzz harnesses reach every public function.

The public API is every `pub fn` (including `const`, `unsafe` and `extern`
functions) in the library crates' sources, outside inline modules gated on
`test` (`#[cfg(test)]`, `#[cfg(all(test, ...))]`) and files named `tests.rs`
or under a `tests/` directory of `src/`.
Each one is identified by its source file and its name qualified with the
type of the enclosing `impl` block, for example
`crates/browntls/src/conn/buffered.rs ConnectionCommon::read_tls`.

`run` builds the fuzz project's library tests with LLVM source-based coverage
on the pinned stable toolchain, runs them (they feed every harness its seeds,
their truncations and mutations: `fuzz/src/seeds.rs`) and checks the result.
`check` does the same from an existing `llvm-cov export` JSON file.

A function passes when its body ran at least once. A function that did not
run, or that has no coverage record at all (compiled out for this target, or
evaluated only at compile time), fails unless an exemption names it with a
reason. Exemptions live in `fuzz/api-coverage-exemptions.txt`, one per line:

    <path> <qualified name>  # <reason>

`<qualified name>` may end in `*` to cover every function of a type or file
(`Foo::*`, `*`). An exemption that matches no failing function is reported as
stale, so the list shrinks as harnesses improve.
"""

from __future__ import annotations

import argparse
import fnmatch
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CRATES = (
    "crates/browntls",
    "crates/browntls-crypto",
    "crates/browntls-pki",
    "crates/browntls-tokio",
)
DEFAULT_EXEMPTIONS = REPO / "fuzz" / "api-coverage-exemptions.txt"

PUB_FN = re.compile(
    r'^(?P<indent>\s*)pub (?:const )?(?:async )?(?:unsafe )?(?:extern "[^"]*" )?fn '
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_]*)"
)
IMPL = re.compile(r"^(?P<indent>\s*)(?:unsafe )?impl\b(?P<rest>.*)$")
# `#[cfg(test)]`, `#[cfg(all(test, ...))]` and the like, but not `not(test)`.
CFG_TEST = re.compile(r"^#\[cfg\((?:test|all\(test\b[^)]*\)|all\([^)]*\btest\b[^)]*\))\)\]")
MOD_OPEN = re.compile(r"^\s*(?:pub(?:\([^)]*\))? )?mod \w+\s*\{")
MACRO_RULES = re.compile(r"^\s*(?:#\[macro_export\]\s*)?macro_rules!")


@dataclass(frozen=True)
class PublicFn:
    path: str  # repository-relative, '/' separated
    name: str  # qualified with the impl type, e.g. "Foo::bar"
    line: int  # 1-based line of the `pub fn`
    in_macro: bool


def _strip_generics(text: str) -> str:
    out, depth = [], 0
    for ch in text:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def _impl_type(rest: str) -> str:
    """The self type's last path segment from the text after `impl`."""
    text = rest.split("{")[0].split(" where ")[0]
    text = _strip_generics(text).strip()
    if " for " in f" {text} ":
        text = text.split(" for ", 1)[1]
    text = text.strip().lstrip("&").replace("mut ", "").replace("dyn ", "")
    text = text.split("::")[-1].strip()
    return re.sub(r"[^A-Za-z0-9_$]", "", text) or "_"


def _code(line: str) -> str:
    """`line` without string literals and `//` comments, for brace counting."""
    line = re.sub(r"'(?:\\.|[^'\\])'", "''", line)  # char literals
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    return line.split("//", 1)[0]


def scan_file(path: Path) -> list[PublicFn]:
    rel = path.relative_to(REPO).as_posix()
    fns: list[PublicFn] = []
    depth = 0
    pending_test = False
    skip_until: int | None = None  # brace depth at which a test module ends
    impls: list[tuple[int, str]] = []  # (depth at open, type)
    pending_impl: str | None = None
    macro_depth: int | None = None
    pending_macro = False
    seen: dict[str, int] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
        stripped = raw.strip()
        code = _code(raw)
        if skip_until is None:
            if CFG_TEST.match(stripped):
                pending_test = True
            elif pending_test and MOD_OPEN.match(raw):
                skip_until = depth
                pending_test = False
            elif pending_test and stripped and not stripped.startswith(("#", "//")):
                pending_test = False
            if MACRO_RULES.match(raw) and macro_depth is None:
                pending_macro = True
            m = IMPL.match(raw)
            if m and not stripped.startswith("//"):
                pending_impl = _impl_type(m.group("rest"))
            m = PUB_FN.match(raw)
            if m:
                qual = m.group("name")
                if impls:
                    qual = f"{impls[-1][1]}::{qual}"
                count = seen.get(qual, 0) + 1
                seen[qual] = count
                if count > 1:
                    qual = f"{qual}#{count}"
                fns.append(PublicFn(rel, qual, number, macro_depth is not None))
        opens, closes = code.count("{"), code.count("}")
        if opens:
            if pending_impl is not None:
                impls.append((depth, pending_impl))
                pending_impl = None
            if pending_macro:
                macro_depth = depth
                pending_macro = False
        elif pending_impl is not None and code.rstrip().endswith(";"):
            pending_impl = None
        depth += opens - closes
        while impls and depth <= impls[-1][0]:
            impls.pop()
        if macro_depth is not None and depth <= macro_depth:
            macro_depth = None
        if skip_until is not None and depth <= skip_until and (opens or closes):
            skip_until = None
    return fns


def public_fns() -> list[PublicFn]:
    out: list[PublicFn] = []
    for crate in CRATES:
        for path in sorted((REPO / crate / "src").rglob("*.rs")):
            # Out-of-line test modules (`#[cfg(test)] mod tests;`).
            if path.name == "tests.rs" or "tests" in path.relative_to(REPO / crate / "src").parts[:-1]:
                continue
            out.extend(scan_file(path))
    return out


def load_coverage(export: Path) -> tuple[dict[tuple[str, int], int], dict[tuple[str, int], int]]:
    """Function entry counts by the (file, line) where each function starts.

    Returns the largest count over all records starting there (any
    instantiation of a generic function will do) and the smallest (every
    expansion of a macro must run; each is a different public type)."""
    data = json.loads(export.read_text(encoding="utf-8"))
    most: dict[tuple[str, int], int] = {}
    least: dict[tuple[str, int], int] = {}
    root = str(REPO) + os.sep
    for unit in data["data"]:
        for func in unit["functions"]:
            if not func["regions"]:
                continue
            first = func["regions"][0]
            name = func["filenames"][first[5]]
            if not name.startswith(root):
                continue
            key = (Path(name).relative_to(REPO).as_posix(), first[0])
            most[key] = max(most.get(key, 0), func["count"])
            least[key] = min(least.get(key, func["count"]), func["count"])
    return most, least


@dataclass(frozen=True)
class Exemption:
    path: str
    name: str
    reason: str
    line: int

    def matches(self, fn: PublicFn) -> bool:
        return fnmatch.fnmatchcase(fn.path, self.path) and fnmatch.fnmatchcase(fn.name, self.name)


def load_exemptions(path: Path) -> list[Exemption]:
    out = []
    if not path.exists():
        return out
    for number, raw in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        body, sep, reason = text.partition("#")
        parts = body.split()
        if len(parts) != 2 or not sep or not reason.strip():
            raise SystemExit(f"{path}:{number}: expected '<path> <name>  # <reason>'")
        out.append(Exemption(parts[0], parts[1], reason.strip(), number))
    return out


def check(export: Path, exemption_files: list[Path], only: list[str], verbose: bool) -> int:
    most, least = load_coverage(export)
    exemptions = [e for f in exemption_files for e in load_exemptions(f)]
    used: set[Exemption] = set()
    fns = [f for f in public_fns() if not only or any(f.path.startswith(p) for p in only)]
    reached, failed, exempt = [], [], []
    for fn in fns:
        key = (fn.path, fn.line)
        count = least.get(key) if fn.in_macro else most.get(key)
        if count:
            reached.append(fn)
            continue
        status = "not compiled" if count is None else "never ran"
        match = next((e for e in exemptions if e.matches(fn)), None)
        if match:
            used.add(match)
            exempt.append((fn, status, match))
        else:
            failed.append((fn, status))
    stale = [e for e in exemptions if e not in used and (not only or any(e.path.startswith(p) for p in only))]
    total = len(fns)
    print(f"public functions: {total}, reached: {len(reached)}, exempt: {len(exempt)}, missing: {len(failed)}")
    if verbose:
        for fn, status, e in exempt:
            print(f"exempt   {fn.path}:{fn.line} {fn.name} ({status}): {e.reason}")
    for fn, status in failed:
        print(f"MISSING  {fn.path}:{fn.line} {fn.name} ({status})")
    for e in stale:
        print(f"STALE    exemption line {e.line}: {e.path} {e.name}")
    return 1 if failed or stale else 0


def _tool(name: str) -> str:
    sysroot = subprocess.run(
        ["rustc", "--print", "sysroot"], cwd=REPO, check=True, capture_output=True, text=True
    ).stdout.strip()
    host = next(
        line.split()[1]
        for line in subprocess.run(
            ["rustc", "-vV"], cwd=REPO, check=True, capture_output=True, text=True
        ).stdout.splitlines()
        if line.startswith("host:")
    )
    tool = Path(sysroot) / "lib" / "rustlib" / host / "bin" / name
    if not tool.exists():
        raise SystemExit(f"{tool} is missing: rustup component add llvm-tools")
    return str(tool)


def run(args: argparse.Namespace) -> int:
    work = Path(args.work_dir or tempfile.mkdtemp(prefix="browntls-api-coverage."))
    profiles = work / "profiles"
    shutil.rmtree(profiles, ignore_errors=True)
    profiles.mkdir(parents=True)
    env = dict(os.environ)
    env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + " -C instrument-coverage").strip()
    env["LLVM_PROFILE_FILE"] = str(profiles / "%p-%m.profraw")
    env.setdefault("CARGO_TARGET_DIR", str(work / "target"))
    manifest = REPO / "fuzz" / "Cargo.toml"
    cargo = ["cargo", "test", "--manifest-path", str(manifest), "--locked", "--lib"]
    build = subprocess.run(
        cargo + ["--no-run", "--message-format=json"],
        cwd=REPO, env=env, check=True, stdout=subprocess.PIPE, text=True,
    )
    binaries = [
        msg["executable"]
        for msg in map(json.loads, build.stdout.splitlines())
        if msg.get("reason") == "compiler-artifact" and msg.get("executable")
        and msg["target"]["name"] == "browntls_fuzz" and msg["profile"]["test"]
    ]
    if len(binaries) != 1:
        raise SystemExit(f"expected one test binary, found {binaries}")
    subprocess.run(cargo, cwd=REPO, env=env, check=True)
    profdata = work / "coverage.profdata"
    subprocess.run(
        [_tool("llvm-profdata"), "merge", "-sparse", *glob.glob(str(profiles / "*.profraw")),
         "-o", str(profdata)],
        check=True,
    )
    export = work / "coverage.json"
    with export.open("w", encoding="utf-8") as out:
        subprocess.run(
            [_tool("llvm-cov"), "export", "--format=text", "--skip-expansions",
             f"--instr-profile={profdata}", binaries[0]],
            check=True, stdout=out,
        )
    print(f"coverage export: {export}")
    return check(export, args.exemptions, args.only, args.verbose)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--exemptions", type=Path, action="append",
                        help=f"exemption file (repeatable; default {DEFAULT_EXEMPTIONS.relative_to(REPO)})")
    common.add_argument("--only", action="append", default=[],
                        help="restrict the report to sources under this repository path prefix")
    common.add_argument("-v", "--verbose", action="store_true", help="list exempt functions too")
    sub.add_parser("list", help="print every public function")
    p_check = sub.add_parser("check", parents=[common], help="check an llvm-cov export")
    p_check.add_argument("export", type=Path)
    p_run = sub.add_parser("run", parents=[common], help="build, run the seeds, and check")
    p_run.add_argument("--work-dir", help="directory for profiles, target and export")
    args = parser.parse_args()
    if args.command == "list":
        for fn in public_fns():
            print(f"{fn.path}:{fn.line} {fn.name}")
        return 0
    args.exemptions = args.exemptions or [DEFAULT_EXEMPTIONS]
    if args.command == "check":
        return check(args.export, args.exemptions, args.only, args.verbose)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
