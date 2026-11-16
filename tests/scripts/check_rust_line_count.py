#!/usr/bin/env python3
"""Enforce the line limit of Git-tracked Rust source files.

Every tracked `.rs` file may hold at most `LIMIT` lines. The limit covers
library code, tests, fuzz harnesses and generated tables alike; a file that
grows past it is split by responsibility instead.

Files that were larger when the limit was introduced are listed in
`rust_line_count_baseline.txt` next to this script, one `<lines> <path>` entry
per line. A listed file may not grow beyond its recorded size, and an entry
whose file is gone or fits the limit must be removed, so the list only shrinks.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


LIMIT = 1000
BASELINE_NAME = "tests/scripts/rust_line_count_baseline.txt"


@dataclass(frozen=True, order=True)
class Diagnostic:
    path: str
    line: int
    message: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.message}"


def _tracked_rust_files(repo_root: Path) -> list[PurePosixPath]:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z", "--", "*.rs"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return sorted(
        PurePosixPath(value.decode("utf-8", "surrogateescape"))
        for value in result.stdout.split(b"\0")
        if value
    )


def count_lines(data: bytes) -> int:
    """Counts lines as `wc -l` does, plus a final line without a newline."""
    return data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)


def _read_baseline(
    repo_root: Path, diagnostics: list[Diagnostic]
) -> dict[PurePosixPath, tuple[int, int]]:
    """Returns `path -> (recorded lines, baseline line number)`."""
    entries: dict[PurePosixPath, tuple[int, int]] = {}
    path = repo_root / BASELINE_NAME
    if not path.exists():
        return entries
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        fields = text.split(maxsplit=1)
        if len(fields) != 2 or not fields[0].isdecimal():
            diagnostics.append(
                Diagnostic(BASELINE_NAME, number, "expected `<lines> <path>`")
            )
            continue
        name = PurePosixPath(fields[1])
        if name in entries:
            diagnostics.append(
                Diagnostic(BASELINE_NAME, number, f"duplicate entry for {name}")
            )
            continue
        entries[name] = (int(fields[0]), number)
    return entries


def scan_repository(repo_root: Path, limit: int = LIMIT) -> tuple[list[Diagnostic], int]:
    """Returns the diagnostics and the number of Rust files examined."""
    repo_root = repo_root.resolve()
    diagnostics: list[Diagnostic] = []
    baseline = _read_baseline(repo_root, diagnostics)
    examined = 0
    seen: set[PurePosixPath] = set()
    for name in _tracked_rust_files(repo_root):
        path = repo_root / name
        if path.is_symlink() or not path.exists():
            # A symlink has no lines of its own, and a file deleted in the
            # working tree is about to leave the index.
            continue
        try:
            lines = count_lines(path.read_bytes())
        except OSError as error:
            diagnostics.append(Diagnostic(str(name), 1, f"cannot read tracked Rust file: {error}"))
            continue
        examined += 1
        seen.add(name)
        recorded = baseline.get(name)
        if recorded is None:
            if lines > limit:
                diagnostics.append(
                    Diagnostic(
                        str(name),
                        limit + 1,
                        f"{lines} lines exceed the limit of {limit}; split the file",
                    )
                )
            continue
        allowed, number = recorded
        if lines <= limit:
            diagnostics.append(
                Diagnostic(
                    BASELINE_NAME,
                    number,
                    f"{name} now has {lines} lines and fits the limit of {limit}; "
                    "remove the entry",
                )
            )
        elif lines > allowed:
            diagnostics.append(
                Diagnostic(
                    str(name),
                    allowed + 1,
                    f"{lines} lines exceed the {allowed} recorded in the baseline; "
                    "split the file instead of growing it",
                )
            )
        elif lines < allowed:
            diagnostics.append(
                Diagnostic(
                    BASELINE_NAME,
                    number,
                    f"{name} shrank to {lines} lines; lower the recorded {allowed}",
                )
            )
    for name, (_, number) in baseline.items():
        if name not in seen:
            diagnostics.append(
                Diagnostic(
                    BASELINE_NAME,
                    number,
                    f"{name} is not a tracked Rust file; remove the entry",
                )
            )
    return sorted(diagnostics), examined


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(__doc__ or "").split("\n\n", maxsplit=1)[0]
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root (defaults to the script's repository)",
    )
    args = parser.parse_args(argv)
    try:
        diagnostics, examined = scan_repository(args.repo_root)
    except (OSError, UnicodeError, subprocess.CalledProcessError) as error:
        print(f"Rust line count check could not start: {error}", file=sys.stderr)
        return 2
    if diagnostics:
        for diagnostic in diagnostics:
            print(diagnostic.render(), file=sys.stderr)
        print(
            f"Rust line count check failed with {len(diagnostics)} error(s)",
            file=sys.stderr,
        )
        return 1
    print(f"validated {examined} tracked Rust files against the {LIMIT}-line limit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
