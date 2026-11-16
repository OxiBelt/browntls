#!/usr/bin/env python3
"""Enforce the line limit of Git-tracked Rust source files.

Every tracked `.rs` file may hold at most `LIMIT` lines. The limit covers
library code, tests, fuzz harnesses and generated tables alike, without
exceptions; a file that grows past it is split by responsibility instead.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


LIMIT = 1000


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


def scan_repository(repo_root: Path, limit: int = LIMIT) -> tuple[list[Diagnostic], int]:
    """Returns the diagnostics and the number of Rust files examined."""
    repo_root = repo_root.resolve()
    diagnostics: list[Diagnostic] = []
    examined = 0
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
        if lines > limit:
            diagnostics.append(
                Diagnostic(
                    str(name),
                    limit + 1,
                    f"{lines} lines exceed the limit of {limit}; split the file",
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
