#!/usr/bin/env python3
"""Validate local links and anchors in Git-tracked Markdown files.

Adapted from OxiBelt tests/scripts/check-markdown-links.py (Apache-2.0).
Upstream revision: 1ad6ab1a65a986b7242550c6baa72384b7170e40.
Copyright 2026 OxiBelt contributors.
Modified for browntls: remove product-specific contracts and exemptions.
This intentionally supports a documented Markdown subset, not full CommonMark.
"""

from __future__ import annotations

import argparse
import html
import posixpath
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit


FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
INLINE_CODE_RE = re.compile(r"(`+)(.+?)\1")
INLINE_LINK_RE = re.compile(r"!?\[[^\]\n]*\]\(([^)\n]*)\)")
REFERENCE_DEFINITION_RE = re.compile(
    r"^\s{0,3}\[([^\]\n]+)\]:\s*(?:<([^>\n]+)>|(\S+))"
)
REFERENCE_LINK_RE = re.compile(r"!?\[([^\]\n]+)\]\[([^\]\n]*)\]")
ATX_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$")
SETEXT_HEADING_RE = re.compile(r"^\s{0,3}(?:=+|-+)\s*$")
EXPLICIT_ANCHOR_RE = re.compile(
    r"<(?:a|[A-Za-z][A-Za-z0-9:-]*)\b[^>]*\b(?:id|name)\s*=\s*"
    r"(?:\"([^\"]+)\"|'([^']+)')[^>]*>",
    re.IGNORECASE,
)
MALFORMED_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")

# Markdown under check is contributor-controlled, so every value copied from it
# into a diagnostic is shortened, and only a bounded number of diagnostics is
# kept. Memory and output then stay proportional to the input, not to the
# product of a long value and the number of times it is referenced.
MAX_REPORTED_VALUE_CHARS = 200
MAX_DIAGNOSTICS = 1000


@dataclass(frozen=True, order=True)
class Diagnostic:
    path: str
    line: int
    message: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.message}"


@dataclass(frozen=True)
class ScanReport:
    """Retained diagnostics, sorted, and the total number found."""

    diagnostics: list[Diagnostic]
    total: int


class _DiagnosticSink:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.retained: list[Diagnostic] = []
        self.total = 0

    @property
    def full(self) -> bool:
        return len(self.retained) >= self.limit

    def add(self, path: PurePosixPath, line: int, message: str) -> None:
        self.total += 1
        if not self.full:
            self.retained.append(Diagnostic(_excerpt(str(path)), line, message))


def _excerpt(value: str) -> str:
    """Return printable, bounded text for quoting `value` in a diagnostic.

    At most MAX_REPORTED_VALUE_CHARS characters of `value` are quoted. A
    backslash or non-printable character is written as an escape such as
    `\\u{1b}`, so the result is at most about ten times that length.
    """
    shown = value[:MAX_REPORTED_VALUE_CHARS]
    escaped = "".join(
        character
        if character.isprintable() and character != "\\"
        else f"\\u{{{ord(character):x}}}"
        for character in shown
    )
    if len(value) > MAX_REPORTED_VALUE_CHARS:
        escaped += f"... ({len(value)} characters)"
    return escaped


def _tracked_files(repo_root: Path) -> set[PurePosixPath]:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z", "--"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return {
        PurePosixPath(value.decode("utf-8", "surrogateescape"))
        for value in result.stdout.split(b"\0")
        if value
    }


def _markdown_files_to_scan(tracked: set[PurePosixPath]) -> tuple[PurePosixPath, ...]:
    return tuple(sorted(path for path in tracked if path.suffix.lower() == ".md"))


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _active_lines(text: str, *, strip_inline_code: bool) -> list[tuple[int, str]]:
    active: list[tuple[int, str]] = []
    fence_character: str | None = None
    fence_length = 0
    for line_number, line in enumerate(text.splitlines(), 1):
        fence = FENCE_RE.match(line)
        if fence:
            marker = fence.group(1)
            if fence_character is None:
                fence_character = marker[0]
                fence_length = len(marker)
            elif marker[0] == fence_character and len(marker) >= fence_length:
                fence_character = None
                fence_length = 0
            active.append((line_number, ""))
            continue
        if fence_character is not None:
            active.append((line_number, ""))
            continue
        if strip_inline_code:
            line = INLINE_CODE_RE.sub("", line)
        active.append((line_number, line))
    return active


def _reference_id(value: str) -> str:
    return " ".join(value.split()).casefold()


def _destination(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    if value.startswith("<"):
        closing = value.find(">")
        return value[1:closing] if closing > 0 else None
    return value.split(maxsplit=1)[0]


def _github_slug(value: str) -> str:
    value = html.unescape(re.sub(r"<[^>]+>", "", value))
    value = value.replace("`", "").replace("*", "").replace("~", "")
    value = value.strip().lower()
    slug = "".join(
        character
        for character in value
        if character.isalnum() or character.isspace() or character in "-_"
    )
    return re.sub(r"\s", "-", slug)


def _markdown_anchors(text: str) -> set[str]:
    lines = _active_lines(text, strip_inline_code=False)
    anchors: set[str] = set()
    counts: dict[str, int] = {}

    def add_heading(value: str) -> None:
        slug = _github_slug(value)
        duplicate = counts.get(slug, 0)
        counts[slug] = duplicate + 1
        anchors.add(slug if duplicate == 0 else f"{slug}-{duplicate}")

    previous = ""
    for _line_number, line in lines:
        for match in EXPLICIT_ANCHOR_RE.finditer(line):
            anchors.add(html.unescape(match.group(1) or match.group(2)))
        heading = ATX_HEADING_RE.match(line)
        if heading:
            add_heading(heading.group(1))
        elif previous.strip() and SETEXT_HEADING_RE.match(line):
            add_heading(previous.strip())
        previous = line
    return anchors


def _local_link_problem(
    *,
    repo_root: Path,
    source: PurePosixPath,
    raw_destination: str,
    tracked: set[PurePosixPath],
    anchor_cache: dict[PurePosixPath, set[str]],
) -> str | None:
    """Return a diagnostic message for a link destination, or None if valid."""
    shown = _excerpt(raw_destination)
    if not raw_destination:
        return "local link has an empty destination"
    if raw_destination.startswith("//"):
        return None
    parsed = urlsplit(raw_destination)
    if parsed.scheme or parsed.netloc:
        if parsed.scheme in {"http", "https", "mailto"}:
            return None
        return f"unsupported or unsafe link scheme: {_excerpt(parsed.scheme or '//')}"
    if MALFORMED_PERCENT_RE.search(parsed.path) or MALFORMED_PERCENT_RE.search(parsed.fragment):
        return f"link has malformed percent encoding: {shown}"

    decoded_path = unquote(parsed.path)
    fragment = unquote(parsed.fragment)
    if "\\" in decoded_path or "\0" in decoded_path:
        return f"link uses an unsafe path: {shown}"
    if decoded_path.startswith("/"):
        return f"local link must be repository-relative: {shown}"

    lexical = (
        PurePosixPath(posixpath.normpath((source.parent / PurePosixPath(decoded_path)).as_posix()))
        if decoded_path
        else source
    )
    candidate = repo_root / Path(lexical)
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(repo_root.resolve())
    except (OSError, RuntimeError, ValueError):
        return f"local link escapes the repository: {shown}"

    if lexical not in tracked:
        return f"local link target is not tracked: {_excerpt(lexical.as_posix())}"
    if not candidate.exists():
        return f"local link target does not exist: {_excerpt(lexical.as_posix())}"
    if fragment and lexical.suffix.lower() == ".md":
        if lexical not in anchor_cache:
            anchor_cache[lexical] = _markdown_anchors(_read_text(candidate))
        if fragment not in anchor_cache[lexical]:
            return (
                f"Markdown anchor does not exist in {_excerpt(lexical.as_posix())}: "
                f"#{_excerpt(fragment)}"
            )
    return None


def _scan_markdown(
    *,
    repo_root: Path,
    source: PurePosixPath,
    tracked: set[PurePosixPath],
    anchor_cache: dict[PurePosixPath, set[str]],
    sink: _DiagnosticSink,
) -> None:
    candidate = repo_root / Path(source)
    if candidate.is_symlink():
        sink.add(source, 1, "Markdown source must not be a symlink")
        return
    text = _read_text(candidate)
    link_lines = _active_lines(text, strip_inline_code=True)
    reference_definitions: dict[str, str] = {}
    # A destination is checked once per source file, however often it is used.
    # Once no further diagnostic can be retained, only the fact that a
    # destination has a problem is remembered, not its message.
    checked: dict[str, str | None] = {}

    def check_destination(line_number: int, destination: str) -> None:
        if destination not in checked:
            problem = _local_link_problem(
                repo_root=repo_root,
                source=source,
                raw_destination=destination,
                tracked=tracked,
                anchor_cache=anchor_cache,
            )
            if problem is not None and sink.full:
                problem = ""
            checked[destination] = problem
        problem = checked[destination]
        if problem is not None:
            sink.add(source, line_number, problem)

    for line_number, line in link_lines:
        definition = REFERENCE_DEFINITION_RE.match(line)
        if not definition:
            continue
        identifier = _reference_id(definition.group(1))
        destination = definition.group(2) or definition.group(3)
        if identifier in reference_definitions:
            sink.add(source, line_number, f"duplicate Markdown reference: {_excerpt(identifier)}")
        else:
            reference_definitions[identifier] = destination

    for line_number, line in link_lines:
        if REFERENCE_DEFINITION_RE.match(line):
            continue
        for match in INLINE_LINK_RE.finditer(line):
            destination = _destination(match.group(1))
            if destination is None:
                sink.add(source, line_number, "Markdown link has a malformed destination")
                continue
            check_destination(line_number, destination)
        for match in REFERENCE_LINK_RE.finditer(line):
            identifier = _reference_id(match.group(2) or match.group(1))
            destination = reference_definitions.get(identifier)
            if destination is None:
                sink.add(
                    source, line_number, f"undefined Markdown reference: {_excerpt(identifier)}"
                )
                continue
            check_destination(line_number, destination)


def scan(repo_root: Path, *, max_diagnostics: int | None = None) -> ScanReport:
    """Scan tracked Markdown.

    The first `max_diagnostics` diagnostics found (default MAX_DIAGNOSTICS)
    are retained and returned sorted; `total` counts every diagnostic.
    """
    repo_root = repo_root.resolve()
    tracked = _tracked_files(repo_root)
    sink = _DiagnosticSink(MAX_DIAGNOSTICS if max_diagnostics is None else max_diagnostics)
    anchor_cache: dict[PurePosixPath, set[str]] = {}
    for source in _markdown_files_to_scan(tracked):
        try:
            _scan_markdown(
                repo_root=repo_root,
                source=source,
                tracked=tracked,
                anchor_cache=anchor_cache,
                sink=sink,
            )
        except (OSError, UnicodeError, ValueError) as error:
            sink.add(source, 1, f"cannot read tracked Markdown: {_excerpt(str(error))}")
    return ScanReport(sorted(sink.retained), sink.total)


def scan_repository(repo_root: Path) -> list[Diagnostic]:
    """Return the retained diagnostics; see `scan()` for the total count."""
    return scan(repo_root).diagnostics


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root (defaults to the script's repository)",
    )
    args = parser.parse_args(argv)
    try:
        report = scan(args.repo_root)
        tracked = _tracked_files(args.repo_root.resolve())
        markdown_count = len(_markdown_files_to_scan(tracked))
        tracked_markdown_count = sum(path.suffix.lower() == ".md" for path in tracked)
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"documentation contract check could not start: {error}", file=sys.stderr)
        return 2
    if report.total:
        for diagnostic in report.diagnostics:
            print(diagnostic.render(), file=sys.stderr)
        omitted = report.total - len(report.diagnostics)
        if omitted:
            print(f"{omitted} further error(s) not shown", file=sys.stderr)
        print(
            f"documentation contract check failed with {report.total} error(s)",
            file=sys.stderr,
        )
        return 1
    print(
        f"validated {markdown_count} of {tracked_markdown_count} tracked Markdown files"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
