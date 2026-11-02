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


@dataclass(frozen=True, order=True)
class Diagnostic:
    path: str
    line: int
    message: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.message}"


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


def _local_link_diagnostic(
    *,
    repo_root: Path,
    source: PurePosixPath,
    line: int,
    raw_destination: str,
    tracked: set[PurePosixPath],
    anchor_cache: dict[PurePosixPath, set[str]],
) -> Diagnostic | None:
    if not raw_destination:
        return Diagnostic(str(source), line, "local link has an empty destination")
    if raw_destination.startswith("//"):
        return None
    parsed = urlsplit(raw_destination)
    if parsed.scheme or parsed.netloc:
        if parsed.scheme in {"http", "https", "mailto"}:
            return None
        return Diagnostic(
            str(source),
            line,
            f"unsupported or unsafe link scheme: {parsed.scheme or '//'}",
        )
    if MALFORMED_PERCENT_RE.search(parsed.path) or MALFORMED_PERCENT_RE.search(parsed.fragment):
        return Diagnostic(str(source), line, f"link has malformed percent encoding: {raw_destination}")

    decoded_path = unquote(parsed.path)
    fragment = unquote(parsed.fragment)
    if "\\" in decoded_path or "\0" in decoded_path:
        return Diagnostic(str(source), line, f"link uses an unsafe path: {raw_destination}")
    if decoded_path.startswith("/"):
        return Diagnostic(str(source), line, f"local link must be repository-relative: {raw_destination}")

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
        return Diagnostic(str(source), line, f"local link escapes the repository: {raw_destination}")

    if lexical not in tracked:
        return Diagnostic(
            str(source),
            line,
            f"local link target is not tracked: {lexical.as_posix()}",
        )
    if not candidate.exists():
        return Diagnostic(
            str(source),
            line,
            f"local link target does not exist: {lexical.as_posix()}",
        )
    if fragment and lexical.suffix.lower() == ".md":
        if lexical not in anchor_cache:
            anchor_cache[lexical] = _markdown_anchors(_read_text(candidate))
        if fragment not in anchor_cache[lexical]:
            return Diagnostic(
                str(source),
                line,
                f"Markdown anchor does not exist in {lexical.as_posix()}: #{fragment}",
            )
    return None


def _scan_markdown(
    *,
    repo_root: Path,
    source: PurePosixPath,
    tracked: set[PurePosixPath],
    anchor_cache: dict[PurePosixPath, set[str]],
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    candidate = repo_root / Path(source)
    if candidate.is_symlink():
        return [Diagnostic(str(source), 1, "Markdown source must not be a symlink")]
    text = _read_text(candidate)
    link_lines = _active_lines(text, strip_inline_code=True)
    reference_definitions: dict[str, str] = {}

    for line_number, line in link_lines:
        definition = REFERENCE_DEFINITION_RE.match(line)
        if not definition:
            continue
        identifier = _reference_id(definition.group(1))
        destination = definition.group(2) or definition.group(3)
        if identifier in reference_definitions:
            diagnostics.append(
                Diagnostic(str(source), line_number, f"duplicate Markdown reference: {identifier}")
            )
        else:
            reference_definitions[identifier] = destination

    for line_number, line in link_lines:
        if REFERENCE_DEFINITION_RE.match(line):
            continue
        for match in INLINE_LINK_RE.finditer(line):
            destination = _destination(match.group(1))
            if destination is None:
                diagnostics.append(
                    Diagnostic(str(source), line_number, "Markdown link has a malformed destination")
                )
                continue
            diagnostic = _local_link_diagnostic(
                repo_root=repo_root,
                source=source,
                line=line_number,
                raw_destination=destination,
                tracked=tracked,
                anchor_cache=anchor_cache,
            )
            if diagnostic:
                diagnostics.append(diagnostic)
        for match in REFERENCE_LINK_RE.finditer(line):
            identifier = _reference_id(match.group(2) or match.group(1))
            destination = reference_definitions.get(identifier)
            if destination is None:
                diagnostics.append(
                    Diagnostic(str(source), line_number, f"undefined Markdown reference: {identifier}")
                )
                continue
            diagnostic = _local_link_diagnostic(
                repo_root=repo_root,
                source=source,
                line=line_number,
                raw_destination=destination,
                tracked=tracked,
                anchor_cache=anchor_cache,
            )
            if diagnostic:
                diagnostics.append(diagnostic)

    return diagnostics


def scan_repository(repo_root: Path) -> list[Diagnostic]:
    repo_root = repo_root.resolve()
    tracked = _tracked_files(repo_root)
    diagnostics: list[Diagnostic] = []
    anchor_cache: dict[PurePosixPath, set[str]] = {}
    for source in _markdown_files_to_scan(tracked):
        try:
            diagnostics.extend(
                _scan_markdown(
                    repo_root=repo_root,
                    source=source,
                    tracked=tracked,
                    anchor_cache=anchor_cache,
                )
            )
        except (OSError, UnicodeError, ValueError) as error:
            diagnostics.append(Diagnostic(str(source), 1, f"cannot read tracked Markdown: {error}"))
    return sorted(diagnostics)


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
        diagnostics = scan_repository(args.repo_root)
        tracked = _tracked_files(args.repo_root.resolve())
        markdown_count = len(_markdown_files_to_scan(tracked))
        tracked_markdown_count = sum(path.suffix.lower() == ".md" for path in tracked)
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"documentation contract check could not start: {error}", file=sys.stderr)
        return 2
    if diagnostics:
        for diagnostic in diagnostics:
            print(diagnostic.render(), file=sys.stderr)
        print(
            f"documentation contract check failed with {len(diagnostics)} error(s)",
            file=sys.stderr,
        )
        return 1
    print(
        f"validated {markdown_count} of {tracked_markdown_count} tracked Markdown files"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
