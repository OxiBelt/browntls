#!/usr/bin/env python3
"""Keep Markdown prose and Rust comments within a line width.

Every Git-tracked Markdown file and every full-line `//`, `///` or `//!`
comment in a Git-tracked Rust file may be at most `LIMIT` characters wide
(Unicode code points). A longer line passes only when it holds a single word
after its indentation and list marker, such as a long URL, path or intra-doc
link, since it cannot be broken any further. Lines that cannot be wrapped without
changing what renders are not checked: YAML front matter, fenced code blocks,
table rows, headings and link reference definitions, in Markdown files and in
the Markdown of Rust comments alike. Code and trailing comments in Rust files
are left to rustfmt (`max_width`, 100 by default).
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


LIMIT = 80

# A Rust full-line comment: indentation, then `//`, `///` or `//!`. Four or
# more slashes are a plain comment, as in rustdoc.
_RUST_COMMENT = re.compile(r"^([ \t]*)(//!|///(?!/)|//)")
_MARKDOWN_QUOTE = re.compile(r"^[ ]{0,3}(?:>[ ]?)+")
_FENCE = re.compile(r"^[ ]*(`{3,}|~{3,})(.*)$")
_HEADING = re.compile(r"^[ ]{0,3}#{1,6}(?:[ \t]|$)")
_LINK_DEFINITION = re.compile(r"^[ ]{0,3}\[[^\]]+\]:")
_TABLE_ROW = re.compile(r"^[ ]*\|")
_DOC_ATTRIBUTE_FENCE = re.compile(r'\bdoc\s*=\s*"(`{3,}|~{3,})')
_LIST_MARKER = re.compile(r"^[ ]*(?:[-*+]|[0-9]{1,9}[.)])[ ]+")


@dataclass(frozen=True, order=True)
class Diagnostic:
    path: str
    line: int
    message: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.message}"


@dataclass(frozen=True)
class Line:
    """A line split into a fixed prefix and the Markdown text after it.

    `prefix` is a Rust comment's indentation and slashes, or a Markdown
    block quote marker. `checked` is false for lines exempt from the limit.
    """

    number: int
    prefix: str
    text: str
    checked: bool


class _Fences:
    """Tracks fenced code blocks, which contain no Markdown to wrap."""

    def __init__(self) -> None:
        self.open: str | None = None
        # Whether a `doc = "```"` attribute opened the block, so the comment
        # lines after the attribute continue it.
        self.from_attribute = False

    def reset(self) -> None:
        if not self.from_attribute:
            self.open = None

    def open_by_attribute(self, fence: str) -> None:
        if self.open is None:
            self.open = fence
            self.from_attribute = True

    def consume(self, text: str) -> bool:
        """Returns whether `text` is a fence line or inside a fenced block."""
        match = _FENCE.match(text)
        if self.open is None:
            if match and not (match.group(1)[0] == "`" and "`" in match.group(2)):
                self.open = match.group(1)
                return True
            return False
        if (
            match
            and match.group(1)[0] == self.open[0]
            and len(match.group(1)) >= len(self.open)
            and not match.group(2).strip()
        ):
            self.open = None
            self.from_attribute = False
        return True


def _exempt_markdown(text: str) -> bool:
    return bool(
        _HEADING.match(text) or _LINK_DEFINITION.match(text) or _TABLE_ROW.match(text)
    )


def markdown_lines(source: str) -> list[Line]:
    lines = source.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    result: list[Line] = []
    fences = _Fences()
    front_matter = bool(lines) and lines[0] == "---"
    for index, raw in enumerate(lines):
        number = index + 1
        if front_matter:
            if index > 0 and raw in ("---", "..."):
                front_matter = False
            result.append(Line(number, "", raw, False))
            continue
        quote = _MARKDOWN_QUOTE.match(raw)
        prefix = quote.group(0) if quote else ""
        text = raw[len(prefix) :]
        in_code = fences.consume(text)
        result.append(Line(number, prefix, text, not in_code and not _exempt_markdown(text)))
    return result


def rust_comment_lines(source: str) -> list[Line]:
    """Returns the full-line comments of a Rust file.

    Code blocks are tracked per comment run, since a run of comments ends
    any fence that it left open. A fence may also come from a `doc`
    attribute (`#![cfg_attr(..., doc = "```no_run")]`), whose block the
    comment lines after it continue.
    """
    result: list[Line] = []
    fences = _Fences()
    previous: str | None = None
    for index, raw in enumerate(source.split("\n")):
        match = _RUST_COMMENT.match(raw)
        if not match:
            previous = None
            attribute = _DOC_ATTRIBUTE_FENCE.search(raw)
            if attribute:
                fences.open_by_attribute(attribute.group(1))
            else:
                fences.reset()
            continue
        prefix = match.group(0)
        if prefix != previous:
            fences.reset()
        previous = prefix
        text = raw[len(prefix) :]
        in_code = fences.consume(text)
        result.append(Line(index + 1, prefix, text, not in_code and not _exempt_markdown(text)))
    return result


def too_wide(line: Line, limit: int) -> bool:
    """Whether `line` is wider than `limit` and could be wrapped."""
    if len(line.prefix) + len(line.text) <= limit:
        return False
    words = _LIST_MARKER.sub("", line.text, count=1).strip()
    return any(c.isspace() for c in words)


def check_file(name: str, source: str, limit: int = LIMIT) -> list[Diagnostic]:
    if name.endswith(".md"):
        lines = markdown_lines(source)
        what = "Markdown line"
    else:
        lines = rust_comment_lines(source)
        what = "Rust comment line"
    return [
        Diagnostic(
            name,
            line.number,
            f"{what} is {len(line.prefix + line.text)} characters wide, "
            f"more than {limit}; wrap it",
        )
        for line in lines
        if line.checked and too_wide(line, limit)
    ]


def _tracked_files(repo_root: Path) -> list[PurePosixPath]:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z", "--", "*.md", "*.rs"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return sorted(
        PurePosixPath(value.decode("utf-8", "surrogateescape"))
        for value in result.stdout.split(b"\0")
        if value
    )


def scan_repository(repo_root: Path, limit: int = LIMIT) -> tuple[list[Diagnostic], int]:
    """Returns the diagnostics and the number of files examined."""
    repo_root = repo_root.resolve()
    diagnostics: list[Diagnostic] = []
    examined = 0
    for name in _tracked_files(repo_root):
        path = repo_root / name
        if path.is_symlink() or not path.exists():
            continue
        try:
            source = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as error:
            diagnostics.append(Diagnostic(str(name), 1, f"cannot read tracked file: {error}"))
            continue
        examined += 1
        diagnostics.extend(check_file(str(name), source.replace("\r\n", "\n"), limit))
    return sorted(diagnostics), examined


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(__doc__ or "").split("\n\n", maxsplit=1)[0]
    )
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--limit", type=int, default=LIMIT)
    args = parser.parse_args(argv)
    if args.limit < 1:
        parser.error("--limit must be positive")
    diagnostics, examined = scan_repository(args.repo_root, args.limit)
    for diagnostic in diagnostics:
        print(diagnostic.render(), file=sys.stderr)
    if diagnostics:
        print(f"{len(diagnostics)} line(s) too wide", file=sys.stderr)
        return 1
    print(f"checked the line width of {examined} Markdown and Rust files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
