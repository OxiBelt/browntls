"""Regression coverage for the Markdown and Rust comment line width check."""

import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "check_line_width", Path(__file__).with_name("check_line_width.py")
)
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)

LONG = ("word " * 20).rstrip()  # 99 characters with spaces throughout
TOKEN = "x" * 100  # 100 characters without whitespace


def lines(name, source, limit=20):
    return [d.line for d in CHECKER.check_file(name, source, limit)]


class MarkdownTests(unittest.TestCase):
    def test_prose_at_the_limit_passes_and_one_more_fails(self):
        self.assertEqual([], lines("a.md", "a" * 9 + " " + "b" * 10 + "\n"))
        self.assertEqual([1], lines("a.md", "a" * 9 + " " + "b" * 11 + "\n"))

    def test_width_counts_characters_not_bytes(self):
        self.assertEqual([], lines("a.md", "§" * 9 + " " + "é" * 10 + "\n"))

    def test_single_word_lines_pass(self):
        self.assertEqual([], lines("a.md", TOKEN + "\n"))
        self.assertEqual([], lines("a.md", "- " + TOKEN + "\n"))
        self.assertEqual([], lines("a.md", "  12. " + TOKEN + "\n"))
        self.assertEqual([], lines("a.md", "> " + TOKEN + "\n"))
        self.assertEqual([1], lines("a.md", "see " + TOKEN + "\n"))
        self.assertEqual([1], lines("a.md", TOKEN + " end\n"))

    def test_lines_that_cannot_wrap_are_exempt(self):
        source = "\n".join(
            [
                "# " + LONG,
                "| " + LONG + " |",
                "  | " + LONG + " |",
                "[label]: https://example.com/ " + LONG,
                "",
            ]
        )
        self.assertEqual([], lines("a.md", source))

    def test_fenced_code_blocks_are_exempt(self):
        source = "\n".join(
            ["```sh", LONG, "````", LONG, "  ~~~~", LONG, "```", LONG, "  ~~~~", LONG, ""]
        )
        # A longer fence of the same character closes a block; a fence of the
        # other character inside it does not.
        self.assertEqual([4, 10], lines("a.md", source))

    def test_inline_backticks_do_not_open_a_fence(self):
        self.assertEqual([2], lines("a.md", "```a`b```\n" + LONG + "\n"))

    def test_front_matter_is_exempt(self):
        source = "---\ndescription: " + LONG + "\n---\n" + LONG + "\n"
        self.assertEqual([4], lines("a.md", source))

    def test_a_thematic_break_later_is_not_front_matter(self):
        source = "text\n---\n" + LONG + "\n---\n"
        self.assertEqual([3], lines("a.md", source))

    def test_block_quote_marker_counts_towards_the_width(self):
        self.assertEqual([1], lines("a.md", "> " + "a" * 9 + " " + "b" * 9 + "\n"))


class RustTests(unittest.TestCase):
    def test_comment_kinds(self):
        source = "\n".join(
            ["// " + LONG, "/// " + LONG, "//! " + LONG, "    //// " + LONG, ""]
        )
        self.assertEqual([1, 2, 3, 4], lines("a.rs", source))

    def test_code_and_trailing_comments_are_left_to_rustfmt(self):
        source = "let x = 1; // " + LONG + '\nlet s = "' + LONG + '";\n'
        self.assertEqual([], lines("a.rs", source))

    def test_single_word_comments_pass(self):
        source = "/// " + TOKEN + "\n/// [`a`]: " + TOKEN + "\n    //! - " + TOKEN + "\n"
        self.assertEqual([], lines("a.rs", source))

    def test_tables_headings_and_link_definitions_are_exempt(self):
        source = "\n".join(
            ["//! | " + LONG + " |", "/// # " + LONG, "/// [`x`]: " + LONG, ""]
        )
        self.assertEqual([], lines("a.rs", source))

    def test_doc_code_blocks_are_exempt_and_end_with_the_comment(self):
        source = "\n".join(
            [
                "/// ```",
                "/// " + LONG,
                "fn f() {}",
                "/// " + LONG,
                "//! ```text",
                "//! " + LONG,
                "/// " + LONG,
                "",
            ]
        )
        # The comment kind changes at line 7, which ends the `//!` block.
        self.assertEqual([4, 7], lines("a.rs", source))

    def test_doc_attribute_opens_a_code_block(self):
        source = "\n".join(
            [
                '#![cfg_attr(feature = "std", doc = "```no_run")]',
                '#![cfg_attr(',
                '    not(feature = "std"),',
                '    doc = "```ignore"',
                ')]',
                "//! " + LONG,
                "//! ```",
                "//! " + LONG,
                "",
            ]
        )
        self.assertEqual([8], lines("a.rs", source))


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)

    def write(self, name, text, *, track=True):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        if track:
            subprocess.run(["git", "-C", str(self.root), "add", "--", name], check=True)

    def test_scans_tracked_markdown_and_rust_files_only(self):
        self.write("docs/a.md", LONG + "\n")
        self.write("src/b.rs", "// " + LONG + "\n")
        self.write("c.txt", LONG + "\n")
        self.write("untracked.md", LONG + "\n", track=False)
        diagnostics, examined = CHECKER.scan_repository(self.root, 80)
        self.assertEqual(2, examined)
        self.assertEqual(
            [
                "docs/a.md:1: Markdown line is 99 characters wide, more than 80; "
                "wrap it",
                "src/b.rs:1: Rust comment line is 102 characters wide, more than "
                "80; wrap it",
            ],
            [d.render() for d in diagnostics],
        )

    def test_main_reports_success_and_failure(self):
        self.write("a.md", "short\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(0, CHECKER.main(["--repo-root", str(self.root)]))
        self.assertIn("checked the line width of 1", out.getvalue())
        self.write("b.md", LONG + "\n")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(1, CHECKER.main(["--repo-root", str(self.root)]))
        self.assertIn("b.md:1:", err.getvalue())
        self.assertIn("1 line(s) too wide", err.getvalue())

    def test_crlf_line_endings_are_not_counted(self):
        self.write("a.md", ("a" * 80 + "\r\n") * 2)
        self.assertEqual([], CHECKER.scan_repository(self.root, 80)[0])


if __name__ == "__main__":
    unittest.main()
