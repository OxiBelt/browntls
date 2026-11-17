"""Regression coverage for the repository's documented Markdown subset."""

import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "check_markdown_links", Path(__file__).with_name("check_markdown_links.py")
)
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class MarkdownLinksTests(unittest.TestCase):
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
            subprocess.run(
                ["git", "-C", str(self.root), "add", "--", name], check=True
            )
        return path

    def messages(self):
        return [item.message for item in CHECKER.scan_repository(self.root)]

    def test_valid_links_anchors_images_and_references(self):
        self.write("docs/target.md", "# Target\n\n## Repeat\n\n## Repeat\n")
        self.write("docs/image.svg", "<svg/>\n")
        self.write("docs/space name.md", "# Spaced\n")
        self.write("README.md", """# Readme
[target](docs/target.md#target)
[duplicate](docs/target.md#repeat-1)
![image](docs/image.svg)
[encoded](docs/space%20name.md#spaced)
[reference][target]
[target]: docs/target.md#repeat
[self](#readme)
[external](https://example.invalid/not-fetched)
[email](mailto:maintainer@example.invalid)
""")
        self.assertEqual([], self.messages())

    def test_missing_and_untracked_targets_fail(self):
        self.write("README.md", "[missing](missing.md)\n[local](local.md)\n")
        self.write("local.md", "# Local\n", track=False)
        messages = self.messages()
        self.assertEqual(2, len(messages))
        self.assertTrue(all("not tracked" in message for message in messages))

    def test_missing_anchor_and_reference_fail(self):
        self.write("README.md", "# Readme\n[bad](#missing)\n[bad][undefined]\n")
        self.assertEqual(2, len(self.messages()))
        self.assertTrue(any("anchor does not exist" in m for m in self.messages()))
        self.assertTrue(any("undefined Markdown reference" in m for m in self.messages()))

    def test_duplicate_reference_fails(self):
        self.write("README.md", "[same]: #a\n[SAME]: #b\n")
        self.assertIn("duplicate Markdown reference", self.messages()[0])

    def test_inline_code_and_fenced_examples_are_ignored(self):
        self.write("README.md", """# Readme
`[missing](inline.md)`
```markdown
[missing](fenced.md)
```
~~~markdown
[missing](tilde.md)
~~~
""")
        self.assertEqual([], self.messages())

    def test_unsafe_paths_and_schemes_fail(self):
        for destination in ("../outside.md", "/tmp/local.md", "bad%xx.md",
                            "javascript:alert", "bad%00.md", "bad%5Cpath.md"):
            with self.subTest(destination=destination):
                self.write("README.md", f"[unsafe]({destination})\n")
                self.assertEqual(1, len(self.messages()))

    def test_target_symlink_cannot_escape_repository(self):
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "secret.md"
            target.write_text("# Secret\n")
            (self.root / "escape.md").symlink_to(target)
            subprocess.run(
                ["git", "-C", str(self.root), "add", "--", "escape.md"], check=True
            )
            self.write("README.md", "[escape](escape.md)\n")
            self.assertTrue(any("escapes the repository" in m for m in self.messages()))
            self.assertTrue(any("source must not be a symlink" in m for m in self.messages()))

    def test_tracked_but_deleted_file_fails(self):
        target = self.write("target.md", "# Target\n")
        self.write("README.md", "[target](target.md)\n")
        target.unlink()
        self.assertTrue(any("does not exist" in m for m in self.messages()))

    def test_setext_explicit_and_formatted_heading_anchors(self):
        self.write("README.md", """Title
=====
## A `formatted` *heading*
<a id="explicit"></a>
[title](#title)
[heading](#a-formatted-heading)
[explicit](#explicit)
""")
        self.assertEqual([], self.messages())

    def test_repeated_long_reference_is_checked_once_and_reported_briefly(self):
        uses = 4096
        destination = "/" + "x" * 65536
        self.write("README.md", f"[r]: {destination}\n" + "[x][r]\n" * uses)
        with mock.patch.object(
            CHECKER, "_local_link_problem", wraps=CHECKER._local_link_problem
        ) as problem:
            report = CHECKER.scan(self.root)
        self.assertEqual(1, problem.call_count)
        self.assertEqual(uses, report.total)
        self.assertEqual(CHECKER.MAX_DIAGNOSTICS, len(report.diagnostics))
        bound = CHECKER.MAX_REPORTED_VALUE_CHARS + 100
        for diagnostic in report.diagnostics:
            self.assertIn("must be repository-relative", diagnostic.message)
            self.assertIn("(65537 characters)", diagnostic.message)
            self.assertLess(len(diagnostic.message), bound)

    def test_long_values_are_shortened_in_every_diagnostic(self):
        long = "y" * 5000
        self.write("target.md", "# Target\n")
        self.write("README.md", "\n".join((
            f"[a](missing-{long}.md)",
            f"[b](target.md#{long})",
            f"[c][undefined-{long}]",
            f"[{long}]: #one",
            f"[{long}]: #two",
            f"[d]({long}%zz)",
        )) + "\n")
        messages = self.messages()
        expected = (
            "local link target is not tracked",
            "Markdown anchor does not exist",
            "undefined Markdown reference",
            "duplicate Markdown reference",
            "malformed percent encoding",
        )
        self.assertEqual(
            sorted(expected),
            sorted(next(e for e in expected if e in m) for m in messages),
        )
        for message in messages:
            self.assertIn("(5", message)
            self.assertLess(len(message), 2 * CHECKER.MAX_REPORTED_VALUE_CHARS + 100)

    def test_control_characters_and_backslashes_are_escaped(self):
        self.write("README.md", "[bad](/\x1b[31mred\u202e\\u{1b})\n")
        [message] = self.messages()
        self.assertNotIn("\x1b", message)
        self.assertNotIn("\u202e", message)
        self.assertIn("\\u{1b}[31mred\\u{202e}\\u{5c}u{1b}", message)

    def test_diagnostics_before_an_unreadable_link_are_kept(self):
        self.write("README.md", "[a](missing.md)\n[b](http://[::1)\n")
        messages = self.messages()
        self.assertTrue(any("not tracked" in m for m in messages))
        self.assertTrue(any("cannot read tracked Markdown" in m for m in messages))

    def test_retained_diagnostics_are_capped_and_total_is_reported(self):
        self.write("README.md", "".join(f"[m](missing-{i}.md)\n" for i in range(10)))
        report = CHECKER.scan(self.root, max_diagnostics=3)
        self.assertEqual(10, report.total)
        self.assertEqual(3, len(report.diagnostics))
        stderr = io.StringIO()
        with mock.patch.object(CHECKER, "MAX_DIAGNOSTICS", 3), \
                contextlib.redirect_stderr(stderr):
            status = CHECKER.main(["--repo-root", str(self.root)])
        self.assertEqual(1, status)
        output = stderr.getvalue()
        self.assertEqual(3, output.count("local link target is not tracked"))
        self.assertIn("7 further error(s) not shown", output)
        self.assertIn("failed with 10 error(s)", output)


if __name__ == "__main__":
    unittest.main()
