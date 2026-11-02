"""Regression coverage for the repository's documented Markdown subset."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


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


if __name__ == "__main__":
    unittest.main()
