"""Regression coverage for the Rust line limit check."""

import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "check_rust_line_count", Path(__file__).with_name("check_rust_line_count.py")
)
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class RustLineCountTests(unittest.TestCase):
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

    def messages(self, limit=10):
        diagnostics, _ = CHECKER.scan_repository(self.root, limit)
        return [item.render() for item in diagnostics]

    def test_counts_lines_like_wc_plus_an_unterminated_last_line(self):
        self.assertEqual(0, CHECKER.count_lines(b""))
        self.assertEqual(1, CHECKER.count_lines(b"\n"))
        self.assertEqual(2, CHECKER.count_lines(b"a\nb\n"))
        self.assertEqual(2, CHECKER.count_lines(b"a\nb"))
        self.assertEqual(2, CHECKER.count_lines(b"a\r\nb\r\n"))

    def test_file_at_the_limit_passes_and_one_line_more_fails(self):
        self.write("src/fits.rs", "x\n" * 10)
        self.assertEqual([], self.messages())
        self.write("src/deep/large.rs", "x\n" * 11)
        self.assertEqual(
            ["src/deep/large.rs:11: 11 lines exceed the limit of 10; split the file"],
            self.messages(),
        )

    def test_reports_the_number_of_files_examined(self):
        self.write("a.rs", "x\n")
        self.write("b/c.rs", "x\n")
        self.write("notes.md", "x\n" * 50)
        self.assertEqual(([], 2), CHECKER.scan_repository(self.root, 10))

    def test_only_tracked_rust_files_count(self):
        self.write("untracked.rs", "x\n" * 50, track=False)
        self.write("data.txt", "x\n" * 50)
        self.write("rs", "x\n" * 50)
        self.assertEqual([], self.messages())

    def test_tracked_but_deleted_file_and_symlink_are_skipped(self):
        self.write("gone.rs", "x\n" * 50).unlink()
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "large.rs"
            target.write_text("x\n" * 50)
            (self.root / "link.rs").symlink_to(target)
            subprocess.run(
                ["git", "-C", str(self.root), "add", "--", "link.rs"], check=True
            )
            self.assertEqual(([], 0), CHECKER.scan_repository(self.root, 10))

    def test_command_line_reports_failures_and_success(self):
        self.write("a.rs", "x\n" * CHECKER.LIMIT)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = CHECKER.main(["--repo-root", str(self.root)])
        self.assertEqual(0, status)
        self.assertIn("validated 1 tracked Rust files", output.getvalue())
        self.write("b.rs", "x\n" * (CHECKER.LIMIT + 1))
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            status = CHECKER.main(["--repo-root", str(self.root)])
        self.assertEqual(1, status)
        self.assertIn(f"b.rs:{CHECKER.LIMIT + 1}: ", errors.getvalue())
        self.assertIn("failed with 1 error(s)", errors.getvalue())

    def test_command_line_reports_a_directory_that_is_no_repository(self):
        with tempfile.TemporaryDirectory() as outside:
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                status = CHECKER.main(["--repo-root", outside])
        self.assertEqual(2, status)
        self.assertIn("could not start", errors.getvalue())

    def test_repository_fits_the_limit(self):
        repo_root = Path(__file__).resolve().parents[2]
        if not (repo_root / ".git").exists():
            self.skipTest("not running from a Git checkout")
        diagnostics, examined = CHECKER.scan_repository(repo_root)
        self.assertEqual([], [item.render() for item in diagnostics])
        self.assertGreater(examined, 0)


if __name__ == "__main__":
    unittest.main()
