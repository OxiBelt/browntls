"""Regression tests: a failing fuzz input never stays in a corpus that CI caches.

The Fuzz workflow keeps corpora in the Actions cache, which pull requests
(forks included) can restore, while the input of a finding must stay private
(SECURITY.md). These tests run scripts/fuzz/run-targets.sh against a stand-in
for `cargo` that "crashes" when its corpus holds a marked entry, and check the
workflow's condition for saving the corpus.
"""

import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "fuzz.yml"
CRASH_MARKER = b"CRASH"

# Stands in for `cargo +TOOLCHAIN ...` as run-targets.sh calls it: seeds,
# builds, `fuzz run` replaying the corpus like libFuzzer (a marked entry
# crashes and is written under -artifact_prefix; otherwise a new unit is added)
# and `fuzz cmin`.
FAKE_CARGO = textwrap.dedent(
    """\
    import hashlib, os, sys
    from pathlib import Path

    args = sys.argv[1:]
    if args and args[0].startswith("+"):
        args = args[1:]
    with open(os.environ["FAKE_CARGO_LOG"], "a") as log:
        log.write(" ".join(args) + "\\n")
    if args[:1] == ["run"]:
        for target in os.environ.get("FAKE_SEED_TARGETS", "").split():
            corpus = Path("corpus") / target
            corpus.mkdir(parents=True, exist_ok=True)
            (corpus / "seed-000").write_bytes(b"seed")
        sys.exit(0)
    if args[:2] in (["fuzz", "build"], ["fuzz", "cmin"]):
        sys.exit(0)
    if args[:2] == ["fuzz", "run"]:
        corpus = Path(next(a for a in args if a.startswith("corpus/")))
        prefix = next(a for a in args if a.startswith("-artifact_prefix="))
        prefix = prefix.split("=", 1)[1]
        for entry in sorted(corpus.iterdir()):
            data = entry.read_bytes()
            if data.startswith(b"CRASH"):
                Path(prefix + "crash-" + hashlib.sha1(data).hexdigest()).write_bytes(data)
                print("==1== ERROR: libFuzzer: deadly signal")
                sys.exit(77)
        (corpus / "new-unit").write_bytes(b"new")
        print("stat::number_of_executed_units: 1")
        sys.exit(0)
    sys.exit(f"fake cargo: unexpected arguments {args}")
    """
)


def file_hashes(root: Path) -> set[str]:
    return {hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob("*") if p.is_file()}


@unittest.skipUnless(shutil.which("bash"), "bash is required")
class RunTargetsCorpusTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.repo = self.root / "repo"
        (self.repo / "scripts" / "fuzz").mkdir(parents=True)
        (self.repo / "fuzz").mkdir()
        for name in ("run-targets.sh", "plan.py"):
            shutil.copy2(REPO / "scripts" / "fuzz" / name, self.repo / "scripts" / "fuzz" / name)
        shutil.copy2(REPO / "fuzz" / "targets.toml", self.repo / "fuzz" / "targets.toml")

        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "fake_cargo.py"
        fake.write_text(FAKE_CARGO)
        cargo = bin_dir / "cargo"
        cargo.write_text(f'#!/bin/sh\nexec "{sys.executable}" -I "{fake}" "$@"\n')
        cargo.chmod(cargo.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        self.findings = self.root / "findings"
        self.log = self.root / "cargo.log"
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "FUZZ_FINDINGS": str(self.findings),
            "FUZZ_MINIMIZE": "1",
            "FAKE_CARGO_LOG": str(self.log),
        }

    def corpus(self, target: str) -> Path:
        return self.repo / "fuzz" / "corpus" / target

    def restore(self, target: str, entries: dict[str, bytes]):
        """Puts entries in a target's corpus, as restoring the cache does."""
        corpus = self.corpus(target)
        corpus.mkdir(parents=True, exist_ok=True)
        for name, data in entries.items():
            (corpus / name).write_bytes(data)

    def run_targets(self, *targets: str, seeds: str = "") -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(self.repo / "scripts" / "fuzz" / "run-targets.sh"), "1", *targets],
            env={**self.env, "FAKE_SEED_TARGETS": seeds},
            capture_output=True,
            text=True,
            timeout=120,
        )

    def published_hashes(self, result: subprocess.CompletedProcess) -> set[str]:
        return set(re.findall(r"input SHA-256: ([0-9a-f]{64})", result.stdout))

    def test_failing_corpus_entry_leaves_the_cached_corpus(self):
        crashing = CRASH_MARKER + b" restored corpus entry"
        self.restore("deframer", {"benign": b"ok", "deadbeef": crashing})
        self.restore("handshake_message", {"benign": b"ok"})

        result = self.run_targets("deframer", "handshake_message", seeds="deframer handshake_message")

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        published = self.published_hashes(result)
        self.assertEqual(published, {hashlib.sha256(crashing).hexdigest()})
        # What the workflow would cache: fuzz/corpus. Nothing in it may match
        # the hash printed to the public log.
        self.assertFalse(self.corpus("deframer").exists())
        self.assertFalse(published & file_hashes(self.repo / "fuzz" / "corpus"))
        # The clean target keeps (and minimizes) its corpus.
        self.assertTrue((self.corpus("handshake_message") / "new-unit").is_file())
        self.assertIn("fuzz cmin", self.log.read_text())
        # The failing corpus is kept with the finding, for reproduction.
        quarantined = list((self.findings / "deframer").glob("corpus.*/deframer/deadbeef"))
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(quarantined[0].read_bytes(), crashing)
        self.assertNotIn(crashing.decode(), result.stdout + result.stderr)

    def test_failing_seed_leaves_the_cached_corpus(self):
        # A seed is generated into the corpus before fuzzing; one that fails
        # must not stay there either.
        self.restore("deframer", {"seed-001": CRASH_MARKER + b" seed"})

        result = self.run_targets("deframer", seeds="deframer")

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(self.published_hashes(result))
        self.assertFalse(self.corpus("deframer").exists())

    def test_repeated_failures_keep_every_quarantined_corpus(self):
        for attempt in (b"1", b"2"):
            self.restore("deframer", {"entry": CRASH_MARKER + attempt})
            result = self.run_targets("deframer")
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(len(list((self.findings / "deframer").glob("corpus.*/deframer/entry"))), 2)

    def test_clean_run_keeps_the_corpus(self):
        self.restore("deframer", {"benign": b"ok"})

        result = self.run_targets("deframer", seeds="deframer")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            sorted(p.name for p in self.corpus("deframer").iterdir()), ["benign", "new-unit", "seed-000"]
        )
        self.assertFalse((self.findings / "deframer").exists())


def workflow_steps(text: str) -> list[dict[str, str]]:
    """The steps of the workflow as {key: value} for their top-level scalar keys."""
    steps = []
    for block in re.split(r"^\s*- name: ", text, flags=re.MULTILINE)[1:]:
        lines = block.splitlines()
        step = {"name": lines[0].strip()}
        for line in lines[1:]:
            m = re.match(r"^\s{8}([a-z-]+):\s*(.*)$", line)
            if m:
                step[m.group(1)] = m.group(2).strip()
        step["body"] = block
        steps.append(step)
    return steps


class WorkflowCorpusCacheTests(unittest.TestCase):
    def setUp(self):
        self.steps = workflow_steps(WORKFLOW.read_text(encoding="utf-8"))

    def test_corpus_is_saved_only_after_a_clean_fuzz_step(self):
        fuzz = [s for s in self.steps if "scripts/fuzz/run-targets.sh" in s["body"]]
        self.assertEqual(len(fuzz), 1)
        fuzz_id = fuzz[0].get("id")
        self.assertTrue(fuzz_id, "the step running run-targets.sh needs an id")

        saves = [
            s for s in self.steps
            if s.get("uses", "").startswith("actions/cache") and "path: fuzz/corpus" in s["body"]
            and "restore@" not in s.get("uses", "")
        ]
        self.assertTrue(saves, "no step saves fuzz/corpus")
        for save in saves:
            condition = save.get("if", "")
            self.assertRegex(condition, r"^success\(\) && ")
            self.assertIn(f"steps.{fuzz_id}.outcome == 'success'", condition)
            self.assertIn("github.event_name != 'pull_request'", condition)
            for status in ("always()", "failure()", "cancelled()", "!"):
                self.assertNotIn(status, condition.replace("!=", ""))


if __name__ == "__main__":
    unittest.main()
