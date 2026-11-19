"""Tests for sealing fuzz findings before CI uploads them.

The Fuzz workflow uploads a failing job's findings only after
scripts/fuzz/findings-envelope.sh has encrypted them to the maintainers'
recipient certificate, because artifacts of this repository are public. These
tests check the round trip, that nothing readable leaks into the sealed file,
that a modified file is refused without unpacking anything, and the
workflow's conditions for sealing and uploading.
"""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "fuzz" / "findings-envelope.sh"
WORKFLOW = REPO / ".github" / "workflows" / "fuzz.yml"
SECRET = b"CRASH-INPUT-THAT-MUST-STAY-PRIVATE"


def envelope(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(SCRIPT), *args], capture_output=True, text=True, timeout=120
    )


@unittest.skipUnless(shutil.which("bash") and shutil.which("openssl"), "bash and openssl are required")
class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.key = self.root / "key.pem"
        self.cert = self.root / "cert.pem"
        result = envelope("keygen", str(self.key), str(self.cert))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.findings = self.root / "findings"
        (self.findings / "target" / "corpus.abc123" / "target").mkdir(parents=True)
        (self.findings / "target" / "crash-1").write_bytes(SECRET)
        (self.findings / "target" / "corpus.abc123" / "target" / "entry").write_bytes(SECRET + b"2")
        (self.findings / "target.log").write_text("panicked at " + SECRET.decode())
        self.sealed = self.root / "out" / "findings.cms"

    def seal(self) -> subprocess.CompletedProcess:
        return envelope("seal", str(self.cert), str(self.findings), str(self.sealed))

    def test_keygen_keeps_the_key_private_and_refuses_to_overwrite(self):
        self.assertEqual(self.key.stat().st_mode & 0o077, 0)
        before = self.key.read_bytes()
        result = envelope("keygen", str(self.key), str(self.root / "other.pem"))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.key.read_bytes(), before)

    def test_round_trip(self):
        result = self.seal()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"SHA-256 [0-9a-f]{64}")
        self.assertNotIn(SECRET.decode(), result.stdout + result.stderr)
        sealed = self.sealed.read_bytes()
        self.assertNotIn(SECRET, sealed)
        self.assertNotIn(b"crash-1", sealed)

        opened = self.root / "opened"
        result = envelope("open", str(self.key), str(self.cert), str(self.sealed), str(opened))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((opened / "target" / "crash-1").read_bytes(), SECRET)
        self.assertEqual(
            (opened / "target" / "corpus.abc123" / "target" / "entry").read_bytes(), SECRET + b"2"
        )
        self.assertFalse(list(opened.glob(".findings.tar.gz")))

    def test_key_agreement_uses_a_sha384_kdf(self):
        self.assertEqual(self.seal().returncode, 0)
        printed = subprocess.run(
            ["openssl", "cms", "-cmsout", "-print", "-inform", "DER", "-in", str(self.sealed)],
            capture_output=True, text=True, check=True,
        ).stdout
        self.assertIn("authEnvelopedData", printed)
        self.assertIn("sha384kdf", printed)

    def test_unsafe_archive_is_refused_and_nothing_is_kept(self):
        # Anyone can encrypt to the public certificate: an archive with a
        # member outside the target must leave nothing behind.
        payload = self.root / "payload"
        payload.mkdir()
        (payload / "ok").write_bytes(b"ok")
        archive = self.root / "evil.tar.gz"
        subprocess.run(
            ["tar", "-C", str(payload), "-czf", str(archive), "ok", "--transform", "s,^ok,../escape,"],
            check=True, capture_output=True,
        )
        evil = self.root / "evil.cms"
        subprocess.run(
            ["openssl", "cms", "-encrypt", "-binary", "-aes-256-gcm", "-recip", str(self.cert),
             "-in", str(archive), "-outform", "DER", "-out", str(evil)],
            check=True, capture_output=True,
        )
        opened = self.root / "sub" / "opened"
        opened.parent.mkdir()
        result = envelope("open", str(self.key), str(self.cert), str(evil), str(opened))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(opened.exists())
        self.assertFalse((self.root / "sub" / "escape").exists())

    def test_modified_file_is_refused_and_nothing_is_unpacked(self):
        self.assertEqual(self.seal().returncode, 0)
        data = bytearray(self.sealed.read_bytes())
        for offset in (len(data) - 1, len(data) - 40):
            tampered = bytearray(data)
            tampered[offset] ^= 1
            path = self.root / f"tampered-{offset}.cms"
            path.write_bytes(tampered)
            opened = self.root / f"opened-{offset}"
            result = envelope("open", str(self.key), str(self.cert), str(path), str(opened))
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(opened.exists())

    def test_other_key_cannot_open(self):
        self.assertEqual(self.seal().returncode, 0)
        other_key, other_cert = self.root / "k2.pem", self.root / "c2.pem"
        self.assertEqual(envelope("keygen", str(other_key), str(other_cert)).returncode, 0)
        opened = self.root / "opened"
        result = envelope("open", str(other_key), str(other_cert), str(self.sealed), str(opened))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(opened.exists())

    def test_open_refuses_an_existing_directory(self):
        self.assertEqual(self.seal().returncode, 0)
        opened = self.root / "opened"
        opened.mkdir()
        result = envelope("open", str(self.key), str(self.cert), str(self.sealed), str(opened))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(opened.iterdir()), [])

    def test_seal_without_a_certificate_writes_nothing(self):
        result = envelope("seal", str(self.root / "missing.pem"), str(self.findings), str(self.sealed))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.sealed.exists())


def workflow_steps(text: str) -> list[dict[str, str]]:
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


class WorkflowFindingsTests(unittest.TestCase):
    def setUp(self):
        self.steps = workflow_steps(WORKFLOW.read_text(encoding="utf-8"))
        self.fuzz_id = next(s["id"] for s in self.steps if "scripts/fuzz/run-targets.sh" in s["body"])

    def test_findings_are_sealed_only_after_the_fuzz_step_failed(self):
        seals = [s for s in self.steps if "findings-envelope.sh seal" in s["body"]]
        self.assertEqual(len(seals), 1)
        condition = seals[0].get("if", "")
        self.assertIn("failure()", condition)
        self.assertIn(f"steps.{self.fuzz_id}.outcome == 'failure'", condition)
        self.assertIn("vars.FUZZ_FINDINGS_RECIPIENT != ''", condition)
        self.assertIn('findings-envelope.sh seal "${cert}"', seals[0]["body"])

    def test_only_the_sealed_file_is_uploaded(self):
        seal_id = next(s["id"] for s in self.steps if "findings-envelope.sh seal" in s["body"])
        uploads = [s for s in self.steps if s.get("uses", "").startswith("actions/upload-artifact")]
        self.assertEqual(len(uploads), 1)
        upload = uploads[0]
        self.assertIn(f"steps.{seal_id}.outcome == 'success'", upload.get("if", ""))
        paths = re.findall(r"^\s+path:\s*(.+)$", upload["body"], flags=re.MULTILINE)
        self.assertEqual(paths, ["${{ runner.temp }}/fuzz-findings-sealed/findings.cms"])
        self.assertIn("SEALED: ${{ runner.temp }}/fuzz-findings-sealed/findings.cms", WORKFLOW.read_text())


if __name__ == "__main__":
    unittest.main()
