"""Tests for sealing fuzz findings before CI uploads them.

The Fuzz workflow uploads a failing job's findings only after
scripts/fuzz/findings-envelope.sh has encrypted them to the maintainers'
recipient certificate, because artifacts of this repository are public. These
tests check the round trip, that nothing readable leaks into the sealed file,
that opened findings are accessible to their owner only, that a modified file
is refused without unpacking anything, and the workflow's conditions for
sealing and uploading.
"""

import io
import os
from pathlib import Path
import re
import stat
import shutil
import subprocess
import tarfile
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "fuzz" / "findings-envelope.sh"
WORKFLOW = REPO / ".github" / "workflows" / "fuzz.yml"
SECRET = b"CRASH-INPUT-THAT-MUST-STAY-PRIVATE"


def envelope(*args: str, umask: int = 0o022) -> subprocess.CompletedProcess:
    # A usual login umask by default, so that the script's own umask is what
    # keeps private files private.
    return subprocess.run(
        ["bash", str(SCRIPT), *args], capture_output=True, text=True, timeout=120, umask=umask
    )


def shared_modes(root: Path) -> list[str]:
    """Paths under root (root included) that grant group or other access.

    Symbolic links are skipped: their own mode is meaningless on Linux.
    """
    shared = []
    for path in [root, *root.rglob("*")]:
        mode = path.lstat().st_mode
        if not stat.S_ISLNK(mode) and mode & 0o077:
            shared.append(f"{oct(stat.S_IMODE(mode))} {path.relative_to(root.parent)}")
    return shared


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
        # The modes a runner's umask 022 gives the findings; `seal` archives
        # them, including the findings directory's own (`.`).
        for path in [self.findings, *self.findings.rglob("*")]:
            path.chmod(0o755 if path.is_dir() else 0o644)
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

    def test_opened_findings_are_private_whatever_the_umask(self):
        self.assertEqual(self.seal().returncode, 0)
        for umask in (0o022, 0o002, 0o000):
            with self.subTest(umask=oct(umask)):
                opened = self.root / f"umask-{umask:03o}" / "new" / "opened"
                result = envelope(
                    "open", str(self.key), str(self.cert), str(self.sealed), str(opened), umask=umask
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((opened / "target" / "crash-1").read_bytes(), SECRET)
                self.assertEqual(stat.S_IMODE(opened.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE((opened / "target.log").stat().st_mode), 0o600)
                self.assertEqual(shared_modes(opened), [])
                # Parent directories that `open` had to create are private too.
                self.assertEqual(shared_modes(opened.parent), [])
                self.assertEqual(shared_modes(opened.parent.parent), [])

    def encrypt(self, archive: Path, name: str) -> Path:
        out = self.root / name
        subprocess.run(
            ["openssl", "cms", "-encrypt", "-binary", "-aes-256-gcm", "-recip", str(self.cert),
             "-in", str(archive), "-outform", "DER", "-out", str(out)],
            check=True, capture_output=True,
        )
        return out

    def test_archive_modes_cannot_share_opened_findings(self):
        # Anyone can encrypt to the public certificate, with any modes: even
        # world-writable entries and a caller umask of 000 must give private
        # files, and a symbolic link must not make `open` change the mode of
        # what it points to.
        outside = self.root / "outside"
        outside.write_bytes(b"not part of the findings")
        outside.chmod(0o644)
        payload = self.root / "payload"
        (payload / "dir").mkdir(parents=True)
        (payload / "dir" / "file").write_bytes(SECRET)
        (payload / "script").write_bytes(b"#!/bin/sh\n")
        os.symlink(outside, payload / "link")
        for path, mode in ((payload, 0o777), (payload / "dir", 0o777),
                           (payload / "dir" / "file", 0o666), (payload / "script", 0o777)):
            path.chmod(mode)
        archive = self.root / "modes.tar.gz"
        subprocess.run(["tar", "-C", str(payload), "-czf", str(archive), "."],
                       check=True, capture_output=True)
        sealed = self.encrypt(archive, "modes.cms")
        opened = self.root / "opened"
        result = envelope("open", str(self.key), str(self.cert), str(sealed), str(opened), umask=0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((opened / "dir" / "file").read_bytes(), SECRET)
        self.assertTrue((opened / "link").is_symlink())
        self.assertEqual(shared_modes(opened), [])
        self.assertEqual(stat.S_IMODE((opened / "script").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o644)

    def locked_archive(self, name: str, dirs_first: bool, extra: tuple[str, ...] = ()) -> Path:
        """Seals an archive whose directories, `.` included, record modes
        without owner access, built with tarfile so that no runner needs to
        read such directories. `extra` adds regular files."""
        archive = self.root / f"{name}.tar.gz"
        dirs = []
        for member, mode in ((".", 0o000), ("./locked", 0o000),
                             ("./locked/inner", 0o000), ("./empty", 0o300)):
            info = tarfile.TarInfo(member)
            info.type, info.mode = tarfile.DIRTYPE, mode
            dirs.append(info)
        with tarfile.open(archive, "w:gz") as tar:
            if dirs_first:
                for info in dirs:
                    tar.addfile(info)
            for member in ("./locked/inner/secret", *extra):
                info = tarfile.TarInfo(member)
                info.size, info.mode = len(SECRET), 0o000
                tar.addfile(info, io.BytesIO(SECRET))
            if not dirs_first:
                for info in reversed(dirs):
                    tar.addfile(info)
        return self.encrypt(archive, f"{name}.cms")

    def test_archive_without_owner_access_opens_completely(self):
        # Modes without owner access recorded after the entries below them
        # (the output directory's own included) must neither stop `open` nor
        # leave the decrypted archive behind.
        opened = self.root / "opened"
        result = envelope("open", str(self.key), str(self.cert), str(self.locked_archive("locked", dirs_first=False)),
                          str(opened))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((opened / "locked" / "inner" / "secret").read_bytes(), SECRET)
        self.assertFalse((opened / ".findings.tar.gz").exists())
        self.assertEqual(shared_modes(opened), [])
        for path in (opened, opened / "locked", opened / "locked" / "inner", opened / "empty"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700, path)
        self.assertEqual(stat.S_IMODE((opened / "locked" / "inner" / "secret").stat().st_mode), 0o600)

    def test_refused_archive_without_owner_access_leaves_nothing(self):
        opened = self.root / "sub" / "opened"
        # GNU tar run by a non-root user cannot unpack below a mode 000
        # directory it made itself; the archive is refused either way.
        sealed = self.locked_archive("locked-escape", dirs_first=True, extra=("../escape",))
        result = envelope("open", str(self.key), str(self.cert), str(sealed), str(opened))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nothing was kept", result.stderr)
        self.assertFalse(opened.exists())
        self.assertFalse((self.root / "sub" / "escape").exists())

    def test_archive_cannot_replace_the_decrypted_file(self):
        archive = self.root / "clash.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for member in ("./.findings.tar.gz", "./sub/.findings.tar.gz"):
                info = tarfile.TarInfo(member)
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
            info = tarfile.TarInfo("./crash")
            info.size = len(SECRET)
            tar.addfile(info, io.BytesIO(SECRET))
        opened = self.root / "opened"
        result = envelope("open", str(self.key), str(self.cert), str(self.encrypt(archive, "clash.cms")),
                          str(opened))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((opened / "crash").read_bytes(), SECRET)
        self.assertFalse((opened / ".findings.tar.gz").exists())

    def test_open_refuses_a_name_that_resolves_to_an_existing_directory(self):
        self.assertEqual(self.seal().returncode, 0)
        existing = self.root / "existing"
        (existing / "keep").mkdir(parents=True)
        (existing / "keep" / "f").write_bytes(b"mine")
        (existing / "keep").chmod(0o755)
        (existing / "keep" / "f").chmod(0o644)
        target = f"{existing}/new/.."
        result = envelope("open", str(self.key), str(self.cert), str(self.sealed), target)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((existing / "target.log").exists())
        self.assertEqual(stat.S_IMODE((existing / "keep").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((existing / "keep" / "f").stat().st_mode), 0o644)

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
        evil = self.encrypt(archive, "evil.cms")
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
