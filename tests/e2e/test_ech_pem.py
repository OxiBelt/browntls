import base64
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import ech_pem


def config(kem_id, version=0xFE0D):
    # Only the ECHConfigList envelope and KEM are interpreted by the harness.
    body = struct.pack("!BH", 7, kem_id) + b"config contents"
    return base64.b64encode(struct.pack("!HHH", 4 + len(body), version, len(body)) + body)


class EchPemTests(unittest.TestCase):
    def test_cleanup_attempts_all_removals_and_reports_remaining_credentials(self):
        resources = {"container": {"id1": "fixture", "id2": "peer"},
                     "volume": {"key-volume": "key-volume"}, "network": {"id3": "network"}}
        removals = []

        def docker(kind, action, *args, **kwargs):
            if action == "ls":
                self.assertIn("label=owner=token", args)
                output = "\n".join(f"{identifier} {name}" for identifier, name in resources[kind].items())
                return subprocess.CompletedProcess([], 0, stdout=output)
            identifier = args[-1]
            removals.append((kind, identifier))
            if identifier == "id1":
                raise ech_pem.e2e.DockerError("container removal denied")
            if identifier != "key-volume":
                del resources[kind][identifier]

        with patch.object(ech_pem.e2e, "docker", side_effect=docker):
            problems = ech_pem.cleanup_run("run", "owner=token", ("key-volume",))
        self.assertEqual(removals, [("container", "id1"), ("container", "id2"),
                                    ("volume", "key-volume"), ("network", "id3")])
        self.assertEqual(problems, ["Docker container fixture: container removal denied",
                                    "Docker volume key-volume: still present after removal"])

    def test_cleanup_ignores_remove_race_only_after_confirming_absence(self):
        def docker(kind, action, *args, **kwargs):
            if action == "rm":
                resources.clear()
                raise ech_pem.e2e.DockerError("no such container")
            output = "id1 fixture\n" if kind == "container" and resources else ""
            return subprocess.CompletedProcess([], 0, stdout=output)

        resources = {"id1"}
        with patch.object(ech_pem.e2e, "docker", side_effect=docker):
            self.assertEqual(ech_pem.cleanup_run("run", "owner=token", ()), [])

    def test_existing_unowned_volume_is_never_mounted_or_removed(self):
        def docker(kind, action, *args, **kwargs):
            if (kind, action) == ("network", "create"):
                return subprocess.CompletedProcess([], 0, stdout="network-id\n")
            return subprocess.CompletedProcess([], 0, stdout="")

        with (patch.object(ech_pem.e2e, "docker", side_effect=docker) as command,
              patch.object(ech_pem.secrets, "token_hex", side_effect=("name", "ownership"))):
            with self.assertRaisesRegex(RuntimeError, "browntls-ech-name-server lacks"):
                ech_pem.run_cases("image", "peer")
        self.assertTrue(any("label=org.oxibelt.browntls-e2e.run=ownership" in call.args
                            for call in command.call_args_list))
        self.assertFalse(any(call.args[:2] == ("volume", "rm") or call.args[0] == "run"
                             for call in command.call_args_list))

    def test_public_config_checks_wire_version_and_kem(self):
        for name, number in {"x25519": 0x20, "x448": 0x21, "p256": 0x10,
                             "p384": 0x11, "p521": 0x12}.items():
            with self.subTest(kem=name):
                ech_pem.check_public_config(config(number), name)
        for data in (config(0x20), config(0x21, 0xFE0C), b"invalid", config(0x21)[:-4]):
            with self.assertRaises(RuntimeError):
                ech_pem.check_public_config(data, "x448")

    def test_publish_accepts_public_block_and_rejects_private_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.pem"
            target = Path(directory) / "client.pem"
            command = ["sh", "-ec", ech_pem.PUBLISH, "publish", str(source), str(target)]
            payload = config(0x20)
            public = b"-----BEGIN ECHCONFIG-----\n" + payload + b"\n-----END ECHCONFIG-----\n"
            for content in (b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
                            + public, public + b"AAAA\n", public + public):
                with self.subTest(content_length=len(content)):
                    source.write_bytes(content)
                    result = subprocess.run(command, capture_output=True, check=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")
                    self.assertFalse(target.exists())
            source.write_bytes(public)
            result = subprocess.run(command, capture_output=True, check=True)
            self.assertEqual(result.stdout.strip(), payload)
            self.assertEqual(target.read_bytes(), public)

    def test_browntls_server_explicitly_advertises_retry(self):
        server, client = ech_pem.commands("image", "peer", "openssl-x448", "server")
        self.assertIn("/server/openssl-x448/ech.pem", server)
        self.assertIn("/server/openssl-x448/ech-public.pem", server)
        self.assertIn("--ech-retry-pem", server)
        self.assertEqual(client[-2:], ["/client/openssl-x448.pem", "/client/ca.pem"])
        server, client = ech_pem.commands("image", "peer", "browntls-p521", "client")
        self.assertIn("/server/browntls-p521/ech.pem", server)
        self.assertIn("/client/browntls-p521.pem", client)
        self.assertNotIn("--ech-retry-pem", client)

    def test_client_must_report_verified_accepted_tls_and_data(self):
        connected = {"event": "connection", "role": "client", "ech": "Accepted",
                     "version": "TLSv1_3", "io": "async", "peer_certificates": 1,
                     "sent": ech_pem.MESSAGE, "received": ech_pem.MESSAGE[::-1]}
        ech_pem.check_browntls(json.dumps(connected), "client")
        for key, wrong in (("ech", "Rejected"), ("received", "wrong"), ("peer_certificates", 0)):
            with self.subTest(field=key), self.assertRaises(RuntimeError):
                ech_pem.check_browntls(json.dumps({**connected, key: wrong}), "client")
