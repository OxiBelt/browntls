import base64
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

import ech_pem


def config(kem_id, version=0xFE0D):
    # Only the ECHConfigList envelope and KEM are interpreted by the harness.
    body = struct.pack("!BH", 7, kem_id) + b"config contents"
    return base64.b64encode(struct.pack("!HHH", 4 + len(body), version, len(body)) + body)


class EchPemTests(unittest.TestCase):
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
