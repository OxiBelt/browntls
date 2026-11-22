import unittest

import key_log


class KeyLogTests(unittest.TestCase):
    def test_validates_required_labels_without_echoing_invalid_bytes(self):
        expected = {"CLIENT_RANDOM"}
        random = "01" * 32
        secret = "AB" * 48
        record = f"CLIENT_RANDOM {random} {secret}\n"
        self.assertEqual(key_log.entries("# header\n" + record, expected),
                         {"CLIENT_RANDOM": (random, secret.lower())})
        for invalid in (record * 2, "", record.replace(secret, "invalid")):
            with self.assertRaises(RuntimeError) as failure:
                key_log.entries(invalid, expected)
            self.assertNotIn(secret, str(failure.exception))
            self.assertNotIn(random, str(failure.exception))

    def test_four_role_version_commands_authenticate_both_peers(self):
        for version in ("1.2", "1.3"):
            for role in ("client", "server"):
                with self.subTest(version=version, role=role):
                    server, client = key_log.commands(version, role)
                    if role == "client":
                        self.assertIn("--key-log", client)
                        self.assertIn("--cert", client)
                        self.assertIn("-Verify", server)
                        self.assertIn("-keylogfile", server)
                    else:
                        self.assertIn("--key-log", server)
                        self.assertIn("--client-ca", server)
                        self.assertIn("-keylogfile", client[-1])
                        self.assertIn("-verify_hostname", client[-1])


if __name__ == "__main__":
    unittest.main()
