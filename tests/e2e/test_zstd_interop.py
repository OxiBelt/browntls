import unittest
from types import SimpleNamespace

import e2e
import zstd_interop


class ZstdInteropHarnessTest(unittest.TestCase):
    def test_only_zstd_is_requested_for_both_browntls_roles(self):
        for role in ("client", "server"):
            args = zstd_interop.brown_args(role)
            self.assertIn("--zstd-cert-compression", args)
            self.assertIn("--tls", args)
            self.assertEqual(args[args.index("--tls") + 1], "1.3")
            self.assertIn("--cert", args)
            self.assertIn("--key", args)
            self.assertIn("--client-ca" if role == "server" else "--ca", args)

    def test_wire_check_requires_zstd_in_both_directions(self):
        good = SimpleNamespace(exit_code=0, stdout=(
            '{"event":"wire","role":"server","sent_zstd":1,'
            '"received_zstd":1,"mutual_auth":true,"data":true}\n'))
        zstd_interop.check_wire(good, "server")
        bad = SimpleNamespace(exit_code=0, stdout=(
            '{"event":"wire","role":"server","sent_zstd":0,'
            '"received_zstd":1,"mutual_auth":true,"data":true}\n'))
        with self.assertRaises(RuntimeError):
            zstd_interop.check_wire(bad, "server")

    def test_build_switch_enables_the_e2e_zstd_feature(self):
        args = e2e.parser().parse_args(["build", "--arch", "amd64", "--zstd"])
        self.assertTrue(args.zstd)


if __name__ == "__main__":
    unittest.main()
