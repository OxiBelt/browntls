"""Focused stream RSL command contracts for the Phase 2 qualification slice."""

import re
import unittest

import e2e


class RecordSizeLimitInterop(unittest.TestCase):
    def test_tls12_and_tls13_use_gnutls_asymmetric_limits_in_both_roles(self):
        suite = e2e.SUITES["gnutls"]
        cases = [
            scenario
            for scenario in e2e.scenarios_for(suite)
            if scenario.name in {"tls12-rsl-asymmetric", "tls13-rsl-asymmetric"}
        ]
        self.assertEqual({case.tls for case in cases}, {"1.2", "1.3"})
        self.assertEqual(len(cases), 2)

        for case in cases:
            with self.subTest(version=case.tls):
                self.assertEqual(case.roles_for(suite), e2e.ROLES)
                self.assertEqual(len(case.message), 4096)
                self.assertEqual(case.browntls_record_size_limit, 1024)
                self.assertEqual(case.peer_record_size_limit, 512)
                for role in e2e.ROLES:
                    brown = e2e.browntls_args(case, role)
                    self.assertEqual(
                        brown[brown.index("--record-size-limit") + 1], "1024"
                    )
                peer_server = e2e.peer_server_command(case, "gnutls")
                self.assertEqual(
                    peer_server[peer_server.index("--recordsize") + 1], "512"
                )
                self.assertEqual(
                    peer_server[peer_server.index("--debug") + 1], "4"
                )
                peer_client = e2e.peer_client_command(case, "gnutls")
                command_text = peer_client[-1]
                self.assertIn("--recordsize 512", command_text)
                self.assertIn("--debug 4", command_text)
                self.assertEqual(
                    "".join(re.findall(r"printf '%s' (r+);", command_text)),
                    case.message,
                )

    def test_gnutls_peer_log_must_confirm_the_browntls_limit(self):
        case = next(
            scenario
            for scenario in e2e.scenarios_for(e2e.SUITES["gnutls"])
            if scenario.name == "tls13-rsl-asymmetric"
        )
        peer = e2e.Container("gnutls", 0, stderr="record_size_limit 1024 negotiated")
        self.assertEqual(e2e.check_gnutls_record_size_limit(case, peer), [])
        peer.stderr = ""
        self.assertTrue(e2e.check_gnutls_record_size_limit(case, peer))


if __name__ == "__main__":
    unittest.main()
