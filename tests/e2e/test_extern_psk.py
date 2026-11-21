"""Pure harness checks for the RFC 9973 independent-peer runner."""

import json
import unittest
from unittest import mock

import extern_psk


class ExternalPskRunnerTest(unittest.TestCase):
    def record(self, role, protocol):
        return {
            "event": "connection",
            "role": role,
            "version": "TLSv1_3" if protocol == "tcp" else "DTLSv1_3",
            "cert_with_extern_psk": True,
            "peer_certificates": int(role == "client"),
            "sent": extern_psk.REQUEST if role == "client" else extern_psk.REPLY,
            "received": extern_psk.REPLY if role == "client" else extern_psk.REQUEST,
            "io": "async" if protocol == "tcp" else "blocking",
        }

    def test_all_roles_and_transports_require_negotiation_and_data(self):
        for protocol in ("tcp", "udp"):
            for role in ("client", "server"):
                with self.subTest(protocol=protocol, role=role):
                    extern_psk.check_browntls(json.dumps(self.record(role, protocol)), role,
                                              protocol)

    def test_rejects_missing_serverhello_extension_evidence(self):
        record = self.record("client", "tcp")
        record["cert_with_extern_psk"] = False
        with self.assertRaisesRegex(RuntimeError, "did not verify RFC 9973"):
            extern_psk.check_browntls(json.dumps(record), "client", "tcp")

    def test_rejects_tcp_case_without_tokio(self):
        record = self.record("client", "tcp")
        record["io"] = "blocking"
        with self.assertRaisesRegex(RuntimeError, "did not use browntls::tokio"):
            extern_psk.check_browntls(json.dumps(record), "client", "tcp")

    def test_server_has_the_client_dns_alias(self):
        with mock.patch.object(extern_psk.subprocess, "Popen") as popen:
            extern_psk.start_server("image", "network", "volume", [], "server")
        command = popen.call_args.args[0]
        alias_at = command.index("--network-alias")
        self.assertEqual(command[alias_at + 1], extern_psk.SERVER_NAME)


if __name__ == "__main__":
    unittest.main()
