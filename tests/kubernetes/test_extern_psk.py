"""Pure checks for strict TLS and DTLS minikube evidence."""

import json
import unittest

import extern_psk


class KubernetesExternalPskTest(unittest.TestCase):
    def test_tcp_tokio_and_udp_dtls_evidence(self):
        for protocol, version in (("tcp", "TLSv1_3"), ("udp", "DTLSv1_3")):
            with self.subTest(protocol=protocol):
                row = {
                    "event": "connection",
                    "role": "client",
                    "version": version,
                    "cert_with_extern_psk": True,
                    "peer_certificates": 1,
                    "sent": extern_psk.REQUEST,
                    "received": extern_psk.REPLY,
                }
                if protocol == "tcp":
                    row["io"] = "async"
                extern_psk.check_logs(json.dumps(row), "client", protocol)

    def test_rejects_non_strict_or_unverified_connection(self):
        row = {
            "event": "connection",
            "role": "client",
            "version": "TLSv1_3",
            "cert_with_extern_psk": False,
            "peer_certificates": 1,
            "sent": extern_psk.REQUEST,
            "received": extern_psk.REPLY,
            "io": "async",
        }
        with self.assertRaisesRegex(RuntimeError, "invalid tcp exchange"):
            extern_psk.check_logs(json.dumps(row), "client", "tcp")


if __name__ == "__main__":
    unittest.main()
