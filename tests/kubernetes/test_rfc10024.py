"""Pure evidence checks for minikube RFC 10024 Service scenarios."""

import json
import unittest
from unittest.mock import Mock, patch

import rfc10024


def row(role, protocol, group):
    sent, received = ((rfc10024.REQUEST, rfc10024.REPLY) if role == "client"
                      else (rfc10024.REPLY, rfc10024.REQUEST))
    return {
        "event": "connection",
        "role": role,
        "version": "TLSv1_3" if protocol == "tcp" else "DTLSv1_3",
        "group": group,
        "handshake": "Full" if protocol == "tcp" else "FullWithHelloRetryRequest",
        "peer_certificates": 1 if role == "client" else 0,
        "service_identity_matched": role == "client",
        "sent": sent,
        "received": received,
        "io": "async" if protocol == "tcp" else "tokio-dtls",
    }


class KubernetesRfc10024Test(unittest.TestCase):
    def test_all_groups_require_authenticated_bidirectional_tls_and_dtls(self):
        self.assertEqual(len(rfc10024.GROUPS), 3)
        for group in rfc10024.GROUPS:
            for protocol in ("tcp", "udp"):
                for role in ("client", "server"):
                    with self.subTest(group=group, protocol=protocol, role=role):
                        rfc10024.check_connection(json.dumps(row(role, protocol, group)),
                                                  role, protocol, group)

    def test_rejects_group_or_retry_kind_mismatch(self):
        for field, value in (("group", "X25519"), ("handshake", "Full")):
            evidence = row("client", "udp", "secp384r1MLKEM1024")
            evidence[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(RuntimeError, "invalid udp exchange"):
                    rfc10024.check_connection(json.dumps(evidence), "client", "udp",
                                              "secp384r1MLKEM1024")

    def test_rejects_missing_certificate_identity_or_tokio_evidence(self):
        for field, value, message in (
                ("peer_certificates", 0, "authenticate the server certificate"),
                ("service_identity_matched", False, "verify the Service DNS identity"),
                ("io", "blocking", "expected Tokio adapter")):
            evidence = row("client", "tcp", "X25519MLKEM768")
            evidence[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(RuntimeError, message):
                    rfc10024.check_connection(json.dumps(evidence), "client", "tcp",
                                              "X25519MLKEM768")

    def test_service_routes_to_named_server_with_separate_credentials(self):
        group = "secp384r1MLKEM1024"
        kubectl = Mock()
        with patch.object(rfc10024.extern_psk, "wait_listening"), patch.object(
                rfc10024.extern_psk, "wait_done", side_effect=[
                    json.dumps(row("client", "udp", group)),
                    json.dumps(row("server", "udp", group)),
                ]):
            rfc10024.scenario(kubectl, "test", "browntls:test", "udp", group)

        service, server = json.loads(kubectl.call_args_list[0].kwargs["data"])["items"]
        client = json.loads(kubectl.call_args_list[1].kwargs["data"])
        self.assertEqual(service["spec"]["selector"], server["metadata"]["labels"])
        self.assertTrue(server["metadata"]["name"].startswith("server-"))
        self.assertTrue(client["metadata"]["name"].startswith("client-"))
        self.assertEqual(service["spec"]["ports"][0]["protocol"], "UDP")
        for pod, secret in ((server, "server-pki"), (client, "trust")):
            self.assertEqual(pod["spec"]["volumes"][0]["secret"]["secretName"], secret)
            self.assertIn("--async", pod["spec"]["containers"][0]["args"])

    def test_requires_one_completed_handshake(self):
        with self.assertRaisesRegex(RuntimeError, "exactly one"):
            rfc10024.check_connection("", "client", "tcp", "X25519MLKEM768")


if __name__ == "__main__":
    unittest.main()
