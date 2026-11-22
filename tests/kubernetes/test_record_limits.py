"""Unit checks for the Phase 2 minikube qualification manifests."""

import json
import unittest

import record_limits


class RecordLimitResources(unittest.TestCase):
    def test_tcp_variants_request_mutual_delegated_credentials_and_distinct_caps(self):
        for style in record_limits.TCP_STYLES:
            with self.subTest(style=style):
                service, server, client = record_limits.tcp_objects("image", style)
                self.assertEqual(service["spec"]["ports"][0]["protocol"], "TCP")
                self.assertEqual(service["spec"]["selector"], server["metadata"]["labels"])
                server_args = server["spec"]["containers"][0]["args"]
                client_args = client["spec"]["containers"][0]["args"]
                for args, limit in ((server_args, "1024"), (client_args, "512")):
                    self.assertIn("--delegated-credentials", args)
                    self.assertEqual(args[args.index("--record-size-limit") + 1], limit)
                    self.assertIn(record_limits.MESSAGE, args)
                tokio_flag = "--async" if style == "buffered" else "--unbuffered"
                self.assertIn(tokio_flag, server_args)
                self.assertIn(tokio_flag, client_args)
                self.assertNotIn("--unbuffered" if style == "buffered" else "--async", server_args)
                self.assertNotIn("--unbuffered" if style == "buffered" else "--async", client_args)

    def test_dtls_versions_offer_asymmetric_caps_over_udp(self):
        for version in record_limits.DTLS_VERSIONS:
            with self.subTest(version=version):
                service, server, client = record_limits.dtls_objects("image", version)
                self.assertEqual(service["spec"]["ports"][0]["protocol"], "UDP")
                self.assertEqual(service["spec"]["selector"], server["metadata"]["labels"])
                server_args = server["spec"]["containers"][0]["args"]
                client_args = client["spec"]["containers"][0]["args"]
                for args, limit in ((server_args, "1024"), (client_args, "512")):
                    self.assertEqual(args[args.index("--record-size-limit") + 1], limit)
                    self.assertEqual(args[args.index("--tls") + 1], version)
                    self.assertIn("--async", args)
                    self.assertIn(record_limits.DTLS_MESSAGE, args)
                    self.assertLessEqual(len(record_limits.DTLS_MESSAGE), int(limit))

    def test_tcp_result_requires_mutual_delegated_credential_use(self):
        expected = {
            "event": "connection", "role": "client", "version": "TLSv1_3",
            "record_size_limit_configured": "512", "delegated_credential": True,
            "io": "async",
            "peer_certificates": 1, "sent": record_limits.MESSAGE,
            "received": record_limits.MESSAGE[::-1],
        }
        record_limits.check_tcp(json.dumps(expected), "client", "buffered")
        expected["io"] = "tokio-unbuffered"
        record_limits.check_tcp(json.dumps(expected), "client", "unbuffered")
        expected["delegated_credential"] = False
        with self.assertRaises(RuntimeError):
            record_limits.check_tcp(json.dumps(expected), "client", "unbuffered")

    def test_dtls_result_checks_the_actual_peer_send_cap(self):
        expected = {
            "event": "connection", "role": "client", "version": "DTLSv1_3",
            "record_size_limit_configured": "512", "max_application_data": 1023,
            "io": "tokio-dtls", "peer_certificates": 1, "closed": True,
            "sent": record_limits.DTLS_MESSAGE,
            "received": record_limits.DTLS_MESSAGE[::-1],
        }
        record_limits.check_dtls(json.dumps(expected), "client", "1.3")
        expected["max_application_data"] = 1024
        with self.assertRaises(RuntimeError):
            record_limits.check_dtls(json.dumps(expected), "client", "1.3")


if __name__ == "__main__":
    unittest.main()
