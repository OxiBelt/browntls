"""Assertions for the Phase 1 Service harness."""

import json
import unittest

import early_data


class EarlyData(unittest.TestCase):
    def test_service_selects_the_server_using_the_same_fixture(self):
        service, server, client = early_data.objects("image", "unbuffered", False, "fixture")
        self.assertEqual(service["spec"]["selector"], server["metadata"]["labels"])
        port = service["spec"]["ports"][0]
        self.assertEqual(port["protocol"], "TCP")
        args = client["spec"]["containers"][0]["args"]
        self.assertEqual(args[1], f"{service['metadata']['name']}:{port['port']}")
        for peer in (server, client):
            self.assertEqual(peer["spec"]["volumes"][0]["secret"]["secretName"], "fixture")

    def test_refusal_requires_exact_unresent_accounting(self):
        base = {
            "event": "early-data", "role": "client", "style": "buffered",
            "accepted": False, "early_bytes": 13, "unresent_bytes": 13,
            "ordinary_exchange": True,
        }
        early_data.check_output(json.dumps(base), "client", "buffered", False)
        for change in ({"early_bytes": 0}, {"unresent_bytes": 0}, {"ordinary_exchange": False}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                early_data.check_output(json.dumps(base | change), "client", "buffered", False)
