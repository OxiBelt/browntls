"""Unit checks for the key-log minikube qualification harness."""

import json
import unittest

import key_log


class KeyLogHarnessTest(unittest.TestCase):
    def test_both_feature_variants_use_memory_volumes_and_mutual_auth(self):
        service, server, client = key_log.service_objects(
            "peer-image", "private", "on-private", "peer.example.test")
        self.assertEqual(service["spec"]["ports"][0]["protocol"], "TCP")
        self.assertEqual(service["spec"]["selector"], server["metadata"]["labels"])
        for peer in (server, client):
            spec = peer["spec"]
            self.assertEqual(spec["volumes"][0]["emptyDir"]["medium"], "Memory")
            self.assertIn("chmod 0700 /key-log",
                          spec["initContainers"][0]["command"][-1])
            container = spec["containers"][0]
            args = container["args"]
            self.assertIn("--key-log", args)
            self.assertIn("--async", args)
            self.assertIn("/fixture/client.key" if peer is client else "/fixture/server.key", args)
            self.assertEqual(container["env"][0]["value"], "/key-log/session.keys")
            self.assertEqual(container["image"], "peer-image")
            if peer is client:
                self.assertEqual(args[args.index("--server-name") + 1], "peer.example.test")

        _, plain_server, plain_client = key_log.service_objects(
            "plain-image", "permissive", "off-permissive", "peer.example.test")
        for peer in (plain_server, plain_client):
            self.assertIn("chmod 0777 /key-log",
                          peer["spec"]["initContainers"][0]["command"][-1])
            self.assertIn("--key-log", peer["spec"]["containers"][0]["args"])
            self.assertEqual(peer["spec"]["containers"][0]["image"], "plain-image")

    def test_only_exact_authenticated_application_data_counts(self):
        for role in ("client", "server"):
            sent, received = ((key_log.MESSAGE, key_log.MESSAGE[::-1]) if role == "client"
                              else (key_log.MESSAGE[::-1], key_log.MESSAGE))
            row = {"event": "connection", "role": role, "version": "TLSv1_3",
                   "peer_certificates": 1, "sent": sent, "received": received,
                   "io": "async"}
            key_log.check_exchange(json.dumps(row), role)
            row["received"] = "unexpected"
            with self.assertRaises(RuntimeError):
                key_log.check_exchange(json.dumps(row), role)


if __name__ == "__main__":
    unittest.main()
