"""Pure evidence checks for minikube RFC 9525 Service scenarios."""

import json
import unittest

import service_identity


class KubernetesServiceIdentityTest(unittest.TestCase):
    def test_pod_names_and_secret_mounts_are_explicit(self):
        pod = service_identity.pod("client", "image", ["client"], "trust")
        self.assertEqual(pod["metadata"]["name"], "client")
        self.assertEqual(pod["spec"]["volumes"][0]["secret"]["secretName"], "trust")

    def test_positive_requires_authenticated_match_and_data(self):
        output = json.dumps({"event": "connection", "service_identity_matched": True,
                             "sent": "identity request", "received": "tseuqer ytitnedi"})
        service_identity.check_identity_output(output, True)

    def test_negative_rejects_any_completed_connection(self):
        service_identity.check_identity_output('{"event":"error","message":"handshake: NotValidForName"}', False)
        output = json.dumps({"event": "connection", "service_identity_matched": True})
        with self.assertRaisesRegex(RuntimeError, "authenticated connection"):
            service_identity.check_identity_output(output, False)


if __name__ == "__main__":
    unittest.main()
