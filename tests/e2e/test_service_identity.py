"""Pure evidence checks for the RFC 9525 Docker scenarios."""

import json
import unittest

import service_identity


class ServiceIdentityEvidenceTest(unittest.TestCase):
    def test_four_san_fixtures_cover_all_reference_identifier_kinds(self):
        self.assertEqual({case[0] for case in service_identity.CASES},
                         {"dns", "ip", "uri", "srv"})
        self.assertIn("otherName:1.3.6.1.5.5.7.8.7;IA5STRING:", service_identity.CASES[-1][1])

    def test_positive_requires_identity_match_and_application_data(self):
        row = {"event": "connection", "service_identity_matched": True,
               "sent": "identity request", "received": "tseuqer ytitnedi"}
        service_identity.check_client(json.dumps(row), "uri:spiffe://example.test/service", True)
        row["service_identity_matched"] = False
        with self.assertRaisesRegex(RuntimeError, "unexpected authenticated identity"):
            service_identity.check_client(json.dumps(row), "uri:spiffe://example.test/service", True)


if __name__ == "__main__":
    unittest.main()
