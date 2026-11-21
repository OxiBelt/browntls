import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ech_service


def log(*rows):
    return "\n".join(json.dumps(row) for row in rows)


class EchServiceTests(unittest.TestCase):
    def setUp(self):
        message = ech_service.MESSAGE
        client = {"event": "connection", "role": "client", "version": "TLSv1_3",
                  "ech": "Accepted", "sent": message, "received": message[::-1],
                  "peer_certificates": 1}
        self.client = client
        self.server = {**client, "role": "server", "server_name": ech_service.INNER,
                       "sent": message[::-1], "received": message}

    def test_retry_must_be_authenticated_and_precede_application_data(self):
        rejected = {"event": "ech-rejected", "retry_configs": True}
        ech_service.check_output(log(rejected, self.client), "client", retry=True)
        for output in (log(self.client), log(self.client, rejected),
                       log({**rejected, "retry_configs": False}, self.client),
                       log(rejected, self.client, self.client)):
            with self.assertRaises(RuntimeError):
                ech_service.check_output(output, "client", retry=True)
        required = {"event": "ech-required", "ech": "Rejected"}
        ech_service.check_output(log(required, self.server), "server", retry=True)
        with self.assertRaises(RuntimeError):
            ech_service.check_output(log(self.server), "server", retry=True)

    def test_accepted_without_retry_checks_async_identity_and_data(self):
        server = {**self.server, "io": "async"}
        ech_service.check_output(log(server), "server", retry=False)
        for key, wrong in (("io", "sync"), ("server_name", ech_service.PUBLIC), ("received", "")):
            with self.subTest(field=key), self.assertRaises(RuntimeError):
                ech_service.check_output(log({**server, key: wrong}), "server", retry=False)

    def test_tcp_service_and_separate_pod_mounts(self):
        for retry in (False, True):
            with self.subTest(retry=retry):
                service, server, client = ech_service.scenario_objects("image:tag", retry)
                self.assertEqual(service["spec"]["ports"][0]["protocol"], "TCP")
                self.assertEqual(service["spec"]["selector"], server["metadata"]["labels"])
                server_args = server["spec"]["containers"][0]["args"]
                client_args = client["spec"]["containers"][0]["args"]
                self.assertIn(f"{service['metadata']['name']}:4433", client_args)
                self.assertEqual("--async" in client_args, not retry)
                self.assertEqual("--ech-retry" in client_args, retry)
                self.assertIn("--ech-retry-pem", server_args)
                self.assertTrue(all("key.pem" not in arg for arg in client_args))
                self.assertEqual(server["spec"]["volumes"][0]["secret"]["secretName"],
                                 "server-fixture")
                self.assertEqual(client["spec"]["volumes"][0]["secret"]["secretName"],
                                 "trust-retry" if retry else "trust-accepted")

    def test_only_public_config_passes_before_creating_client_secret(self):
        pem = b"-----BEGIN ECHCONFIG-----\nAAAA\n-----END ECHCONFIG-----\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.pem"
            path.write_bytes(pem)
            self.assertEqual(ech_service.public_config(path), path)
            path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n" + pem)
            with self.assertRaises(RuntimeError):
                ech_service.public_config(path)

    def test_cleanup_on_failure_only_targets_run_namespace_and_image(self):
        def run(*args, **kwargs):
            if "create" in args and "secret" in args:
                raise RuntimeError("simulated failure creating a fixture")

        with (patch.object(ech_service.revocation, "run", side_effect=run) as command,
              patch.object(ech_service, "keygen"), patch.object(ech_service, "public_config"),
              patch.object(ech_service.secrets, "token_hex", return_value="abc")):
            with self.assertRaisesRegex(RuntimeError, "simulated failure"):
                ech_service.run_service("owned-by-caller", "source:original")
        self.assertEqual([call.args for call in command.call_args_list[-3:]], [
            ("minikube", "--profile", "owned-by-caller", "kubectl", "--", "--context",
             "owned-by-caller", "-n", "browntls-ech-abc", "delete", "namespace",
             "browntls-ech-abc", "--timeout=60s", "--ignore-not-found=true"),
            ("minikube", "--profile", "owned-by-caller", "image", "rm", "browntls-e2e:ech-abc"),
            ("docker", "image", "rm", "browntls-e2e:ech-abc"),
        ])
        build = next(call for call in command.call_args_list if call.args[:2] == ("docker", "build"))
        self.assertIn("BASE=source:original", build.args)
        self.assertIn("org.oxibelt.browntls-e2e.run=browntls-ech-abc", build.args)
