import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

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

    def namespace(self, uid="uid-owned", owner="owner-token"):
        return json.dumps({"metadata": {"name": "ech-run", "uid": uid,
                                       "labels": {ech_service.OWNER_LABEL: owner}}})

    def test_preexisting_namespace_is_not_registered_for_removal(self):
        kubectl = Mock(side_effect=[RuntimeError("AlreadyExists"),
                                    self.namespace(uid="uid-foreign", owner="other-token")])
        register = Mock()
        with self.assertRaisesRegex(RuntimeError, "creating namespace ech-run failed"):
            ech_service.create_namespace(kubectl, register, "ech-run", "owner-token")
        register.assert_not_called()
        spec = json.loads(kubectl.call_args_list[0].kwargs["data"])
        self.assertEqual(spec["metadata"]["labels"], {ech_service.OWNER_LABEL: "owner-token"})
        self.assertEqual(kubectl.call_args.args[:3], ("get", "namespace", "ech-run"))

    def test_ambiguous_create_registers_only_the_confirmed_owned_uid(self):
        kubectl = Mock(side_effect=[subprocess.TimeoutExpired("kubectl", 30), self.namespace()])
        register = Mock()
        with self.assertRaisesRegex(RuntimeError, "creating namespace ech-run failed"):
            ech_service.create_namespace(kubectl, register, "ech-run", "owner-token")
        register.assert_called_once_with("namespace ech-run", ech_service.delete_namespace,
                                         kubectl, "ech-run", "uid-owned")

    def test_failed_namespace_removal_reports_secret_and_attempts_other_cleanup(self):
        kubectl = Mock(side_effect=[self.namespace(), RuntimeError("Forbidden"), self.namespace()])
        remove_image = Mock()
        with self.assertRaisesRegex(RuntimeError, "namespace ech-run: .*Secret server-fixture"):
            with ech_service.checked_cleanup() as register:
                register("image run-image", remove_image)
                register("namespace ech-run", ech_service.delete_namespace, kubectl,
                         "ech-run", "uid-owned")
        remove_image.assert_called_once_with()
        delete = kubectl.call_args_list[1]
        self.assertEqual(delete.args, ("delete", "--raw", "/api/v1/namespaces/ech-run", "-f", "-"))
        self.assertEqual(json.loads(delete.kwargs["data"])["preconditions"], {"uid": "uid-owned"})

    def test_namespace_removal_accepts_true_absence_or_replacement(self):
        for read in ("", self.namespace(uid="uid-replacement", owner="different-owner")):
            with self.subTest(read=read):
                kubectl = Mock(return_value=read)
                ech_service.delete_namespace(kubectl, "ech-run", "uid-owned")
                self.assertEqual(kubectl.call_count, 1)
        kubectl = Mock(side_effect=[self.namespace(), RuntimeError("NotFound"), ""])
        ech_service.delete_namespace(kubectl, "ech-run", "uid-owned")
        self.assertEqual(kubectl.call_count, 3)

    def test_fixture_container_name_collision_does_not_remove_foreign_container(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(ech_service.revocation, "run", side_effect=[
                    RuntimeError("container name in use"), ""]) as command:
                with self.assertRaisesRegex(RuntimeError, "container name in use"):
                    ech_service.keygen("image", "fixture", "owner-token", Path(directory) / "keys",
                                       7, private=True)
        self.assertEqual(command.call_count, 2)
        self.assertEqual(command.call_args.args[:3], ("docker", "container", "ls"))
        self.assertIn(f"label={ech_service.OWNER_LABEL}=owner-token", command.call_args.args)

    def runtime_image(self, owner="owner-token"):
        return json.dumps({
            "status": {"id": "sha256:cri-id"},
            "info": {"imageSpec": {"config": {"Labels": {ech_service.OWNER_LABEL: owner}}}},
        })

    def test_minikube_image_removal_uses_cri_identity_and_rechecks_reference(self):
        reference = "docker.io/library/browntls-e2e:ech-run"
        inventory = json.dumps([{"id": "cri-id", "repoTags": [reference]}])
        minikube = Mock(side_effect=[inventory, self.runtime_image(), "", '{"images": []}',
                                    '{"images": [{"id": "other-id"}]}'])
        ech_service.remove_minikube_image(minikube, ("node-1", "node-2"), "browntls-e2e:ech-run",
                                         "owner-token", "sha256:cri-id")
        self.assertEqual([call.args for call in minikube.call_args_list], [
            ("image", "ls", "--format", "json"),
            ("ssh", "--", "sudo", "crictl", "inspecti", reference),
            ("image", "rm", "sha256:cri-id"),
            ("ssh", "--node", "node-1", "--", "sudo", "crictl", "images", "-o", "json"),
            ("ssh", "--node", "node-2", "--", "sudo", "crictl", "images", "-o", "json"),
        ])

    def test_minikube_image_still_tagged_after_removal_is_a_failure(self):
        image = "browntls-e2e:ech-run"
        inventory = json.dumps([{"id": "cri-id", "repoTags": [f"docker.io/library/{image}"]}])
        remaining = json.dumps({"images": [{"id": "replacement-id", "repoTags": [image]}]})
        for removal in ("", RuntimeError("Removal denied")):
            with self.subTest(removal=removal):
                minikube = Mock(side_effect=[inventory, self.runtime_image(), removal, remaining])
                with self.assertRaisesRegex(RuntimeError, "node node-1 still lists image replacement-id"):
                    ech_service.remove_minikube_image(minikube, ("node-1",), image, "owner-token", None)

    def test_minikube_image_untagged_id_and_unreadable_node_are_reported(self):
        image = "browntls-e2e:ech-run"
        inventory = json.dumps([{"id": "cri-id", "repoTags": [f"docker.io/library/{image}"]}])
        minikube = Mock(side_effect=[inventory, self.runtime_image(), "", RuntimeError("SSH failed"),
                                    '{"images": [{"id": "cri-id"}]}'])
        with self.assertRaisesRegex(RuntimeError, "(?s)inventory on node node-1.*node node-2 still lists image cri-id"):
            ech_service.remove_minikube_image(minikube, ("node-1", "node-2"), image, "owner-token",
                                             "sha256:cri-id")

    def test_minikube_image_checks_captured_id_even_when_tag_disappeared_earlier(self):
        minikube = Mock(side_effect=["[]", '{"images": [{"id": "cri-id"}]}'])
        with self.assertRaisesRegex(RuntimeError, "node node-1 still lists image cri-id"):
            ech_service.remove_minikube_image(minikube, ("node-1",), "browntls-e2e:ech-run",
                                             "owner-token", "sha256:cri-id")

    def test_minikube_image_rejects_malformed_node_inventory(self):
        minikube = Mock(side_effect=["[]", '{}'])
        with self.assertRaisesRegex(RuntimeError, "invalid CRI image inventory"):
            ech_service.remove_minikube_image(minikube, ("node-1",), "browntls-e2e:ech-run",
                                             "owner-token", "sha256:cri-id")

    def test_minikube_image_requires_positive_ownership_or_actual_absence(self):
        image = "browntls-e2e:ech-run"
        inventory = json.dumps([{"id": "cri-id", "repoTags": [f"docker.io/library/{image}"]}])
        minikube = Mock(side_effect=[inventory, self.runtime_image("foreign-owner")])
        with self.assertRaisesRegex(RuntimeError, "lacks this run's ownership label"):
            ech_service.remove_minikube_image(minikube, ("node-1",), image, "owner-token", None)
        self.assertEqual(minikube.call_count, 2)
        minikube = Mock(side_effect=["[]", '{"images": []}'])
        ech_service.remove_minikube_image(minikube, ("node-1",), image, "owner-token", None)
        self.assertEqual(minikube.call_count, 2)
