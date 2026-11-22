#!/usr/bin/env python3
"""Exercise accepted and authenticated stale ECH over minikube TCP Services."""

import argparse
import base64
import binascii
from contextlib import ExitStack, contextmanager
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

import revocation

PORT = 4433
INNER = "ech-inner.test"
PUBLIC = "ech-public.test"
MESSAGE = "ech service request"
UID = 65532
PKI_SCRIPT = revocation.ROOT / "tests/e2e/peer/gen-ech-pki.sh"
OWNER_LABEL = "org.oxibelt.browntls-e2e.run"
COMMAND_ERRORS = (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError)


def public_config(path):
    lines = path.read_bytes().splitlines()
    if len(lines) < 3 or lines[0] != b"-----BEGIN ECHCONFIG-----" or (
            lines[-1] != b"-----END ECHCONFIG-----"):
        raise RuntimeError("expected a public-only ECH PEM fixture")
    try:
        if base64.b64decode(b"".join(lines[1:-1]), validate=True):
            return path
    except binascii.Error:
        pass
    raise RuntimeError("expected base64 ECH configuration data")


@contextmanager
def checked_cleanup():
    problems = []

    def attempt(name, action, *args):
        try:
            action(*args)
        except COMMAND_ERRORS as error:
            problems.append(f"{name}: {error}")

    try:
        with ExitStack() as stack:
            yield lambda name, action, *args: stack.callback(attempt, name, action, *args)
    except BaseException:
        if problems:
            print("cleanup failed:\n" + "\n".join(problems), file=sys.stderr)
        raise
    if problems:
        raise RuntimeError("cleanup failed:\n" + "\n".join(problems))


def remove_and_verify(find_owned, delete):
    identifier = find_owned()
    if identifier is None:
        return
    problem = None
    try:
        delete(identifier)
    except COMMAND_ERRORS as error:
        problem = error
    if find_owned() is not None:
        raise RuntimeError(f"still present after removal{f': {problem}' if problem else ''}")


def keygen(image, name, owner, directory, config_id, private):
    directory.mkdir()
    run = revocation.run

    def find_owned():
        output = run("docker", "container", "ls", "--all", "--no-trunc", "--filter",
                     f"label={OWNER_LABEL}={owner}", "--format", "{{.Names}} {{.ID}}",
                     capture=True, seconds=30)
        return dict(line.split() for line in output.splitlines() if line.strip()).get(name)

    def remove(identifier):
        run("docker", "container", "rm", "-f", identifier, capture=True, seconds=30)

    with checked_cleanup() as register:
        register(f"Docker fixture container {name}", remove_and_verify, find_owned, remove)
        identifier = run("docker", "create", "--name", name, "--network", "none", "--user", "0:0",
                         "--label", f"{OWNER_LABEL}={owner}", image, "ech-keygen", "--out", "/ech",
                         "--public-name", PUBLIC, "--config-id", str(config_id), "--ech-pem",
                         capture=True, seconds=30).strip()
        run("docker", "start", "-a", identifier, capture=True, seconds=30)
        files = ["ech-public.pem", "ech.pem"] if private else ["ech-public.pem"]
        for file in files:
            run("docker", "cp", f"{identifier}:/ech/{file}", str(directory / file), seconds=30)


def create_secret(kubectl, name, files):
    kubectl("create", "secret", "generic", name,
            *(f"--from-file={key}={path}" for key, path in files.items()), capture=True)


def pod(name, image, args, secret):
    return revocation.resource("Pod", name, {
        "metadata": {"name": name, "labels": {"app": name}},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "activeDeadlineSeconds": 120,
            "securityContext": {"runAsNonRoot": True, "runAsUser": UID,
                                "runAsGroup": UID, "fsGroup": UID},
            "containers": [{"name": "peer", "image": image, "imagePullPolicy": "Never",
                            "args": args, "volumeMounts": [{"name": "fixture",
                                "mountPath": "/fixture", "readOnly": True}]}],
            "volumes": [{"name": "fixture", "secret": {"secretName": secret,
                                                       "defaultMode": 0o440}}],
        },
    })


def scenario_objects(image, retry):
    case = "retry" if retry else "accepted"
    server = f"server-{case}"
    client = f"client-{case}"
    service = f"ech-{case}"
    service_obj = revocation.resource("Service", service, {"spec": {
        "type": "ClusterIP", "selector": {"app": server},
        "ports": [{"port": PORT, "targetPort": PORT, "protocol": "TCP"}],
    }})
    server_args = ["server", "--listen", f"0.0.0.0:{PORT}", "--tls", "1.3",
                   "--accept", "2" if retry else "1",
                   "--cert", "/fixture/inner.pem", "--key", "/fixture/inner.key",
                   "--sni-cert", f"{PUBLIC},/fixture/public.pem,/fixture/public.key",
                   "--ech-pem", "/fixture/current-key.pem",
                   "--ech-retry-pem", "/fixture/retry-config.pem"]
    client_args = ["client", "--connect", f"{service}:{PORT}", "--server-name", INNER,
                   "--ca", "/fixture/ca.pem", "--tls", "1.3", "--wait", "12",
                   "--ech-pem", "/fixture/start-config.pem", "--message", MESSAGE,
                   "--expect-reply", MESSAGE[::-1]]
    if retry:
        client_args.append("--ech-retry")
    else:
        server_args.append("--async")
        client_args.append("--async")
    return (service_obj, pod(server, image, server_args, "server-fixture"),
            pod(client, image, client_args, f"trust-{case}"))


def check_output(output, role, retry):
    rows = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    relevant = [row for row in rows if row.get("event") in {
        "connection", "error", "ech-rejected", "ech-required",
    }]
    expected = ["connection"]
    if retry:
        expected.insert(0, "ech-rejected" if role == "client" else "ech-required")
    if [row.get("event") for row in relevant] != expected:
        raise RuntimeError(f"{role} did not report the expected ECH event sequence")
    if retry and role == "client" and relevant[0].get("retry_configs") is not True:
        raise RuntimeError("client rejection did not carry authenticated retry configurations")
    if retry and role == "server" and relevant[0].get("ech") != "Rejected":
        raise RuntimeError("server did not report ECH rejection before ech_required")
    connection = relevant[-1]
    sent, received = (MESSAGE, MESSAGE[::-1]) if role == "client" else (MESSAGE[::-1], MESSAGE)
    fields = {"role": role, "version": "TLSv1_3", "ech": "Accepted",
              "sent": sent, "received": received}
    if not retry:
        fields["io"] = "async"
    if role == "server":
        fields["server_name"] = INNER
    else:
        fields["peer_certificates"] = 1
    if any(connection.get(key) != value for key, value in fields.items()):
        raise RuntimeError(f"{role} did not confirm ECH acceptance and TLS 1.3 application data")


def wait_pod(kubectl, pod_name, listening=False):
    expected = "listening" if listening else "Succeeded"
    deadline = time.monotonic() + 80
    while time.monotonic() < deadline:
        phase = kubectl("get", "pod", pod_name, "-o", "jsonpath={.status.phase}",
                        capture=True, seconds=12).strip()
        if phase == "Succeeded" and not listening:
            return kubectl("logs", pod_name, capture=True, seconds=12)
        if phase in {"Failed", "Succeeded"}:
            raise RuntimeError(f"pod {pod_name} ended {phase} while waiting for {expected}")
        if listening and phase == "Running":
            logs = kubectl("logs", pod_name, capture=True, check=False, seconds=12)
            if '"event":"listening"' in logs:
                return logs
        time.sleep(0.5)
    raise RuntimeError(f"pod {pod_name} did not reach {expected}")


def run_case(kubectl, image, retry):
    service, server, client = scenario_objects(image, retry)
    kubectl("create", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "List",
            "items": [service, server]}), seconds=30)
    server_name = server["metadata"]["name"]
    wait_pod(kubectl, server_name, listening=True)
    kubectl("create", "-f", "-", data=json.dumps(client), seconds=30)
    check_output(wait_pod(kubectl, client["metadata"]["name"]), "client", retry)
    check_output(wait_pod(kubectl, server_name), "server", retry)
    print(f"{service['metadata']['name']}: verified ECH and data through a TCP Service", flush=True)


def parse_namespace_metadata(output):
    resource = json.loads(output)
    metadata = resource.get("metadata") if isinstance(resource, dict) else None
    if not isinstance(metadata, dict) or not metadata.get("uid"):
        raise RuntimeError("namespace response did not contain an identity")
    return metadata


def namespace_metadata(kubectl, namespace):
    output = kubectl("get", "namespace", namespace, "--ignore-not-found=true", "-o", "json",
                     capture=True, seconds=15)
    return parse_namespace_metadata(output) if output.strip() else None


def owned_namespace_uid(metadata, namespace, owner):
    if metadata and metadata.get("name") == namespace and (
            metadata.get("labels", {}).get(OWNER_LABEL) == owner):
        return metadata.get("uid")
    return None


def delete_namespace(kubectl, namespace, uid):
    metadata = namespace_metadata(kubectl, namespace)
    if metadata is None or metadata.get("uid") != uid:
        return
    options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}}
    problem = None
    try:
        # The API checks the UID at deletion time, including replacements
        # created after the preceding read.
        kubectl("delete", "--raw", f"/api/v1/namespaces/{namespace}", "-f", "-",
                data=json.dumps(options), capture=True, seconds=30)
    except COMMAND_ERRORS as error:
        problem = error
    deadline = time.monotonic() + 60
    while True:
        metadata = namespace_metadata(kubectl, namespace)
        if metadata is None or metadata.get("uid") != uid:
            return
        if (problem and not metadata.get("deletionTimestamp")) or time.monotonic() >= deadline:
            detail = f": {problem}" if problem else ""
            raise RuntimeError(f"still present, potentially retaining Secret server-fixture{detail}")
        time.sleep(0.5)


def create_namespace(kubectl, register, namespace, owner):
    spec = revocation.resource("Namespace", namespace, {
        "metadata": {"name": namespace, "labels": {OWNER_LABEL: owner}},
    })
    try:
        created = kubectl("create", "-f", "-", "-o", "json", data=json.dumps(spec),
                          capture=True, seconds=30)
        uid = owned_namespace_uid(parse_namespace_metadata(created), namespace, owner)
        if not uid:
            raise RuntimeError(f"create did not confirm ownership of namespace {namespace}")
    except COMMAND_ERRORS as error:
        try:
            uid = owned_namespace_uid(namespace_metadata(kubectl, namespace), namespace, owner)
        except COMMAND_ERRORS as read_error:
            raise RuntimeError(f"cannot verify ownership of namespace {namespace}: {read_error}") from error
        if uid:
            register(f"namespace {namespace}", delete_namespace, kubectl, namespace, uid)
        raise RuntimeError(f"creating namespace {namespace} failed: {error}") from error
    register(f"namespace {namespace}", delete_namespace, kubectl, namespace, uid)


def docker_image_id(image, owner=None):
    filters = ["--filter", f"reference={image}"]
    if owner is not None:
        filters += ["--filter", f"label={OWNER_LABEL}={owner}"]
    output = revocation.run("docker", "image", "ls", "--no-trunc", *filters,
                            "--format", "{{.ID}}", capture=True, seconds=30)
    ids = output.split()
    if len(ids) > 1:
        raise RuntimeError(f"ambiguous Docker image identity for {image}")
    return ids[0] if ids else None


def minikube_image_ids(minikube, image):
    images = json.loads(minikube("image", "ls", "--format", "json", capture=True, seconds=45))
    if not isinstance(images, list):
        raise RuntimeError("minikube did not return an image inventory")
    refs = {image, f"docker.io/library/{image}", f"docker.io/{image}"}
    ids = set()
    for row in images:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise RuntimeError("minikube image inventory contains an invalid identity")
        if refs.intersection(row.get("repoTags") or ()):
            ids.add(row["id"].removeprefix("sha256:"))
    return ids


def minikube_nodes(kubectl):
    names = kubectl("get", "nodes", "-o", 'jsonpath={range .items[*]}{.metadata.name}{"\\n"}{end}',
                    capture=True, seconds=30).split()
    if not names:
        raise RuntimeError("minikube did not report any nodes for image cleanup")
    return names


def verify_minikube_image_absent(minikube, nodes, image, runtime_id):
    refs = {image, f"docker.io/library/{image}", f"docker.io/{image}"}
    expected_id = runtime_id.removeprefix("sha256:") if runtime_id else None
    problems = []
    for node in nodes:
        try:
            output = minikube("ssh", "--node", node, "--", "sudo", "crictl", "images",
                              "-o", "json", capture=True, seconds=30)
            inventory = json.loads(output)
            images = inventory.get("images") if isinstance(inventory, dict) else None
            if not isinstance(images, list):
                raise RuntimeError("invalid CRI image inventory")
            for row in images:
                if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"]:
                    raise RuntimeError("CRI image inventory contains an invalid identity")
                tags = row.get("repoTags")
                if tags is None:  # An untagged image may omit repoTags.
                    tags = []
                if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
                    raise RuntimeError("CRI image inventory contains invalid tags")
                if row["id"].removeprefix("sha256:") == expected_id or refs.intersection(tags):
                    problems.append(f"node {node} still lists image {row['id']} for {image}")
        except COMMAND_ERRORS as error:
            problems.append(f"cannot verify CRI image inventory on node {node}: {error}")
    return problems


def owned_minikube_image_id(minikube, image, owner):
    ids = minikube_image_ids(minikube, image)
    if not ids:
        return None
    reference = f"docker.io/library/{image}"
    detail = json.loads(minikube("ssh", "--", "sudo", "crictl", "inspecti", reference,
                                 capture=True, seconds=30))
    runtime_id = detail.get("status", {}).get("id")
    if not isinstance(runtime_id, str) or ids != {runtime_id.removeprefix("sha256:")}:
        raise RuntimeError(f"cannot confirm the CRI identity for {reference}")
    labels = detail.get("info", {}).get("imageSpec", {}).get("config", {}).get("Labels", {})
    if not isinstance(labels, dict) or labels.get(OWNER_LABEL) != owner:
        raise RuntimeError(f"minikube image {reference} lacks this run's ownership label")
    return runtime_id


def remove_minikube_image(minikube, nodes, image, owner, loaded_id):
    runtime_id = owned_minikube_image_id(minikube, image, owner)
    if runtime_id and loaded_id and runtime_id.removeprefix("sha256:") != loaded_id.removeprefix("sha256:"):
        raise RuntimeError(f"CRI image identity changed for {image}: {loaded_id} to {runtime_id}")
    problem = None
    if runtime_id is not None:
        try:
            minikube("image", "rm", runtime_id, capture=True, seconds=45)
        except COMMAND_ERRORS as error:
            problem = error
    problems = verify_minikube_image_absent(minikube, nodes, image, loaded_id or runtime_id)
    if problems:
        if problem:
            problems.insert(0, str(problem))
        raise RuntimeError("\n".join(problems))


@contextmanager
def service_environment(profile, source_image, purpose):
    run_id = secrets.token_hex(8)
    owner = secrets.token_hex(16)
    namespace = f"browntls-{purpose}-{run_id}"
    image = f"browntls-e2e:{purpose}-{run_id}"

    def minikube(*args, **kwargs):
        return revocation.run("minikube", "--profile", profile, *args, **kwargs)

    def kubectl(*args, **kwargs):
        return minikube("kubectl", "--", "--context", profile, "-n", namespace, *args, **kwargs)

    with tempfile.TemporaryDirectory(prefix=f"browntls-{purpose}-") as temporary, checked_cleanup() as register:
        directory = Path(temporary)
        archive = str(directory / "image.tar")
        # Some CRI runtimes remove all tags for an image ID. Give this run a
        # distinct image config so removing it cannot remove the source image.
        revocation.run("docker", "image", "inspect", source_image, capture=True, seconds=30)
        if docker_image_id(image):
            raise RuntimeError(f"Docker image tag {image} already exists")

        def remove_docker_image(identifier):
            revocation.run("docker", "image", "rm", identifier, capture=True, seconds=30)

        register(f"Docker image {image}", remove_and_verify,
                 lambda: docker_image_id(image, owner), remove_docker_image)
        revocation.run("docker", "build", "--network=none", "--build-arg", f"BASE={source_image}",
                       "--label", f"{OWNER_LABEL}={owner}", "--tag", image,
                       "-", data="ARG BASE=scratch\nFROM ${BASE}\n", capture=True, seconds=60)
        if not docker_image_id(image, owner):
            raise RuntimeError(f"Docker image {image} lacks this run's ownership label")
        revocation.run("docker", "save", "-o", archive, image, seconds=60)
        if minikube_image_ids(minikube, image):
            raise RuntimeError(f"minikube image tag {image} already exists")

        nodes = minikube_nodes(kubectl)
        loaded_id = None

        def remove_loaded_image():
            remove_minikube_image(minikube, nodes, image, owner, loaded_id)

        register(f"minikube image {image}", remove_loaded_image)
        minikube("image", "load", archive, "--overwrite=false", seconds=180)
        loaded_id = owned_minikube_image_id(minikube, image, owner)
        if loaded_id is None:
            raise RuntimeError(f"minikube did not confirm the loaded image for {image}")
        create_namespace(kubectl, register, namespace, owner)
        kubectl("wait", "--for=create", "serviceaccount/default", "--timeout=30s",
                capture=True, seconds=35)
        yield kubectl, image, directory, namespace, owner


def run_service(profile, source_image):
    with service_environment(profile, source_image, "ech") as environment:
        kubectl, image, directory, namespace, owner = environment
        revocation.run("sh", str(PKI_SCRIPT), str(directory), INNER, PUBLIC, capture=True, seconds=30)
        for name, config_id, private in (("current", 7, True), ("stale", 6, False)):
            keygen(source_image, f"{namespace}-{name}", owner, directory / name, config_id, private)
        current = public_config(directory / "current/ech-public.pem")
        stale = public_config(directory / "stale/ech-public.pem")
        create_secret(kubectl, "server-fixture", {
            "inner.pem": directory / "inner.pem", "inner.key": directory / "inner.key",
            "public.pem": directory / "public.pem", "public.key": directory / "public.key",
            "current-key.pem": directory / "current/ech.pem", "retry-config.pem": current,
        })
        for case, config in (("accepted", current), ("retry", stale)):
            create_secret(kubectl, f"trust-{case}", {
                "ca.pem": directory / "ca.pem", "start-config.pem": config,
            })
            run_case(kubectl, image, retry=case == "retry")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="built browntls-e2e image")
    parser.add_argument("--profile", required=True, help="existing running minikube profile")
    args = parser.parse_args()
    try:
        run_service(args.profile, args.image)
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as error:
        print(f"minikube ECH check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
