#!/usr/bin/env python3
"""Exercise accepted and authenticated stale ECH over minikube TCP Services."""

import argparse
import base64
import binascii
from contextlib import ExitStack
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


def keygen(image, name, directory, config_id, private):
    directory.mkdir()
    run = revocation.run
    try:
        run("docker", "create", "--name", name, "--network", "none", "--user", "0:0",
            image, "ech-keygen", "--out", "/ech", "--public-name", PUBLIC,
            "--config-id", str(config_id), "--ech-pem", capture=True, seconds=30)
        run("docker", "start", "-a", name, capture=True, seconds=30)
        files = ["ech-public.pem", "ech.pem"] if private else ["ech-public.pem"]
        for file in files:
            run("docker", "cp", f"{name}:/ech/{file}", str(directory / file), seconds=30)
    finally:
        run("docker", "rm", "-f", name, capture=True, check=False, seconds=30)


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


def run_service(profile, source_image):
    run_id = secrets.token_hex(8)
    namespace = f"browntls-ech-{run_id}"
    image = f"browntls-e2e:ech-{run_id}"

    def minikube(*args, **kwargs):
        return revocation.run("minikube", "--profile", profile, *args, **kwargs)

    def kubectl(*args, **kwargs):
        return minikube("kubectl", "--", "--context", profile, "-n", namespace, *args, **kwargs)

    with tempfile.TemporaryDirectory(prefix="browntls-ech-") as temporary, ExitStack() as cleanup:
        directory = Path(temporary)
        archive = str(directory / "image.tar")
        revocation.run("sh", str(PKI_SCRIPT), temporary, INNER, PUBLIC, capture=True, seconds=30)
        for name, config_id, private in (("current", 7, True), ("stale", 6, False)):
            keygen(source_image, f"{namespace}-{name}", directory / name, config_id, private)
        current = public_config(directory / "current/ech-public.pem")
        stale = public_config(directory / "stale/ech-public.pem")
        # Some CRI runtimes remove all tags for an image ID. Give this run a
        # distinct image config so removing it cannot remove the source image.
        revocation.run("docker", "image", "inspect", source_image, capture=True, seconds=30)
        revocation.run("docker", "build", "--network=none", "--build-arg", f"BASE={source_image}",
                       "--label", f"org.oxibelt.browntls-e2e.run={namespace}", "--tag", image,
                       "-", data="ARG BASE=scratch\nFROM ${BASE}\n", capture=True, seconds=60)
        cleanup.callback(revocation.run, "docker", "image", "rm", image, seconds=30, check=False)
        revocation.run("docker", "save", "-o", archive, image, seconds=60)
        cleanup.callback(minikube, "image", "rm", image, seconds=45, check=False)
        minikube("image", "load", archive, seconds=180)
        cleanup.callback(kubectl, "delete", "namespace", namespace, "--timeout=60s",
                         "--ignore-not-found=true", check=False, seconds=70)
        kubectl("create", "namespace", namespace, seconds=30)
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
