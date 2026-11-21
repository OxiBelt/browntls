#!/usr/bin/env python3
"""Check certificate-authenticated DTLS through a minikube UDP Service."""

import argparse
import json
import ipaddress
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from revocation import ROOT, resource, run


PORT = 4433
REQUEST = "hello from browntls"
REBIND_REQUEST = "hello after rebind"
MODES = ("basic", "enhanced")
VERSIONS = {"1.2": "DTLSv1_2", "1.3": "DTLSv1_3"}


def pod(role, image, args):
    return resource("Pod", role, {
        "metadata": {"name": role, "labels": {"role": role}},
        "spec": {
            "restartPolicy": "Never",
            "serviceAccountName": "peer",
            "automountServiceAccountToken": False,
            "containers": [{
                "name": "peer",
                "image": image,
                "imagePullPolicy": "Never",
                "args": args,
                "volumeMounts": [{"name": "pki", "mountPath": "/pki", "readOnly": True}],
            }],
            "volumes": [{"name": "pki", "secret": {"secretName": role}}],
        },
    })


def address(value):
    if value.startswith("["):
        host, port = value[1:].split("]:", 1)
    else:
        host, port = value.rsplit(":", 1)
    return ipaddress.ip_address(host), int(port)


def check_exchange(output, role, version, mode):
    records = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    exchanges = [record for record in records if record.get("event") == "connection"]
    sent, received = (REQUEST, REQUEST[::-1]) if role == "client" else (REQUEST[::-1], REQUEST)
    if len(exchanges) != 1:
        raise RuntimeError(f"{role} recorded {len(exchanges)} successful exchanges")
    actual = exchanges[0]
    expected = {
        "role": role,
        "version": VERSIONS[version],
        "sent": sent,
        "received": received,
        "closed": True,
        "mode": mode,
        "rrc": True,
        "rebind_sent": REBIND_REQUEST if role == "client" else REBIND_REQUEST[::-1],
        "rebind_received": REBIND_REQUEST[::-1] if role == "client" else REBIND_REQUEST,
    }
    if any(actual.get(key) != value for key, value in expected.items()):
        raise RuntimeError(f"{role} recorded an unexpected DTLS exchange: {actual}")
    if actual.get("peer_certificates", 0) < 1:
        raise RuntimeError(f"{role} did not authenticate its peer certificate")
    if role == "client":
        if address(actual["initial_local"])[1] == address(actual["rebound_local"])[1]:
            raise RuntimeError("client source port did not change")
        if actual.get("old_socket_dropped") is not True:
            raise RuntimeError("client did not drop its old socket")
    else:
        if address(actual["initial_peer"]) != address(actual["handle"]):
            raise RuntimeError("server handle differs from the admitted tuple")
        if address(actual["initial_peer"]) == address(actual["rebound_peer"]):
            raise RuntimeError("server validated source tuple did not change")


def wait_for(kubectl, role, target, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        phase = kubectl("get", "pod", role, "-o", "jsonpath={.status.phase}", capture=True).strip()
        if target == "listening":
            output = kubectl("logs", role, capture=True, check=False)
            if '"event":"listening"' in output:
                return
        if phase == target:
            return
        if phase in {"Failed", "Succeeded"}:
            raise RuntimeError(f"{role} ended with phase {phase} while waiting for {target}")
        time.sleep(0.5)
    raise RuntimeError(f"{role} did not reach {target} in {timeout}s")


def run_version(kubectl, directory, namespace, image, version, mode):
    hostname = f"peer.{namespace}.svc.cluster.local"
    run("sh", str(ROOT / "tests/e2e/peer/gen-pki.sh"), str(directory), hostname, capture=True)
    pki = directory / "ecdsa-p256"
    apis = ["--tls", version, "--group", "secp256r1", "--dtls-rebind", mode]
    for role in ("server", "client"):
        kubectl("create", "secret", "generic", role, f"--from-file=ca.pem={pki / 'ca.pem'}",
                f"--from-file=cert.pem={pki / (role + '.pem')}",
                f"--from-file=key.pem={pki / (role + '.key')}")
    cert = ["--cert", "/pki/cert.pem", "--key", "/pki/key.pem"]
    server = pod("server", image, ["dtls-server", "--listen", f"0.0.0.0:{PORT}",
                                    "--client-ca", "/pki/ca.pem", *cert, *apis])
    service = resource("Service", "peer", {
        "spec": {"selector": {"role": "server"},
                 "ports": [{"port": PORT, "targetPort": PORT, "protocol": "UDP"}]},
    })
    service_account = resource("ServiceAccount", "peer", {})
    kubectl("apply", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "List",
                                                 "items": [service_account, service, server]}))
    wait_for(kubectl, "server", "listening", 90)
    client = pod("client", image, ["dtls-client", "--connect", f"{hostname}:{PORT}",
                                    "--server-name", hostname, "--ca", "/pki/ca.pem",
                                    *cert, *apis])
    kubectl("apply", "-f", "-", data=json.dumps(client))
    wait_for(kubectl, "client", "Succeeded", 90)
    wait_for(kubectl, "server", "Succeeded", 45)
    for role in ("client", "server"):
        check_exchange(kubectl("logs", role, capture=True), role, version, mode)
    print(f"DTLS {version} {mode} mutual authentication and rebind exchanges passed over the UDP Service",
          flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="local browntls-e2e image with DTLS support")
    parser.add_argument("--profile", help="reuse an already running minikube profile")
    parser.add_argument("--version", action="append", choices=VERSIONS)
    args = parser.parse_args()
    run_id = f"browntls-dtls-{secrets.token_hex(4)}"
    profile = args.profile or run_id
    image = f"browntls-e2e:{run_id}"

    def minikube(*command, **kwargs):
        return run("minikube", "--profile", profile, *command, **kwargs)

    tagged = False
    try:
        if not args.profile:
            minikube("start", "--driver=docker", "--container-runtime=containerd",
                     "--kubernetes-version=v1.37.0", "--keep-context", "--cpus=2",
                     "--memory=4096", "--wait-timeout=180s", seconds=360)
        run("docker", "tag", args.image, image)
        tagged = True
        with tempfile.TemporaryDirectory(prefix=run_id) as temp:
            tar = str(Path(temp) / "peer.tar")
            run("docker", "save", "-o", tar, image)
            minikube("image", "load", tar, seconds=180)
            cases = [(version, mode) for version in (args.version or VERSIONS) for mode in MODES]
            for index, (version, mode) in enumerate(cases):
                namespace = f"{run_id}-{index}"

                def kubectl(*command, **kwargs):
                    return minikube("kubectl", "--", "--context", profile, "-n", namespace,
                                    *command, **kwargs)

                kubectl("create", "namespace", namespace)
                try:
                    run_version(kubectl, Path(temp) / namespace, namespace, image, version, mode)
                except (OSError, RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired):
                    kubectl("get", "pods,services", "-o", "wide", check=False, seconds=15)
                    for role in ("server", "client"):
                        kubectl("logs", role, "--tail=30", check=False, seconds=15)
                    raise
                finally:
                    kubectl("delete", "namespace", namespace, "--timeout=60s", check=False,
                            seconds=70)
        return 0
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(f"DTLS Kubernetes check failed: {error}", file=sys.stderr)
        return 1
    finally:
        if tagged:
            minikube("image", "rm", image, check=False, seconds=45)
            run("docker", "image", "rm", image, check=False, seconds=30)
        if not args.profile:
            minikube("delete", check=False, seconds=90)


if __name__ == "__main__":
    sys.exit(main())
