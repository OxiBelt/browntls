#!/usr/bin/env python3
"""Qualify strict RFC 9973 TLS and DTLS services on an existing minikube profile."""

import argparse
import json
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import revocation

ROOT = revocation.ROOT
TCP_PORT = 4433
UDP_PORT = 4434
REQUEST = "RFC 9973 Kubernetes external PSK"
REPLY = REQUEST[::-1]
IDENTITY = "browntls-kubernetes-rfc9973"


def pod(role, protocol, image, args, secret):
    return revocation.resource("Pod", role, {
        "metadata": {"labels": {"role": role, "protocol": protocol}},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "activeDeadlineSeconds": 240,
            "containers": [{
                "name": "peer",
                "image": image,
                "imagePullPolicy": "Never",
                "args": args,
                "volumeMounts": [{"name": "pki", "mountPath": "/pki", "readOnly": True}],
            }],
            "volumes": [{"name": "pki", "secret": {"secretName": secret}}],
        },
    })


def wait_done(kubectl, role, expected, timeout=100):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        phase = kubectl("get", "pod", role, "-o", "jsonpath={.status.phase}",
                        capture=True).strip()
        if phase in {"Succeeded", "Failed"}:
            if phase != expected:
                log = kubectl("logs", role, capture=True, check=False)
                raise RuntimeError(f"{role} ended in {phase}: {log[-3000:]}")
            return kubectl("logs", role, capture=True)
        time.sleep(0.5)
    raise RuntimeError(f"{role} did not end within {timeout}s")


def wait_listening(kubectl, server, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        output = kubectl("logs", server, capture=True, check=False)
        if '"event":"listening"' in output:
            return
        phase = kubectl("get", "pod", server, "-o", "jsonpath={.status.phase}",
                        capture=True, check=False).strip()
        if phase in {"Failed", "Succeeded"}:
            raise RuntimeError(f"server ended before listening: {output[-3000:]}")
        time.sleep(0.5)
    raise RuntimeError("server did not start listening")


def check_logs(output, role, protocol):
    rows = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    rows = [row for row in rows if row.get("event") == "connection"]
    if len(rows) != 1:
        raise RuntimeError(f"{role} has no single completed handshake")
    row = rows[0]
    version = "TLSv1_3" if protocol == "tcp" else "DTLSv1_3"
    expected_sent, expected_received = ((REQUEST, REPLY) if role == "client" else (REPLY, REQUEST))
    if (row.get("role") != role or row.get("version") != version or
            row.get("cert_with_extern_psk") is not True or
            row.get("sent") != expected_sent or row.get("received") != expected_received):
        raise RuntimeError(f"{role} reported an invalid {protocol} exchange: {row}")
    if role == "client" and row.get("peer_certificates", 0) < 1:
        raise RuntimeError("client did not validate the server certificate")
    if protocol == "tcp" and row.get("io") != "async":
        raise RuntimeError("TCP case did not use browntls::tokio")


def one_protocol(kubectl, namespace, image, protocol, pki_secret):
    tcp = protocol == "tcp"
    port = TCP_PORT if tcp else UDP_PORT
    subcommand = "server" if tcp else "dtls-server"
    client_command = "client" if tcp else "dtls-client"
    base = ["--tls", "1.3", "--external-psk-file", "/pki/psk.bin",
            "--external-psk-identity", IDENTITY]
    if tcp:
        base.append("--async")
    server_args = [subcommand, "--listen", f"0.0.0.0:{port}", "--cert",
                   "/pki/server.pem", "--key", "/pki/server.key", *base]
    server_name = f"server-{protocol}"
    client_name = f"client-{protocol}"
    service_name = f"tls-server-{protocol}"
    server_dns = f"{service_name}.{namespace}.svc.cluster.local"
    server = pod("server", protocol, image, server_args, pki_secret)
    server["metadata"]["name"] = server_name
    service = revocation.resource("Service", service_name, {
        "spec": {"selector": {"role": "server", "protocol": protocol},
                 "ports": [{"name": protocol, "port": port, "targetPort": port,
                            "protocol": "TCP" if tcp else "UDP"}]},
    })
    kubectl("apply", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "List",
                                                   "items": [service, server]}))
    wait_listening(kubectl, server_name)
    client_args = [client_command, "--connect", f"{service_name}:{port}", "--server-name",
                   server_dns, "--ca", "/pki/ca.pem", *base,
                   "--message", REQUEST, "--expect-reply", REPLY]
    client = pod("client", protocol, image, client_args, pki_secret)
    client["metadata"]["name"] = client_name
    kubectl("apply", "-f", "-", data=json.dumps(client))
    client_log = wait_done(kubectl, client_name, "Succeeded")
    server_log = wait_done(kubectl, server_name, "Succeeded")
    check_logs(client_log, "client", protocol)
    check_logs(server_log, "server", protocol)
    print(f"minikube {protocol.upper()} service: strict PSK, certificate extension and data passed",
          flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="local browntls-e2e image")
    parser.add_argument("--profile", required=True,
                        help="existing running minikube profile; this runner never starts or stops it")
    args = parser.parse_args()
    run_id = secrets.token_hex(4)
    namespace = f"browntls-psk-{run_id}"
    image = f"browntls-e2e:psk-{run_id}"

    def minikube(*command, **kwargs):
        return revocation.run("minikube", "--profile", args.profile, *command, **kwargs)

    def kubectl(*command, **kwargs):
        return minikube("kubectl", "--", "--context", args.profile, "-n", namespace,
                        *command, **kwargs)

    tagged = False
    namespace_created = False
    try:
        revocation.run("docker", "tag", args.image, image)
        tagged = True
        with tempfile.TemporaryDirectory(prefix="browntls-psk-") as temp:
            directory = Path(temp)
            psk = directory / "psk.bin"
            psk.write_bytes(secrets.token_bytes(32))
            psk.chmod(0o600)
            tar = str(directory / "image.tar")
            revocation.run("docker", "save", "-o", tar, image)
            minikube("image", "load", tar, seconds=180)
            kubectl("create", "namespace", namespace)
            namespace_created = True
            for protocol in ("tcp", "udp"):
                server_dns = f"tls-server-{protocol}.{namespace}.svc.cluster.local"
                pki_dir = directory / protocol
                pki_dir.mkdir()
                revocation.run("sh", str(ROOT / "tests/e2e/peer/gen-pki.sh"), str(pki_dir),
                               server_dns, capture=True)
                pki = pki_dir / "ecdsa-p256"
                secret = f"pki-{protocol}"
                kubectl("create", "secret", "generic", secret,
                        *(f"--from-file={name}={pki / name}" for name in
                          ("ca.pem", "server.pem", "server.key")),
                        f"--from-file=psk.bin={psk}")
                one_protocol(kubectl, namespace, image, protocol, secret)
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
        print(f"minikube RFC 9973 check failed: {error}", file=sys.stderr)
        if namespace_created:
            kubectl("get", "pods,services", "-o", "wide", check=False, seconds=15)
            for role in ("server", "client"):
                kubectl("logs", role, "--tail=50", check=False, seconds=15)
        return 1
    finally:
        if namespace_created:
            kubectl("delete", "namespace", namespace, "--timeout=60s", check=False,
                    seconds=70)
        if tagged:
            minikube("image", "rm", image, check=False, seconds=45)
            revocation.run("docker", "image", "rm", image, check=False, seconds=30)


if __name__ == "__main__":
    sys.exit(main())
