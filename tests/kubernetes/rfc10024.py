#!/usr/bin/env python3
"""Qualify RFC 10024 hybrid key exchanges through TLS and DTLS Services."""

import argparse
import json
import secrets
import subprocess
import sys
import tempfile
from contextlib import suppress
from pathlib import Path

import extern_psk
import revocation

ROOT = revocation.ROOT
TCP_PORT = 4433
UDP_PORT = 4434
REQUEST = "RFC 10024 Kubernetes authenticated exchange"
REPLY = REQUEST[::-1]
GROUPS = (
    "X25519MLKEM768",
    "secp256r1MLKEM768",
    "secp384r1MLKEM1024",
)


def connection_rows(output):
    rows = []
    for line in output.splitlines():
        if line.startswith("{"):
            row = json.loads(line)
            if row.get("event") == "connection":
                rows.append(row)
    return rows


def check_connection(output, role, protocol, group):
    rows = connection_rows(output)
    if len(rows) != 1:
        raise RuntimeError(f"{role} did not report exactly one completed handshake: {rows}")
    row = rows[0]
    version = "TLSv1_3" if protocol == "tcp" else "DTLSv1_3"
    handshake = "Full" if protocol == "tcp" else "FullWithHelloRetryRequest"
    sent, received = (REQUEST, REPLY) if role == "client" else (REPLY, REQUEST)
    if (row.get("role") != role or row.get("version") != version or
            row.get("group") != group or row.get("handshake") != handshake or
            row.get("sent") != sent or row.get("received") != received):
        raise RuntimeError(f"{role} reported an invalid {protocol} exchange: {row}")
    if role == "client":
        if row.get("peer_certificates", 0) < 1:
            raise RuntimeError("client did not authenticate the server certificate")
        if row.get("service_identity_matched") is not True:
            raise RuntimeError("client did not verify the Service DNS identity")
    elif row.get("peer_certificates") != 0:
        raise RuntimeError("server unexpectedly reported client certificates")
    expected_io = "async" if protocol == "tcp" else "tokio-dtls"
    if row.get("io") != expected_io:
        raise RuntimeError(f"{role} did not use the expected Tokio adapter: {row.get('io')!r}")


def scenario(kubectl, namespace, image, protocol, group):
    is_tcp = protocol == "tcp"
    port = TCP_PORT if is_tcp else UDP_PORT
    suffix = f"{protocol}-{group.lower()}"
    server_name = f"server-{suffix}"
    client_name = f"client-{suffix}"
    service_name = f"kx-{suffix}"
    server_dns = f"{service_name}.{namespace}.svc.cluster.local"
    server_command = "server" if is_tcp else "dtls-server"
    client_command = "client" if is_tcp else "dtls-client"
    server_args = [server_command, "--listen", f"0.0.0.0:{port}", "--cert",
                   "/pki/server.pem", "--key", "/pki/server.key", "--accept", "1",
                   "--tls", "1.3", "--group", group, "--async"]
    client_args = [client_command, "--connect", f"{service_name}:{port}",
                   "--server-name", server_dns, "--reference-id", f"dns:{server_dns}",
                   "--ca", "/pki/ca.pem", "--message", REQUEST, "--expect-reply", REPLY,
                   "--tls", "1.3", "--group", group, "--async"]

    server = extern_psk.pod(server_name, protocol, image, server_args, "server-pki")
    server["metadata"]["name"] = server_name
    service = revocation.resource("Service", service_name, {
        "spec": {"selector": {"role": server_name, "protocol": protocol},
                 "ports": [{"name": protocol, "port": port, "targetPort": port,
                            "protocol": "TCP" if is_tcp else "UDP"}]},
    })
    kubectl("apply", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "List",
                                                     "items": [service, server]}))
    extern_psk.wait_listening(kubectl, server_name)

    client = extern_psk.pod(client_name, protocol, image, client_args, "trust")
    client["metadata"]["name"] = client_name
    kubectl("apply", "-f", "-", data=json.dumps(client))
    client_log = extern_psk.wait_done(kubectl, client_name, "Succeeded")
    server_log = extern_psk.wait_done(kubectl, server_name, "Succeeded")
    check_connection(client_log, "client", protocol, group)
    check_connection(server_log, "server", protocol, group)
    print(f"minikube {protocol.upper()} Service: {group} authenticated and exchanged data",
          flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="local browntls-e2e image")
    parser.add_argument("--profile", required=True,
                        help="existing running profile; this runner never starts or stops it")
    args = parser.parse_args()
    run_id = secrets.token_hex(4)
    namespace = f"browntls-rfc10024-{run_id}"
    image = f"browntls-e2e:rfc10024-{run_id}"

    def minikube(*command, **kwargs):
        return revocation.run("minikube", "--profile", args.profile, *command, **kwargs)

    def kubectl(*command, **kwargs):
        return minikube("kubectl", "--", "--context", args.profile, "-n", namespace,
                        *command, **kwargs)

    tagged = namespace_created = False
    try:
        revocation.run("docker", "tag", args.image, image)
        tagged = True
        with tempfile.TemporaryDirectory(prefix="browntls-rfc10024-") as temporary:
            root = Path(temporary)
            archive = str(root / "image.tar")
            revocation.run("docker", "save", "-o", archive, image)
            minikube("image", "load", archive, seconds=180)
            kubectl("create", "namespace", namespace)
            namespace_created = True
            pki = root / "pki"
            pki.mkdir()
            server_dns = f"*.{namespace}.svc.cluster.local"
            revocation.run("sh", str(ROOT / "tests/e2e/peer/gen-pki.sh"), str(pki),
                           server_dns, capture=True)
            ecdsa = pki / "ecdsa-p256"
            kubectl("create", "secret", "generic", "server-pki",
                    *(f"--from-file={ecdsa / name}" for name in ("server.pem", "server.key")))
            kubectl("create", "secret", "generic", "trust", f"--from-file={ecdsa / 'ca.pem'}")
            for protocol in ("tcp", "udp"):
                for group in GROUPS:
                    scenario(kubectl, namespace, image, protocol, group)
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
        print(f"minikube RFC 10024 check failed: {error}", file=sys.stderr)
        if namespace_created:
            kubectl("get", "pods,services", "-o", "wide", check=False, seconds=15)
            for protocol in ("tcp", "udp"):
                for group in GROUPS:
                    suffix = f"{protocol}-{group.lower()}"
                    for role in ("client", "server"):
                        kubectl("logs", f"{role}-{suffix}", "--tail=50", check=False,
                                seconds=15)
        return 1
    finally:
        try:
            if namespace_created:
                kubectl("delete", "namespace", namespace, "--timeout=60s", seconds=70)
        finally:
            if tagged:
                try:
                    with suppress(RuntimeError):
                        minikube("image", "rm", image, seconds=45)
                finally:
                    revocation.run("docker", "image", "rm", image, check=False, seconds=30)


if __name__ == "__main__":
    sys.exit(main())
