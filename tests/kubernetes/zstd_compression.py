#!/usr/bin/env python3
"""Exercise observed Zstandard certificate decoding over Tokio Services."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

import ech_service
import revocation

ROOT = revocation.ROOT
PORT = 4433
MESSAGE = "zstd service request"


def check_exchange(output, role, io, version):
    rows = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    records = [row for row in rows if row.get("event") == "connection"]
    sent, received = (MESSAGE, MESSAGE[::-1]) if role == "client" else (MESSAGE[::-1], MESSAGE)
    expected = {"role": role, "version": version, "peer_certificates": 1,
                "sent": sent, "received": received, "io": io}
    if len(records) != 1 or any(records[0].get(key) != value for key, value in expected.items()):
        raise RuntimeError(f"{role} did not report authenticated application data: {records}")
    if records[0].get("zstd_certificate_messages_received", 0) < 1:
        raise RuntimeError(f"{role} did not successfully decompress a Zstandard certificate")


def run_case(kubectl, directory, namespace, image, name, transport, io):
    service_name = f"peer-{name}"
    server_name = f"server-{name}"
    client_name = f"client-{name}"
    secret_name = f"fixture-{name}"
    hostname = f"{service_name}.{namespace}.svc.cluster.local"
    pki = directory / name
    revocation.run("sh", str(ROOT / "tests/e2e/peer/gen-pki.sh"), str(pki), hostname,
                   capture=True, seconds=60)
    cert_dir = pki / "ecdsa-p256"
    kubectl("create", "secret", "generic", secret_name,
            f"--from-file=ca.pem={cert_dir / 'ca.pem'}",
            f"--from-file=server.pem={cert_dir / 'server.pem'}",
            f"--from-file=server.key={cert_dir / 'server.key'}",
            f"--from-file=client.pem={cert_dir / 'client.pem'}",
            f"--from-file=client.key={cert_dir / 'client.key'}")
    protocol = "dtls-server" if transport == "UDP" else "server"
    client_protocol = "dtls-client" if transport == "UDP" else "client"
    flags = ["--tls", "1.3", "--zstd-cert-compression"]
    if transport == "UDP" or io == "async":
        flags.append("--async")
    elif io == "tokio-unbuffered":
        flags.append("--unbuffered")
    service = revocation.resource("Service", service_name, {"spec": {
        "type": "ClusterIP", "selector": {"app": server_name},
        "ports": [{"port": PORT, "targetPort": PORT, "protocol": transport}],
    }})
    server_args = [protocol, "--listen", f"0.0.0.0:{PORT}", "--accept", "1",
                   "--cert", "/fixture/server.pem", "--key", "/fixture/server.key",
                   "--client-ca", "/fixture/ca.pem", "--message", MESSAGE, *flags]
    kubectl("apply", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "List",
               "items": [service, ech_service.pod(server_name, image, server_args, secret_name)]}))
    try:
        ech_service.wait_pod(kubectl, server_name, listening=True)
        address = kubectl("get", "service", service_name, "-o",
                          "jsonpath={.spec.clusterIP}", capture=True).strip()
        if not address or address == "None":
            raise RuntimeError(f"Service {service_name} has no ClusterIP")
        endpoint = f"[{address}]:{PORT}" if ":" in address else f"{address}:{PORT}"
        client_args = [client_protocol, "--connect", endpoint, "--server-name", hostname,
                       "--ca", "/fixture/ca.pem", "--cert", "/fixture/client.pem",
                       "--key", "/fixture/client.key", "--message", MESSAGE,
                       "--expect-reply", MESSAGE[::-1], *flags]
        kubectl("apply", "-f", "-", data=json.dumps(
            ech_service.pod(client_name, image, client_args, secret_name)))
        ech_service.wait_pod(kubectl, client_name)
        ech_service.wait_pod(kubectl, server_name)
        for role, pod_name in (("client", client_name), ("server", server_name)):
            check_exchange(kubectl("logs", pod_name, capture=True), role, io,
                           "DTLSv1_3" if transport == "UDP" else "TLSv1_3")
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired):
        kubectl("get", "pods,services", "-o", "wide", check=False, seconds=15)
        for pod_name in (server_name, client_name):
            kubectl("logs", pod_name, "--tail=30", check=False, seconds=15)
        raise
    print(f"{name}: both endpoints decoded Zstd certificates and exchanged authenticated data",
          flush=True)


def run_service(profile, source_image):
    with ech_service.service_environment(profile, source_image, "zstd") as environment:
        kubectl, image, directory, namespace, _owner = environment
        cases = [("tcp-buffered", "TCP", "async"),
                 ("tcp-unbuffered", "TCP", "tokio-unbuffered"),
                 ("dtls-udp", "UDP", "tokio-dtls")]
        for name, transport, io in cases:
            run_case(kubectl, directory, namespace, image, name, transport, io)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="browntls-e2e image built with --zstd")
    parser.add_argument("--profile", required=True,
                        help="existing running minikube profile; lifecycle remains with caller")
    args = parser.parse_args()
    try:
        run_service(args.profile, args.image)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(f"Zstd Kubernetes check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
