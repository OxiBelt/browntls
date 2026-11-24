#!/usr/bin/env python3
"""Qualify delegated credentials and asymmetric record limits through Services."""

import argparse
import json
import sys
import time

import ech_service
import revocation

PORT = 4433
MESSAGE = ("phase-2" * 586)[:4096]
DTLS_MESSAGE = "dtls-2" * 80
TCP_STYLES = ("buffered", "unbuffered")
DTLS_VERSIONS = {"1.2": "DTLSv1_2", "1.3": "DTLSv1_3"}
PKI_SCRIPT = revocation.ROOT / "tests/e2e/peer/gen-pki.sh"
COMMAND_ERRORS = ech_service.COMMAND_ERRORS


def events(output):
    return [json.loads(line) for line in output.splitlines() if line.startswith("{")]


def check_tcp(output, role, style):
    records = [row for row in events(output) if row.get("event") == "connection"]
    expected = {
        "event": "connection",
        "role": role,
        "version": "TLSv1_3",
        "record_size_limit_configured": "512" if role == "client" else "1024",
        "delegated_credential": True,
        "peer_certificates": 1,
        "sent": MESSAGE if role == "client" else MESSAGE[::-1],
        "received": MESSAGE[::-1] if role == "client" else MESSAGE,
    }
    if len(records) != 1 or any(records[0].get(key) != value for key, value in expected.items()):
        raise RuntimeError(f"{role} {style} did not confirm mutual delegated credentials: {records}")
    expected_io = "tokio-unbuffered" if style == "unbuffered" else "async"
    if records[0].get("io") != expected_io:
        raise RuntimeError(f"{role} {style} exchange used {records[0].get('io')!r}, expected {expected_io!r}")


def check_dtls(output, role, version):
    records = [row for row in events(output) if row.get("event") == "connection"]
    expected = {
        "event": "connection",
        "role": role,
        "version": DTLS_VERSIONS[version],
        "record_size_limit_configured": "512" if role == "client" else "1024",
        "max_application_data": (1024 if role == "client" else 512) - (version == "1.3"),
        "io": "tokio-dtls",
        "peer_certificates": 1,
        "sent": DTLS_MESSAGE if role == "client" else DTLS_MESSAGE[::-1],
        "received": DTLS_MESSAGE[::-1] if role == "client" else DTLS_MESSAGE,
        "closed": True,
    }
    if len(records) != 1 or any(records[0].get(key) != value for key, value in expected.items()):
        raise RuntimeError(f"{role} DTLS {version} did not confirm the exchange: {records}")
    if max(len(records[0]["sent"]), len(records[0]["received"])) > 480:
        raise RuntimeError(f"{role} DTLS {version} application data exceeds the 480-byte qualification payload")


def tcp_objects(image, style):
    suffix = style
    service_name = f"dc-{suffix}"
    server_name = f"dc-server-{suffix}"
    client_name = f"dc-client-{suffix}"
    service = revocation.resource("Service", service_name, {
        "spec": {"type": "ClusterIP", "selector": {"app": server_name}, "ports": [
            {"port": PORT, "targetPort": PORT, "protocol": "TCP"},
        ]},
    })
    common = ["--tls", "1.3", "--delegated-credentials"]
    if style == "buffered":
        common.append("--async")
    elif style == "unbuffered":
        common.append("--unbuffered")
    server_args = ["server", "--listen", f"0.0.0.0:{PORT}", "--accept", "1",
                   "--cert", "/fixture/server.pem", "--key", "/fixture/server.key",
                   "--client-ca", "/fixture/ca.pem", "--record-size-limit", "1024",
                   "--message", MESSAGE, *common]
    client_args = ["client", "--connect", f"{service_name}:{PORT}", "--server-name",
                   "record-limit.test", "--ca", "/fixture/ca.pem", "--cert",
                   "/fixture/client.pem", "--key", "/fixture/client.key",
                   "--record-size-limit", "512", "--message", MESSAGE,
                   "--expect-reply", MESSAGE[::-1], "--tls", "1.3",
                   "--delegated-credentials"]
    if style == "buffered":
        client_args.append("--async")
    elif style == "unbuffered":
        client_args.append("--unbuffered")
    return (
        service,
        ech_service.pod(server_name, image, server_args, "dc-fixture"),
        ech_service.pod(client_name, image, client_args, "dc-fixture"),
    )


def dtls_objects(image, version):
    service_name = f"dtls-{version.replace('.', '')}"
    server_name = f"dtls-server-{version.replace('.', '')}"
    client_name = f"dtls-client-{version.replace('.', '')}"
    service = revocation.resource("Service", service_name, {
        "spec": {"type": "ClusterIP", "selector": {"app": server_name}, "ports": [
            {"port": PORT, "targetPort": PORT, "protocol": "UDP"},
        ]},
    })
    server_args = ["dtls-server", "--listen", f"0.0.0.0:{PORT}", "--accept", "1",
                   "--cert", "/fixture/server.pem", "--key", "/fixture/server.key",
                   "--client-ca", "/fixture/ca.pem", "--tls", version,
                   "--async", "--record-size-limit", "1024", "--message", DTLS_MESSAGE]
    client_args = ["dtls-client", "--connect", f"{service_name}:{PORT}", "--server-name",
                   "record-limit.test", "--ca", "/fixture/ca.pem", "--cert", "/fixture/client.pem",
                   "--key", "/fixture/client.key", "--tls", version,
                   "--async", "--record-size-limit", "512", "--message", DTLS_MESSAGE,
                   "--expect-reply", DTLS_MESSAGE[::-1]]
    return (
        service,
        ech_service.pod(server_name, image, server_args, "dc-fixture"),
        ech_service.pod(client_name, image, client_args, "dc-fixture"),
    )


def wait_pod(kubectl, pod_name, listening=False):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        phase = kubectl("get", "pod", pod_name, "-o", "jsonpath={.status.phase}",
                        capture=True, seconds=12).strip()
        if phase == "Succeeded" and not listening:
            return kubectl("logs", pod_name, capture=True, seconds=12)
        if phase in {"Failed", "Succeeded"}:
            raise RuntimeError(f"{pod_name} ended {phase} before becoming ready")
        if listening and phase == "Running":
            logs = kubectl("logs", pod_name, capture=True, check=False, seconds=12)
            if '"event":"listening"' in logs:
                return logs
        time.sleep(0.5)
    raise RuntimeError(f"{pod_name} did not finish within 90 seconds")


def run_tcp(kubectl, image, directory, style):
    service, server, client = tcp_objects(image, style)
    server_name, client_name = server["metadata"]["name"], client["metadata"]["name"]
    kubectl("create", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "List",
           "items": [service, server]}), seconds=30)
    wait_pod(kubectl, server_name, listening=True)
    kubectl("create", "-f", "-", data=json.dumps(client), seconds=30)
    check_tcp(wait_pod(kubectl, client_name), "client", style)
    check_tcp(wait_pod(kubectl, server_name), "server", style)
    print(f"TLS 1.3 {style}: mutual delegated credentials and asymmetric limits passed", flush=True)


def run_dtls(kubectl, image, version):
    service, server, client = dtls_objects(image, version)
    server_name, client_name = server["metadata"]["name"], client["metadata"]["name"]
    kubectl("create", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "List",
           "items": [service, server]}), seconds=30)
    wait_pod(kubectl, server_name, listening=True)
    kubectl("create", "-f", "-", data=json.dumps(client), seconds=30)
    check_dtls(wait_pod(kubectl, client_name), "client", version)
    check_dtls(wait_pod(kubectl, server_name), "server", version)
    print(f"DTLS {version}: asymmetric record size limits and application exchange passed", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="ready local browntls-e2e image")
    parser.add_argument("--profile", required=True, help="running minikube profile")
    args = parser.parse_args()
    try:
        with ech_service.service_environment(args.profile, args.image, "phase2") as env:
            kubectl, image, directory, _, _ = env
            revocation.run("sh", str(PKI_SCRIPT), str(directory), "record-limit.test",
                           "--delegated-credentials", capture=True, seconds=30)
            pki = directory / "ecdsa-p256"
            ech_service.create_secret(kubectl, "dc-fixture", {
                "ca.pem": pki / "ca.pem",
                "server.pem": pki / "server.pem",
                "server.key": pki / "server.key",
                "client.pem": pki / "client.pem",
                "client.key": pki / "client.key",
            })
            for style in TCP_STYLES:
                run_tcp(kubectl, image, directory, style)
            for version in DTLS_VERSIONS:
                run_dtls(kubectl, image, version)
    except COMMAND_ERRORS as error:
        print(f"Phase 2 record limit Kubernetes check failed: {error}", file=sys.stderr)
        return 1
    print("verified run-owned namespace and image cleanup", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
