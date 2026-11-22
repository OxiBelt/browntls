#!/usr/bin/env python3
"""Prove TLS 1.3 Zstandard certificate compression with OpenSSL on the wire."""

import argparse
import json
import sys

import e2e

PORT = 4433
MESSAGE = e2e.MESSAGE
PEER = "openssl-zstd"
PEER_TAG = e2e.peer_image_tag(PEER)
DOCKERFILE = e2e.E2E_DIR / "peer" / "openssl-zstd.Dockerfile"


def build_peer():
    e2e.docker("build", "--pull", "-t", PEER_TAG, "-f", str(DOCKERFILE),
               str(e2e.E2E_DIR / "peer"), timeout=1800,
               env={"BUILDKIT_PROGRESS": "plain"})


def brown_args(role):
    cert = ["--cert", "/pki/ecdsa-p256/" + role + ".pem", "--key",
            "/pki/ecdsa-p256/" + role + ".key"]
    common = ["--tls", "1.3", "--zstd-cert-compression"]
    if role == "server":
        return ["server", "--listen", f"0.0.0.0:{PORT}", "--accept", "1",
                "--client-ca", "/pki/ecdsa-p256/ca.pem", *cert, *common]
    return ["client", "--connect", f"tls-server:{PORT}", "--server-name", "tls-server",
            "--ca", "/pki/ecdsa-p256/ca.pem", *cert, "--message", MESSAGE,
            "--expect-reply", MESSAGE[::-1], *common]


def check_brown(container, role):
    records = [row for row in e2e.events(container.stdout)
               if row.get("event") == "connection"]
    sent, received = (MESSAGE, MESSAGE[::-1]) if role == "client" else (MESSAGE[::-1], MESSAGE)
    expected = {"role": role, "version": "TLSv1_3",
                "sent": sent, "received": received}
    if container.exit_code != 0 or len(records) != 1 or any(
            records[0].get(key) != value for key, value in expected.items()):
        raise RuntimeError(f"browntls {role} failed mTLS or data exchange: {container}")
    if records[0].get("peer_certificates", 0) < 1:
        raise RuntimeError(f"browntls {role} did not authenticate a certificate")
    if records[0].get("zstd_certificate_messages_received", 0) < 1:
        raise RuntimeError(f"browntls {role} did not decode a Zstandard certificate")


def check_wire(container, role):
    records = [json.loads(line) for line in container.stdout.splitlines()
               if line.startswith("{")]
    wires = [row for row in records if row.get("event") == "wire"]
    expected = {"role": role, "mutual_auth": True, "data": True}
    if container.exit_code != 0 or len(wires) != 1 or any(
            wires[0].get(key) != value for key, value in expected.items()) or any(
                wires[0].get(key, 0) < 1 for key in ("sent_zstd", "received_zstd")):
        raise RuntimeError(f"OpenSSL {role} did not observe Zstd certificates both ways: {container}")


def exchange(run, brown_role):
    peer_role = "server" if brown_role == "client" else "client"
    if peer_role == "server":
        command = ["openssl-zstd", "server", "0.0.0.0", MESSAGE]
        brown_client = brown_args("client")
    else:
        command = ["openssl-zstd", "client", "tls-server", MESSAGE]
        brown_client = brown_args("server")
    server_image = PEER_TAG if peer_role == "server" else run.image
    server_command = command if peer_role == "server" else brown_client
    server = run.start_server(server_image, server_command, {})
    if not run.wait_for_log(server, "listening", 20):
        raise RuntimeError(f"{peer_role} did not start: {run.finish_server(server, 2)}")
    if brown_role == "client":
        client = run.run_client(run.image, brown_client, {})
    else:
        client = run.run_client(PEER_TAG, command, {})
    finished = run.finish_server(server, 30)
    try:
        check_wire(finished if peer_role == "server" else client, peer_role)
        check_brown(client if brown_role == "client" else finished, brown_role)
    except RuntimeError as error:
        raise RuntimeError(f"{error}\nclient: {client}\nserver: {finished}") from error
    print(f"TLS 1.3 browntls {brown_role} / OpenSSL {peer_role}: mTLS, data, "
          "and Zstd CompressedCertificate observed in both wire directions", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="browntls-e2e image built with --zstd")
    parser.add_argument("--skip-peer-build", action="store_true")
    args = parser.parse_args()
    if not e2e.image_exists(args.image):
        raise SystemExit(f"browntls image {args.image} is not available")
    if not args.skip_peer_build:
        print(f"building {PEER_TAG} from {DOCKERFILE.relative_to(e2e.REPO_ROOT)}", flush=True)
        build_peer()
    elif not e2e.image_exists(PEER_TAG):
        raise SystemExit(f"OpenSSL peer image {PEER_TAG} is missing")

    suite = e2e.Suite("openssl-zstd", "OpenSSL Zstandard compression", "openssl", PEER,
                      frozenset())
    arch = e2e.ARCHES["amd64"]
    try:
        with e2e.Run(arch, suite, args.image) as run:
            run.generate_pki()
            for role in ("client", "server"):
                exchange(run, role)
        return 0
    except (e2e.DockerError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"Zstandard OpenSSL interoperability failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
