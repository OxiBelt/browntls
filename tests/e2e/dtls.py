#!/usr/bin/env python3
"""Run mutual DTLS 1.3 exchanges with wolfSSL in separate containers."""

import argparse
import sys

from e2e import (
    ARCHES,
    DockerError,
    Run,
    Suite,
    build_peer_image,
    events,
    image_exists,
    image_tag,
    output_tail,
    summarize,
)

SUITE = Suite("dtls13", "wolfSSL DTLS 1.3", "wolfssl", "wolfssl", frozenset())
PORT = "4433"
SERVER_NAME = "dtls-server.test"
PKI = "/pki/ecdsa-p256"
REQUEST = "hello from browntls"
REPLY = REQUEST[::-1]


def exchange(run: Run, browntls_role: str) -> bool:
    browntls_server = browntls_role == "server"
    server_image = run.image if browntls_server else run.peer
    client_image = run.peer if browntls_server else run.image
    wolf_command = ["wolfssl-dtls"]
    browntls_args = ["--tls", "1.3", "--group", "secp256r1"]
    server_command = (
        ["dtls-server", "--listen", f"0.0.0.0:{PORT}", "--cert", f"{PKI}/server.pem",
         "--key", f"{PKI}/server.key", "--client-ca", f"{PKI}/ca.pem", *browntls_args]
        if browntls_server else [*wolf_command, "server", SERVER_NAME, PORT]
    )
    client_command = (
        [*wolf_command, "client", SERVER_NAME, PORT] if browntls_server else
        ["dtls-client", "--connect", f"{SERVER_NAME}:{PORT}", "--server-name", SERVER_NAME,
         "--ca", f"{PKI}/ca.pem", "--cert", f"{PKI}/client.pem", "--key", f"{PKI}/client.key",
         *browntls_args]
    )
    print(f"DTLS 1.3 with browntls as {browntls_role}", flush=True)
    server = run.start_server(server_image, server_command, {}, alias=SERVER_NAME)
    if not run.wait_for_log(server, "listening", 10):
        server = run.finish_server(server, 1)
        print(f"server did not become ready (exit {server.exit_code})", file=sys.stderr)
        print(output_tail(server.stdout, server.stderr), file=sys.stderr)
        return False
    client = run.run_client(client_image, client_command, {})
    server = run.finish_server(server, 8)
    brown, wolf = (server, client) if browntls_server else (client, server)
    records = [record for record in events(brown.stdout) if record.get("event") == "connection"]
    sent, received = (REPLY, REQUEST) if browntls_server else (REQUEST, REPLY)
    passed = (
        brown.exit_code == wolf.exit_code == 0
        and "verified DTLSv1.3, payloads and close_notify" in wolf.stdout.splitlines()
        and len(records) == 1
        and records[0].get("role") == browntls_role
        and records[0].get("version") == "DTLSv1_3"
        and records[0].get("peer_certificates", 0) > 0
        and records[0].get("sent") == sent
        and records[0].get("received") == received
        and records[0].get("closed") is True
    )
    for role, container in (("server", server), ("client", client)):
        if passed:
            print(f"{role}: {summarize(container, role)}", flush=True)
        else:
            print(f"{role} (exit {container.exit_code})", file=sys.stderr)
            print(output_tail(container.stdout, container.stderr), file=sys.stderr)
    return passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True, choices=sorted(ARCHES))
    parser.add_argument("--image", help="browntls E2E image for the selected architecture")
    parser.add_argument("--skip-peer-build", action="store_true")
    args = parser.parse_args()
    image = args.image or image_tag(args.arch)
    run = Run(ARCHES[args.arch], SUITE, image)
    try:
        if not image_exists(image):
            raise DockerError(f"browntls image {image} is missing; build it with e2e.py")
        if not args.skip_peer_build:
            build_peer_image(SUITE.peer_image)
        if not image_exists(run.peer):
            raise DockerError(f"wolfSSL image {run.peer} is missing")
        with run:
            run.generate_pki(SERVER_NAME)
            results = [exchange(run, role) for role in ("client", "server")]
        return 0 if all(results) else 1
    except DockerError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
