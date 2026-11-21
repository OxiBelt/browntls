#!/usr/bin/env python3
"""Run full mutual DTLS exchanges with wolfSSL and OpenSSL in containers."""

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

SUITES = {
    "wolfssl": Suite("dtls13", "wolfSSL DTLS 1.3", "wolfssl", "wolfssl", frozenset()),
    "openssl": Suite("dtls12", "OpenSSL DTLS 1.2", "openssl", "openssl-dtls", frozenset()),
}
CID_SUITE = Suite("dtls-cid", "wolfSSL DTLS CID", "wolfssl-cid", "wolfssl", frozenset())
TLS12_SUITE = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
PORT = "4433"
SERVER_NAME = "dtls-server.test"
PKI = "/pki/ecdsa-p256"
REQUEST = "hello from browntls"
REPLY = REQUEST[::-1]


def version_sets(suite: Suite) -> tuple[tuple[str, ...], ...]:
    # OpenSSL supports DTLS 1.2 only; the second case explicitly offers both
    # versions on browntls and must still select 1.2 in each browntls role.
    if suite.implementation == "openssl":
        return (("1.2",), ("1.2", "1.3"))
    return (("1.2",), ("1.3",)) if suite.implementation == "wolfssl-cid" else (("1.3",),)


def exchange(run: Run, browntls_role: str, versions: tuple[str, ...]) -> bool:
    browntls_server = browntls_role == "server"
    server_image = run.image if browntls_server else run.peer
    client_image = run.peer if browntls_server else run.image
    openssl = run.suite.implementation == "openssl"
    cid = run.suite.implementation == "wolfssl-cid"
    peer_command = ["openssl-dtls" if openssl else "wolfssl-dtls"]
    browntls_args = [arg for version in versions for arg in ("--tls", version)]
    browntls_args += ["--group", "secp256r1"]
    if cid:
        browntls_args += ["--dtls-cid"]
    if openssl:
        browntls_args += ["--suite", TLS12_SUITE]
        if "1.3" in versions:
            # Keep both protocol versions usable in the mixed configuration.
            browntls_args += ["--suite", "TLS13_AES_128_GCM_SHA256"]
    server_command = (
        ["dtls-server", "--listen", f"0.0.0.0:{PORT}", "--cert", f"{PKI}/server.pem",
         "--key", f"{PKI}/server.key", "--client-ca", f"{PKI}/ca.pem", *browntls_args]
        if browntls_server else [*peer_command, "server", SERVER_NAME, PORT,
                                 *(["--cid", versions[0]] if cid else [])]
    )
    client_command = (
        [*peer_command, "client", SERVER_NAME, PORT, *(["--cid", versions[0]] if cid else [])]
        if browntls_server else
        ["dtls-client", "--connect", f"{SERVER_NAME}:{PORT}", "--server-name", SERVER_NAME,
         "--ca", f"{PKI}/ca.pem", "--cert", f"{PKI}/client.pem", "--key", f"{PKI}/client.key",
         *browntls_args]
    )
    print(f"{run.suite.description}, browntls {browntls_role} permitting {versions}", flush=True)
    server = run.start_server(server_image, server_command, {}, alias=SERVER_NAME)
    if not run.wait_for_log(server, "listening", 10):
        server = run.finish_server(server, 1)
        print(f"server did not become ready (exit {server.exit_code})", file=sys.stderr)
        print(output_tail(server.stdout, server.stderr), file=sys.stderr)
        return False
    client = run.run_client(client_image, client_command, {})
    server = run.finish_server(server, 8)
    brown, peer = (server, client) if browntls_server else (client, server)
    records = [record for record in events(brown.stdout) if record.get("event") == "connection"]
    sent, received = (REPLY, REQUEST) if browntls_server else (REQUEST, REPLY)
    marker = (f"verified DTLSv1.{versions[0][-1]}, bidirectional CID, mTLS, "
              "full handshake, payloads and close_notify") if cid else (
        "verified DTLSv1.2, ECDHE-ECDSA-AES128-GCM-SHA256, EMS, mTLS, "
        "full handshake, payloads and close_notify" if openssl else
        "verified DTLSv1.3, payloads and close_notify")
    passed = (
        brown.exit_code == peer.exit_code == 0
        and marker in peer.stdout.splitlines()
        and len(records) == 1
        and records[0].get("role") == browntls_role
        and records[0].get("version") == ("DTLSv1_2" if openssl or (cid and versions == ("1.2",)) else "DTLSv1_3")
        and (not openssl or records[0].get("suite") == TLS12_SUITE)
        and records[0].get("handshake") in ("Full", "FullWithHelloRetryRequest")
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
    parser.add_argument("--suite", choices=["all", *SUITES, "wolfssl-cid"], default="all")
    parser.add_argument("--skip-peer-build", action="store_true")
    args = parser.parse_args()
    image = args.image or image_tag(args.arch)
    suites = (list(SUITES.values()) if args.suite == "all" else
              [CID_SUITE if args.suite == "wolfssl-cid" else SUITES[args.suite]])
    try:
        if not image_exists(image):
            raise DockerError(f"browntls image {image} is missing; build it with e2e.py")
        results = []
        for suite in suites:
            run = Run(ARCHES[args.arch], suite, image)
            if not args.skip_peer_build:
                build_peer_image(suite.peer_image)
            if not image_exists(run.peer):
                raise DockerError(f"{suite.description} image {run.peer} is missing")
            with run:
                run.generate_pki(SERVER_NAME)
                results.extend(exchange(run, role, versions)
                               for versions in version_sets(suite)
                               for role in ("client", "server"))
        return 0 if all(results) else 1
    except DockerError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
