#!/usr/bin/env python3
"""Run full mutual DTLS exchanges with wolfSSL, OpenSSL and Pion in containers."""

import argparse
import ipaddress
import sys
from urllib.parse import urlsplit

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
PQC_SUITE = Suite("dtls13-pqc", "wolfSSL DTLS 1.3 RFC 10024", "wolfssl-pqc", "wolfssl", frozenset())
CID_SUITE = Suite("dtls-cid", "wolfSSL DTLS CID", "wolfssl-cid", "wolfssl", frozenset())
PION_SUITE = Suite("dtls-migration", "Pion DTLS migration", "pion", "pion", frozenset())
# Pion v4.0.2 can validate a remote move with both versions. AddPath is DTLS 1.3.
PION_CASES = (("client", "1.2", "basic"), ("client", "1.3", "basic"),
              ("server", "1.3", "basic"), ("server", "1.3", "enhanced"))
REBIND = "hello after rebind"
PQC_GROUPS = ("X25519MLKEM768", "secp256r1MLKEM768", "secp384r1MLKEM1024")
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


def resumption_records(stdout: str, role: str, mechanism: str, *, oracle: bool) -> bool:
    records = [record for record in events(stdout) if record.get("event") == "connection"]
    sent, received = (REPLY, REQUEST) if role == "server" else (REQUEST, REPLY)
    return len(records) == 2 and all(
        record.get("role") == role
        and record.get("index") == index
        and record.get("mechanism") == mechanism
        and record.get("version") == "DTLSv1_2"
        and record.get("suite") == TLS12_SUITE
        and record.get("handshake") == ("Full" if index == 0 else "Resumed")
        and record.get("peer_certificates", 0) > 0
        and record.get("sent") == sent
        and record.get("received") == received
        and record.get("closed") is True
        and (not oracle or record.get("ems") is True)
        for index, record in enumerate(records)
    )


def migration_records(brown: dict, stdout: str, role: str, version: str, mode: str) -> bool:
    records = [event for event in events(stdout) if event.get("event") == "migration"]
    if len(records) != 1:
        return False
    peer = records[0]
    server = role == "server"
    side = "peer" if server else "local"
    if not (
        peer.get("role") == ("client" if server else "server")
        and peer.get("version") == version
        and brown.get("bidirectional_cid") is True
        and brown.get("rrc") is True
        and brown.get("mode") == mode
        and brown.get("rebind_received") == (REBIND if server else REBIND[::-1])
        and brown.get("rebind_sent") == (REBIND[::-1] if server else REBIND)
        and (bool(brown.get("handle")) if server else brown.get("old_socket_dropped") is True)
    ):
        return False
    # A local socket may report its wildcard IP. Its UDP port must agree
    # with the remote endpoint's independent observation on the Docker bridge.
    def endpoint(value):
        parsed = urlsplit("//" + value)
        return ipaddress.ip_address(parsed.hostname), parsed.port

    try:
        ports = set()
        for stage, key in (("initial", "before"), ("rebound", "after")):
            brown_ip, brown_port = endpoint(brown[f"{stage}_{side}"])
            peer_ip, peer_port = endpoint(peer[key])
            if not brown_port or brown_port != peer_port:
                return False
            if brown_ip != peer_ip and not (brown_ip.is_unspecified or peer_ip.is_unspecified):
                return False
            ports.add(brown_port)
        return len(ports) == 2
    except (KeyError, TypeError, ValueError):
        return False


def exchange(run: Run, browntls_role: str, versions: tuple[str, ...],
             mechanism: str | None = None, group: str | None = None, mode: str | None = None) -> bool:
    if mechanism is not None and (
        run.suite.implementation != "openssl" or versions != ("1.2",)
        or mechanism not in ("session-id", "ticket")
    ):
        raise ValueError("resumption requires OpenSSL, DTLS 1.2 and session-id|ticket")
    pion = run.suite == PION_SUITE
    if pion != (mode is not None) or (pion and (
        len(versions) != 1 or (browntls_role, versions[0], mode) not in PION_CASES
    )):
        raise ValueError("unsupported Pion migration case")
    browntls_server = browntls_role == "server"
    pqc = run.suite.implementation == "wolfssl-pqc"
    if pqc != (group is not None) or (group is not None and group not in PQC_GROUPS):
        raise ValueError("RFC 10024 requires one of the three named hybrid groups")
    server_image = run.image if browntls_server else run.peer
    client_image = run.peer if browntls_server else run.image
    openssl = run.suite.implementation == "openssl"
    cid = run.suite.implementation == "wolfssl-cid"
    peer_command = ["openssl-dtls" if openssl else "wolfssl-dtls"]
    browntls_args = [arg for version in versions for arg in ("--tls", version)]
    browntls_args += ["--group", group or "secp256r1"]
    if pion:
        peer_command = ["pion-dtls"]
        browntls_args += ["--dtls-rebind", mode]
    if cid:
        browntls_args += ["--dtls-cid"]
    if openssl:
        browntls_args += ["--suite", TLS12_SUITE]
        if "1.3" in versions:
            # Keep both protocol versions usable in the mixed configuration.
            browntls_args += ["--suite", "TLS13_AES_128_GCM_SHA256"]
    peer_args = ["--group", group] if pqc else []
    if pion:
        peer_args = [versions[0]]
    server_command = (
        ["dtls-server", "--listen", f"0.0.0.0:{PORT}", "--cert", f"{PKI}/server.pem",
         "--key", f"{PKI}/server.key", "--client-ca", f"{PKI}/ca.pem", *browntls_args]
        if browntls_server else [*peer_command, "server", SERVER_NAME, PORT,
                                 *(["--cid", versions[0]] if cid else []), *peer_args]
    )
    client_command = (
        [*peer_command, "client", SERVER_NAME, PORT, *(["--cid", versions[0]] if cid else []), *peer_args]
        if browntls_server else
        ["dtls-client", "--connect", f"{SERVER_NAME}:{PORT}", "--server-name", SERVER_NAME,
         "--ca", f"{PKI}/ca.pem", "--cert", f"{PKI}/client.pem", "--key", f"{PKI}/client.key",
         *browntls_args]
    )
    if mechanism:
        brown_command, oracle_command = ((server_command, client_command) if browntls_server
                                         else (client_command, server_command))
        brown_command += ["--dtls12-resumption", mechanism,
                          "--accept" if browntls_server else "--connections", "2"]
        oracle_command.append(mechanism)
    print(f"{run.suite.description}, browntls {browntls_role} permitting {versions}"
          f"{', ' + group if group else ''}"
          f"{', ' + mode if mode else ''}"
          f"{', resumption ' + mechanism if mechanism else ''}", flush=True)
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
    handshakes = ("Full", "FullWithHelloRetryRequest")
    if pqc:
        marker = f"verified DTLSv1.3, {group}, mTLS, full handshake, payloads and close_notify"
        handshakes = ("FullWithHelloRetryRequest",)
    elif cid:
        marker = (f"verified DTLSv1.{versions[0][-1]}, bidirectional CID, mTLS, "
                  "full handshake, payloads and close_notify")
    elif openssl:
        marker = ("verified DTLSv1.2, ECDHE-ECDSA-AES128-GCM-SHA256, EMS, mTLS, "
                  "full handshake, payloads and close_notify")
    else:
        marker = "verified DTLSv1.3, payloads and close_notify"
    passed = (
        brown.exit_code == peer.exit_code == 0
        and (pion or marker in peer.stdout.splitlines())
        and len(records) == 1
        and records[0].get("role") == browntls_role
        and records[0].get("version") == ("DTLSv1_2" if openssl or versions == ("1.2",) else "DTLSv1_3")
        and (not openssl or records[0].get("suite") == TLS12_SUITE)
        and records[0].get("handshake") in handshakes
        and records[0].get("peer_certificates", 0) > 0
        and (group is None or records[0].get("group") == group)
        and records[0].get("sent") == sent
        and records[0].get("received") == received
        and records[0].get("closed") is True
    )
    if pion and passed:
        passed = migration_records(records[0], peer.stdout, browntls_role, versions[0], mode)
    if mechanism:
        passed = (
            brown.exit_code == peer.exit_code == 0
            and resumption_records(brown.stdout, browntls_role, mechanism, oracle=False)
            and resumption_records(peer.stdout, "client" if browntls_server else "server",
                                   mechanism, oracle=True)
        )
    for role, container in (("server", server), ("client", client)):
        if passed:
            if pion and container is peer:
                migration = next(e for e in events(peer.stdout) if e.get("event") == "migration")
                print(f"{role}: Pion DTLS {migration['version']}, "
                      f"{migration['before']} -> {migration['after']}", flush=True)
            else:
                print(f"{role}: {summarize(container, role)}", flush=True)
        else:
            print(f"{role} (exit {container.exit_code})", file=sys.stderr)
            print(output_tail(container.stdout, container.stderr), file=sys.stderr)
    return passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True, choices=sorted(ARCHES))
    parser.add_argument("--image", help="browntls E2E image for the selected architecture")
    parser.add_argument("--suite", choices=["all", *SUITES, "wolfssl-cid", "wolfssl-pqc", "pion"], default="all")
    parser.add_argument("--resumption", action="store_true",
                        help="only four DTLS 1.2 ID/ticket resumption cases (requires --suite openssl)")
    parser.add_argument("--skip-peer-build", action="store_true")
    parser.add_argument("--peer-image", help="use this local peer image with --skip-peer-build")
    args = parser.parse_args()
    if args.peer_image and (not args.skip_peer_build or args.suite == "all"):
        parser.error("--peer-image requires --skip-peer-build and one --suite")
    if args.resumption and args.suite != "openssl":
        parser.error("--resumption requires --suite openssl")
    image = args.image or image_tag(args.arch)
    suites = (list(SUITES.values()) if args.suite == "all" else
              [PION_SUITE if args.suite == "pion" else
               CID_SUITE if args.suite == "wolfssl-cid" else
               PQC_SUITE if args.suite == "wolfssl-pqc" else SUITES[args.suite]])
    try:
        if not image_exists(image):
            raise DockerError(f"browntls image {image} is missing; build it with e2e.py")
        results = []
        for suite in suites:
            run = Run(ARCHES[args.arch], suite, image)
            if args.peer_image:
                run.peer = args.peer_image
            if not args.skip_peer_build:
                build_peer_image(suite.peer_image)
            if not image_exists(run.peer):
                raise DockerError(f"{suite.description} image {run.peer} is missing")
            with run:
                run.generate_pki(SERVER_NAME)
                if args.resumption:
                    results.extend(exchange(run, role, ("1.2",), mechanism)
                                   for mechanism in ("session-id", "ticket")
                                   for role in ("client", "server"))
                elif suite == PION_SUITE:
                    results.extend(exchange(run, role, (version,), mode=mode)
                                   for role, version, mode in PION_CASES)
                elif suite == PQC_SUITE:
                    results.extend(exchange(run, role, ("1.3",), group=group)
                                   for group in PQC_GROUPS
                                   for role in ("client", "server"))
                else:
                    results.extend(exchange(run, role, versions)
                                   for versions in version_sets(suite)
                                   for role in ("client", "server"))
        return 0 if all(results) else 1
    except DockerError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
