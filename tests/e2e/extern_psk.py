#!/usr/bin/env python3
"""Qualify RFC 9973 against the pinned independent wolfSSL peer."""

import argparse
import json
import select
import secrets
import subprocess
import sys
import time
from pathlib import Path

import e2e

ROOT = e2e.REPO_ROOT
PEER_DOCKERFILE = e2e.E2E_DIR / "peer" / "wolfssl.Dockerfile"
PEER_CONTEXT = PEER_DOCKERFILE.parent
PORT = 4433
SERVER_NAME = "tls-server.test"
IDENTITY = "browntls-e2e-rfc9973"
REQUEST = "RFC 9973 external PSK interoperability"
REPLY = REQUEST[::-1]


def run(*args, input_data=None, capture=True, timeout=120, check=True):
    result = subprocess.run(args, cwd=ROOT, input=input_data, capture_output=capture,
                            timeout=timeout, check=False)
    if check and result.returncode:
        detail = result.stderr.decode("utf-8", "replace")[-3000:] if capture else ""
        raise RuntimeError(f"{args[0]} exited {result.returncode}: {detail}")
    return result


def records(output):
    return [json.loads(line) for line in output.splitlines() if line.startswith("{")]


def check_browntls(output, role, protocol):
    matches = [r for r in records(output) if r.get("event") == "connection"]
    if len(matches) != 1:
        raise RuntimeError(f"browntls {role} did not report one completed handshake")
    record = matches[0]
    expected = "TLSv1_3" if protocol == "tcp" else "DTLSv1_3"
    if (record.get("role") != role or record.get("version") != expected or
            record.get("cert_with_extern_psk") is not True or
            (role == "client" and record.get("peer_certificates", 0) < 1) or
            record.get("sent") != (REQUEST if role == "client" else REPLY) or
            record.get("received") != (REPLY if role == "client" else REQUEST)):
        raise RuntimeError(f"browntls {role} did not verify RFC 9973 and the data exchange")
    if protocol == "tcp" and record.get("io") != "async":
        raise RuntimeError("TCP qualification did not use browntls::tokio")


def start_server(image, network, volume, command, container_name):
    return subprocess.Popen(
        ["docker", "run", "--rm", "--name", container_name, "--network", network,
         "--network-alias", SERVER_NAME,
         "-v", f"{volume}:/pki:ro", image, *command],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def wait_server(server, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if server.poll() is not None:
            _, error = server.communicate()
            raise RuntimeError("server exited before listening: " +
                               error.decode("utf-8", "replace")[-2500:])
        readable, _, _ = select.select([server.stdout], [], [], 0.2)
        if readable:
            line = server.stdout.readline()
            if not line:
                continue
            if b"listening" in line:
                return
    raise RuntimeError("server did not report readiness within 20 seconds")


def scenario(image, wolf_image, network, volume, protocol, brown_role, suffix):
    port = str(PORT)
    pki = "/pki/ecdsa-p256"
    brown_opts = ["--tls", "1.3", "--external-psk-file", "/pki/psk.bin",
                  "--external-psk-identity", IDENTITY]
    if protocol == "tcp":
        brown_opts.append("--async")
        brown_server = ["server", "--listen", f"0.0.0.0:{port}", "--cert",
                        f"{pki}/server.pem", "--key", f"{pki}/server.key", *brown_opts]
        brown_client = ["client", "--connect", f"{SERVER_NAME}:{port}", "--server-name",
                        SERVER_NAME, "--ca", f"{pki}/ca.pem", *brown_opts,
                        "--message", REQUEST, "--expect-reply", REPLY]
    else:
        brown_server = ["dtls-server", "--listen", f"0.0.0.0:{port}", "--cert",
                        f"{pki}/server.pem", "--key", f"{pki}/server.key", *brown_opts]
        brown_client = ["dtls-client", "--connect", f"{SERVER_NAME}:{port}", "--server-name",
                        SERVER_NAME, "--ca", f"{pki}/ca.pem", *brown_opts,
                        "--message", REQUEST, "--expect-reply", REPLY]
    wolf_server = ["wolfssl-extern-psk", "server", "udp" if protocol == "udp" else "tcp",
                   "0.0.0.0", port, f"{pki}/ca.pem", f"{pki}/server.pem",
                   f"{pki}/server.key", "/pki/psk.bin"]
    wolf_client = ["wolfssl-extern-psk", "client", "udp" if protocol == "udp" else "tcp",
                   SERVER_NAME, port, f"{pki}/ca.pem", f"{pki}/client.pem",
                   f"{pki}/client.key", "/pki/psk.bin"]
    server_is_brown = brown_role == "server"
    server_image = image if server_is_brown else wolf_image
    server_command = brown_server if server_is_brown else wolf_server
    client_image = image if brown_role == "client" else wolf_image
    client_command = brown_client if brown_role == "client" else wolf_client
    name = f"browntls-extern-psk-{suffix}"
    client_name = f"{name}-client"
    server = start_server(server_image, network, volume, server_command, name)
    try:
        wait_server(server)
        try:
            result = run("docker", "run", "--rm", "--name", client_name, "--network", network,
                         "-v", f"{volume}:/pki:ro", client_image, *client_command,
                         timeout=45, check=False)
        except subprocess.TimeoutExpired as error:
            if server.poll() is None:
                server.kill()
            server_out, server_err = server.communicate()
            client_out = error.stdout or b""
            client_err = error.stderr or b""
            raise RuntimeError(f"client timed out; stdout={client_out[-2000:]!r}; "
                               f"stderr={client_err[-2000:]!r}; "
                               f"server stdout={server_out[-2000:]!r}; "
                               f"server stderr={server_err[-2000:]!r}") from error
        output = result.stdout.decode("utf-8", "replace")
        error = result.stderr.decode("utf-8", "replace")
        server_out, server_err = server.communicate(timeout=45)
        if result.returncode or server.returncode:
            raise RuntimeError(f"peer command failed ({result.returncode}, {server.returncode}): "
                               f"{output[-2500:]} {error[-2500:]} "
                               f"{server_out.decode('utf-8', 'replace')[-2500:]} "
                               f"{server_err.decode('utf-8', 'replace')[-2500:]}")
        if brown_role == "client":
            check_browntls(output, "client", protocol)
            wolf_output = server_out.decode("utf-8", "replace")
        else:
            server_records = server_out.decode("utf-8", "replace")
            check_browntls(server_records, "server", protocol)
            wolf_output = output
        if "verified TLS 1.3 cert_with_extern_psk, certificate, payload and close_notify" not in wolf_output:
            raise RuntimeError("wolfSSL did not verify its certificate and complete the data exchange")
        print(f"{protocol} browntls-as-{brown_role}: verified ServerHello extension 33, "
              "certificate validation and bidirectional data", flush=True)
    finally:
        if server.poll() is None:
            server.kill()
            server.communicate()
        run("docker", "rm", "-f", name, check=False)
        run("docker", "rm", "-f", client_name, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="local browntls-e2e image")
    parser.add_argument("--build-peer", action="store_true", help="build pinned wolfSSL peer")
    parser.add_argument("--peer-image", default="browntls-e2e:wolfssl-extern-psk")
    args = parser.parse_args()
    run_id = secrets.token_hex(5)
    network, volume = f"browntls-psk-{run_id}", f"browntls-psk-{run_id}"
    key = secrets.token_bytes(32)
    try:
        if args.build_peer:
            run("docker", "build", "-f", str(PEER_DOCKERFILE), "-t", args.peer_image,
                str(PEER_CONTEXT), timeout=1800)
        if not e2e.image_exists(args.image):
            raise RuntimeError(f"browntls image {args.image} is missing")
        if not e2e.image_exists(args.peer_image):
            raise RuntimeError(f"wolfSSL image {args.peer_image} is missing; pass --build-peer")
        run("docker", "network", "create", "--label", f"{e2e.LABEL}={run_id}", network)
        run("docker", "volume", "create", "--label", f"{e2e.LABEL}={run_id}", volume)
        run("docker", "run", "--rm", "-v", f"{volume}:/pki", "alpine:3.24",
            "sh", "-c", "mkdir -p /pki/ecdsa-p256 && chmod 700 /pki /pki/ecdsa-p256")
        run("docker", "run", "--rm", "-i", "-v", f"{volume}:/pki", "alpine:3.24",
            "sh", "-c", "umask 077; cat > /pki/psk.bin; chmod 0444 /pki/psk.bin",
            input_data=key)
        run("docker", "run", "--rm", "-v", f"{volume}:/pki", "--entrypoint", "sh",
            args.peer_image, "/usr/local/share/browntls-e2e/gen-pki.sh", "/pki", SERVER_NAME,
            timeout=600)
        for proto in ("tcp", "udp"):
            for role in ("client", "server"):
                scenario(args.image, args.peer_image, network, volume, proto, role,
                         f"{proto}-{role}-{run_id}")
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        # Never include secret material or a command containing key bytes.
        print(f"RFC 9973 e2e failed: {error}", file=sys.stderr)
        return 1
    finally:
        key = b"\0" * len(key)
        run("docker", "rm", "-f", f"browntls-extern-psk-{run_id}", check=False)
        run("docker", "volume", "rm", "-f", volume, check=False)
        run("docker", "network", "rm", network, check=False)


if __name__ == "__main__":
    sys.exit(main())
