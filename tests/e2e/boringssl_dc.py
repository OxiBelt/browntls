#!/usr/bin/env python3
"""Run one TLS 1.3 delegated-credential exchange against pinned BoringSSL."""

import argparse
import json
import secrets
import sys
import time

import e2e


PEER = "boringssl-dc"
SERVER_NAME = "tls-server.test"
PORT = 4433
MESSAGE = "BoringSSL delegated credential interoperability"
REPLY = MESSAGE[::-1]
DOCKER_USER = "65532:65532"


def check_browntls(output):
    records = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    if any(record.get("event") == "error" for record in records):
        raise RuntimeError("browntls client reported an error")
    connections = [record for record in records if record.get("event") == "connection"]
    if len(connections) != 1:
        raise RuntimeError("browntls did not report exactly one completed connection")
    record = connections[0]
    expected = {
        "role": "client",
        "version": "TLSv1_3",
        "delegated_credential": True,
        "peer_certificates": 1,
        "service_identity_matched": True,
        "sent": MESSAGE,
        "received": REPLY,
    }
    if any(record.get(name) != value for name, value in expected.items()):
        raise RuntimeError("browntls did not authenticate the delegated credential and exchange data")


def owned_containers(label):
    result = e2e.docker("ps", "-aq", "--filter", f"label={label}", check=False)
    return result.stdout.split()


def resource_label(kind, name, label_key):
    result = e2e.docker(kind, "inspect", "-f", f"{{{{ index .Labels \"{label_key}\" }}}}",
                        name, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def cleanup(run_id, network, volumes):
    label = f"{e2e.LABEL}={run_id}"
    problems = []
    containers = owned_containers(label)
    if containers:
        e2e.docker("rm", "-f", *containers, check=False)
    for volume in volumes:
        if resource_label("volume", volume, e2e.LABEL) == run_id:
            result = e2e.docker("volume", "rm", volume, check=False)
            if result.returncode:
                problems.append(f"could not remove owned Docker volume {volume}")
    if resource_label("network", network, e2e.LABEL) == run_id:
        result = e2e.docker("network", "rm", network, check=False)
        if result.returncode:
            problems.append(f"could not remove owned Docker network {network}")
    if owned_containers(label):
        problems.append("owned Docker containers remain after cleanup")
    for volume in volumes:
        if resource_label("volume", volume, e2e.LABEL) == run_id:
            problems.append(f"owned Docker volume remains after cleanup: {volume}")
    if resource_label("network", network, e2e.LABEL) == run_id:
        problems.append("owned Docker network remains after cleanup")
    return problems


def wait_listening(container, timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        output = e2e.docker("logs", container, check=False)
        logs = output.stdout + output.stderr
        if "listening" in logs.splitlines():
            return
        running = e2e.docker("inspect", "-f", "{{.State.Running}}", container,
                             check=False)
        if running.returncode or running.stdout.strip() != "true":
            state = e2e.docker("inspect", "-f",
                               "{{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}}",
                               container, check=False).stdout.strip()
            raise RuntimeError(f"BoringSSL server exited before listening ({state}): {logs[-2000:]}")
        time.sleep(0.2)
    raise RuntimeError("BoringSSL server did not report its listening socket")


def run_case(image, peer_image):
    run_id = secrets.token_hex(12)
    network = f"browntls-boringssl-dc-{run_id}"
    server_volume = f"{network}-server"
    client_volume = f"{network}-client"
    label = f"{e2e.LABEL}={run_id}"
    server_name = f"{network}-server"
    client_name = f"{network}-client"
    volumes = (server_volume, client_volume)
    error = None
    try:
        e2e.docker("network", "create", "--label", label, network)
        for volume in volumes:
            e2e.docker("volume", "create", "--label", label, volume)
            actual = resource_label("volume", volume, e2e.LABEL)
            if actual != run_id:
                raise RuntimeError(f"new Docker volume {volume} did not retain its run label")

        e2e.docker(
            "run", "--rm", "--label", label,
            "--mount", f"type=volume,src={server_volume},dst=/pki",
            "--mount", f"type=volume,src={client_volume},dst=/client",
            "--entrypoint", "python3", peer_image,
            "/usr/local/share/browntls-e2e/boringssl-dc-pki.py", "/pki", "/client",
            timeout=90,
        )

        server = e2e.docker(
            "run", "-d", "--name", server_name, "--label", label,
            "--network", network, "--network-alias", e2e.SERVER_ALIAS,
            "--mount", f"type=volume,src={server_volume},dst=/pki,readonly",
            "--user", DOCKER_USER, peer_image, "boringssl-dc-server",
            "/pki/server.der", "/pki/dc.der", "/pki/dc.key", timeout=30,
        ).stdout.strip()
        wait_listening(server)

        client_result = e2e.docker(
            "run", "--rm", "--name", client_name, "--label", label,
            "--network", network,
            "--mount", f"type=volume,src={client_volume},dst=/client,readonly",
            "--user", DOCKER_USER, image,
            "client", "--connect", f"{e2e.SERVER_ALIAS}:{PORT}",
            "--server-name", SERVER_NAME, "--ca", "/client/ca.pem",
            "--tls", "1.3", "--async", "--delegated-credentials",
            "--message", MESSAGE, "--expect-reply", REPLY, timeout=60, check=False,
        )
        client = client_result.stdout
        if client_result.returncode:
            server_logs = e2e.docker("logs", server, check=False)
            detail = (client_result.stdout + client_result.stderr +
                      server_logs.stdout + server_logs.stderr)
            raise RuntimeError(f"browntls client failed ({client_result.returncode}): {detail[-4000:]}")
        check_browntls(client)

        status = e2e.docker("wait", server, timeout=20).stdout.strip()
        logs = e2e.docker("logs", server, check=False).stdout
        if status != "0" or logs.splitlines().count(
                "accepted TLS 1.3 delegated credential and data") != 1:
            raise RuntimeError(f"BoringSSL server failed its delegated-credential exchange: {logs[-2000:]}")
        print("BoringSSL TLS 1.3 delegated credential: browntls authenticated and exchanged data",
              flush=True)
    except BaseException as caught:
        error = caught
        raise
    finally:
        problems = cleanup(run_id, network, volumes)
        if problems:
            detail = "Docker cleanup failed: " + "; ".join(problems)
            if error is None:
                raise RuntimeError(detail)
            print(detail, file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="built browntls-e2e image")
    parser.add_argument("--peer-image", default=e2e.peer_image_tag(PEER))
    parser.add_argument("--build-peer", action="store_true",
                        help="build the pinned BoringSSL delegated-credential image")
    args = parser.parse_args()
    if args.build_peer and args.peer_image != e2e.peer_image_tag(PEER):
        parser.error("--build-peer builds the default --peer-image tag")
    try:
        if args.build_peer:
            e2e.build_peer_image(PEER)
        if not e2e.image_exists(args.image):
            raise RuntimeError(f"browntls image {args.image} is missing")
        if not e2e.image_exists(args.peer_image):
            raise RuntimeError(f"BoringSSL image {args.peer_image} is missing; pass --build-peer")
        run_case(args.image, args.peer_image)
    except (OSError, RuntimeError) as error:
        print(f"BoringSSL delegated-credential e2e failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
