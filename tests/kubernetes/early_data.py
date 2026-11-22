#!/usr/bin/env python3
"""Check external-PSK early data and ordinary traffic through TCP Services."""

import argparse
import json
import secrets
import sys

import ech_service
import revocation

PORT = 4433
EARLY_BYTES = 13


def objects(image, style, accepted, secret):
    decision = "accept" if accepted else "decline"
    scenario = f"{style}-{decision}"
    service = f"tls-{scenario}"
    server = f"server-{scenario}"
    client = f"client-{scenario}"
    service_object = revocation.resource("Service", service, {
        "spec": {"type": "ClusterIP", "selector": {"app": server}, "ports": [
            {"port": PORT, "targetPort": PORT, "protocol": "TCP"},
        ]},
    })
    args = ["/fixture/psk.bin", style, decision]
    return (
        service_object,
        ech_service.pod(server, image, ["early-data-server", f"0.0.0.0:{PORT}", *args], secret),
        ech_service.pod(client, image, ["early-data-client", f"{service}:{PORT}", *args], secret),
    )


def check_output(output, role, style, accepted):
    events = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    result = [row for row in events if row.get("event") != "listening"]
    expected = {
        "event": "early-data", "role": role, "style": style, "accepted": accepted,
        "early_bytes": EARLY_BYTES if role == "client" or accepted else 0,
        "unresent_bytes": EARLY_BYTES if role == "client" and not accepted else 0,
        "ordinary_exchange": True,
    }
    if result != [expected]:
        raise RuntimeError(f"{role} did not confirm {style} {expected}")


def run_case(kubectl, image, directory, style, accepted):
    secret = f"psk-{style}-{'accept' if accepted else 'decline'}"
    psk = directory / f"{secret}.bin"
    psk.write_bytes(secrets.token_bytes(32))
    psk.chmod(0o600)
    ech_service.create_secret(kubectl, secret, {"psk.bin": psk})
    service, server, client = objects(image, style, accepted, secret)
    server_name = server["metadata"]["name"]
    client_name = client["metadata"]["name"]
    kubectl("create", "-f", "-", data=json.dumps({
        "apiVersion": "v1", "kind": "List", "items": [service, server],
    }), seconds=30)
    try:
        ech_service.wait_pod(kubectl, server_name, listening=True)
        kubectl("create", "-f", "-", data=json.dumps(client), seconds=30)
        check_output(ech_service.wait_pod(kubectl, client_name), "client", style, accepted)
        check_output(ech_service.wait_pod(kubectl, server_name), "server", style, accepted)
    except ech_service.COMMAND_ERRORS:
        for name in (server_name, client_name):
            kubectl("logs", name, "--tail=25", check=False, seconds=15)
        raise
    print(f"{style} {'accept' if accepted else 'decline'}: early counts and 1-RTT passed",
          flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="local browntls-e2e image")
    parser.add_argument("--profile", required=True, help="running minikube profile")
    args = parser.parse_args()
    try:
        with ech_service.service_environment(args.profile, args.image, "early") as environment:
            kubectl, image, directory, _, _ = environment
            for style in ("buffered", "unbuffered"):
                for accepted in (True, False):
                    run_case(kubectl, image, directory, style, accepted)
    except ech_service.COMMAND_ERRORS as error:
        print(f"minikube early-data check failed: {error}", file=sys.stderr)
        return 1
    print("verified namespace and image cleanup", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
