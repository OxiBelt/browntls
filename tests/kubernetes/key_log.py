#!/usr/bin/env python3
"""Qualify TLS key-log file permissions over isolated minikube TCP Services."""

import argparse
import ipaddress
import json
import subprocess
import sys
import time

import ech_service
import revocation

PORT = 4433
MESSAGE = "key log qualification request"
OBSERVER_IMAGE = "busybox:1.36.1"
UID = 65532


def pod(name, image, args, directory_mode):
    mode = "0700" if directory_mode == "private" else "0777"
    observer = (
        {"name": "observer", "image": OBSERVER_IMAGE, "imagePullPolicy": "IfNotPresent",
         "command": ["sh", "-c", "while :; do sleep 3600; done"],
         "volumeMounts": [{"name": "key-log", "mountPath": "/key-log", "readOnly": True}]}
    )
    body = revocation.resource("Pod", name, {
        "metadata": {"name": name, "labels": {"app": name}},
        "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "activeDeadlineSeconds": 180,
            "securityContext": {"runAsNonRoot": True, "runAsUser": UID,
                                "runAsGroup": UID, "fsGroup": UID},
            "initContainers": [{"name": "prepare-key-log-volume", "image": OBSERVER_IMAGE,
                                "imagePullPolicy": "IfNotPresent", "command": ["sh", "-c",
                                    f"chown {UID}:{UID} /key-log && chmod {mode} /key-log"],
                                "securityContext": {"runAsUser": 0, "runAsGroup": 0,
                                                    "runAsNonRoot": False},
                                "volumeMounts": [{"name": "key-log",
                                                  "mountPath": "/key-log"}]}],
            "containers": [{"name": "peer", "image": image, "imagePullPolicy": "Never",
                            "args": [*args, "--key-log"], "env": [{"name": "SSLKEYLOGFILE",
                                "value": "/key-log/session.keys"}],
                            "volumeMounts": [{"name": "key-log", "mountPath": "/key-log"}]},
                         observer],
            "volumes": [{"name": "key-log", "emptyDir": {"medium": "Memory"}}],
        },
    })
    return body


def service_objects(image, directory_mode, name, certificate_name):
    server_name, client_name = f"server-{name}", f"client-{name}"
    service = revocation.resource("Service", f"peer-{name}", {"spec": {
        "type": "ClusterIP", "selector": {"app": server_name},
        "ports": [{"port": PORT, "targetPort": PORT, "protocol": "TCP"}],
    }})
    server_args = ["server", "--listen", f"0.0.0.0:{PORT}", "--accept", "1",
                   "--cert", "/fixture/server.pem", "--key", "/fixture/server.key",
                   "--client-ca", "/fixture/ca.pem", "--message", MESSAGE, "--tls", "1.3",
                   "--async"]
    client_args = ["client", "--connect", f"peer-{name}:{PORT}", "--server-name",
                   certificate_name, "--ca", "/fixture/ca.pem", "--cert",
                   "/fixture/client.pem", "--key", "/fixture/client.key", "--message",
                   MESSAGE, "--expect-reply", MESSAGE[::-1], "--tls", "1.3", "--async",
                   "--wait", "25"]
    return (service,
            pod(server_name, image, server_args, directory_mode),
            pod(client_name, image, client_args, directory_mode))


def check_exchange(output, role):
    try:
        rows = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    except (TypeError, ValueError):
        raise RuntimeError(f"{role} output was not valid peer JSON") from None
    events = [row for row in rows if row.get("event") == "connection"]
    sent, received = (MESSAGE, MESSAGE[::-1]) if role == "client" else (MESSAGE[::-1], MESSAGE)
    if len(events) != 1 or any(events[0].get(key) != value for key, value in {
            "role": role, "version": "TLSv1_3", "peer_certificates": 1,
            "sent": sent, "received": received, "io": "async"}.items()):
        raise RuntimeError(f"{role} did not complete the authenticated application exchange")


def wait_peer(kubectl, pod_name, listening=False):
    deadline = time.monotonic() + 80
    while time.monotonic() < deadline:
        try:
            pod_state = json.loads(kubectl("get", "pod", pod_name, "-o", "json",
                                           capture=True, seconds=25))
        except (subprocess.TimeoutExpired, RuntimeError):
            continue
        phase = pod_state.get("status", {}).get("phase")
        statuses = pod_state.get("status", {}).get("containerStatuses", [])
        peer_state = next((item.get("state", {}) for item in statuses
                           if item.get("name") == "peer"), {})
        terminated = peer_state.get("terminated")
        if terminated is not None:
            code = terminated.get("exitCode")
            reason = terminated.get("reason", "unknown")
            if listening or code != 0:
                raise RuntimeError(f"{pod_name} exited before expected state ({reason}, {code})")
            return
        if listening and phase == "Running":
            try:
                output = kubectl("logs", pod_name, "-c", "peer", capture=True, seconds=25)
            except (subprocess.TimeoutExpired, RuntimeError):
                continue
            if '"event":"listening"' in output:
                return
        elif phase == "Failed":
            raise RuntimeError(f"{pod_name} exited before the expected peer state")
        time.sleep(0.5)
    raise RuntimeError(f"{pod_name} did not reach the expected peer state")


def check_file(kubectl, pod_name, enabled):
    command = ["exec", pod_name, "-c", "observer", "--", "sh", "-c",
               "if [ -f /key-log/session.keys ] && [ -s /key-log/session.keys ]; then "
               "stat -c %a /key-log/session.keys; "
               "elif [ -e /key-log/session.keys ]; then printf empty; else printf absent; fi"]
    mode = kubectl(*command, capture=True, seconds=15).strip()
    expected = "600" if enabled else "absent"
    if mode != expected:
        raise RuntimeError(f"{pod_name} key-log file state did not match the feature setting")


def run_case(kubectl, image, name, enabled, directory_mode, fixture, server_name):
    service, server, client = service_objects(image, directory_mode, name, server_name)
    for role, item in (("server", server), ("client", client)):
        secret = f"fixture-{name}-{role}"
        ech_service.create_secret(kubectl, secret, {
            "ca.pem": fixture / "ca.pem",
            f"{role}.pem": fixture / f"{role}.pem",
            f"{role}.key": fixture / f"{role}.key",
        })
        item["spec"]["containers"][0]["volumeMounts"].append(
            {"name": "fixture", "mountPath": "/fixture", "readOnly": True})
        item["spec"]["volumes"].append({"name": "fixture", "secret": {
            "secretName": secret, "defaultMode": 0o440}})
    kubectl("create", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "List",
            "items": [service, server]}), seconds=30)
    wait_peer(kubectl, server["metadata"]["name"], listening=True)
    ip = ipaddress.ip_address(kubectl(
        "get", "service", service["metadata"]["name"],
        "-o", "jsonpath={.spec.clusterIP}", capture=True, seconds=25,
    ).strip())
    # Connect to the Service IP while preserving the certificate's DNS name.
    # This avoids depending on DNS propagation for a newly created Service.
    args = client["spec"]["containers"][0]["args"]
    args[args.index("--connect") + 1] = f"[{ip}]:{PORT}" if ip.version == 6 else f"{ip}:{PORT}"
    kubectl("create", "-f", "-", data=json.dumps(client), seconds=30)
    wait_peer(kubectl, client["metadata"]["name"])
    wait_peer(kubectl, server["metadata"]["name"])
    for role, item in (("client", client), ("server", server)):
        pod_name = item["metadata"]["name"]
        check_exchange(kubectl("logs", pod_name, "-c", "peer", capture=True), role)
        check_file(kubectl, pod_name, enabled and directory_mode == "private")
    print(f"{name}: authenticated exchange and key-log file state qualified", flush=True)


def run_service(profile, feature_image, plain_image, kubectl_binary=None):
    for enabled, source_image in ((True, feature_image), (False, plain_image)):
        purpose = "key-log" if enabled else "no-key-log"
        with ech_service.service_environment(profile, source_image, purpose, kubectl_binary) as env:
            kubectl, image, directory, namespace, _owner = env
            hostname = f"*.{namespace}.svc.cluster.local"
            pki = directory / "pki"
            revocation.run("sh", str(revocation.ROOT / "tests/e2e/peer/gen-pki.sh"),
                           str(pki), hostname, capture=True, seconds=60)
            fixture = pki / "ecdsa-p256"
            for directory_mode in ("private", "permissive"):
                name = f"{'on' if enabled else 'off'}-{directory_mode}"
                server_name = f"peer-{name}.{namespace}.svc.cluster.local"
                run_case(kubectl, image, name, enabled, directory_mode, fixture, server_name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-log-image", required=True, help="peer image built with --key-log")
    parser.add_argument("--plain-image", required=True, help="peer image built without --key-log")
    parser.add_argument("--profile", required=True,
                        help="existing running minikube profile; lifecycle remains with caller")
    parser.add_argument("--kubectl", help="optional local kubectl binary for the specified context")
    args = parser.parse_args()
    try:
        run_service(args.profile, args.key_log_image, args.plain_image, args.kubectl)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(f"key-log Kubernetes check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
