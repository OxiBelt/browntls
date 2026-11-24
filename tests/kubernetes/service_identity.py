#!/usr/bin/env python3
"""Qualify RFC 9525 URI and SRV identities through TCP and UDP Services."""

import argparse
import json
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import revocation

ROOT = revocation.ROOT
PORTS = {"tcp": 4433, "udp": 4434}
CASES = (("tcp", "uri", "URI:spiffe://example.test/kubernetes", "spiffe://example.test/kubernetes"),
         ("udp", "srv", "otherName:1.3.6.1.5.5.7.8.7;IA5STRING:_http.example.test", "_http.example.test"))


def certificate(directory, san):
    def openssl(*args):
        revocation.run("openssl", *args, cwd=directory, seconds=30)

    openssl("req", "-new", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-noenc", "-days", "1", "-subj", "/CN=service-identity-test", "-keyout", "ca.key",
            "-out", "ca.pem", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
            "-subj", "/CN=service-identity-test", "-keyout", "server.key", "-out", "server.csr")
    (directory / "leaf.ext").write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=" + san + "\n", encoding="ascii")
    openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
            "-set_serial", "2", "-days", "1", "-extfile", "leaf.ext", "-out", "server.pem")


def pod(name, image, args, secret):
    return revocation.resource("Pod", name, {"metadata": {"name": name, "labels": {"app": name}}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "activeDeadlineSeconds": 120, "containers": [{"name": "peer", "image": image,
        "imagePullPolicy": "Never", "args": args,
        "volumeMounts": [{"name": "pki", "mountPath": "/pki", "readOnly": True}]}],
        "volumes": [{"name": "pki", "secret": {"secretName": secret}}]}})


def wait(kubectl, name, phase):
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        state = kubectl("get", "pod", name, "-o", "jsonpath={.status.phase}", capture=True).strip()
        if state == phase:
            return kubectl("logs", name, capture=True, check=False)
        if state in {"Succeeded", "Failed"}:
            raise RuntimeError(f"{name} ended {state}: {kubectl('logs', name, capture=True, check=False)[-2000:]}")
        time.sleep(0.5)
    raise RuntimeError(f"{name} did not reach {phase}")


def check_identity_output(output, matched):
    rows = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    connections = [row for row in rows if row.get("event") == "connection"]
    if not matched:
        if connections:
            raise RuntimeError(f"mismatched reference reported an authenticated connection: {connections}")
        if not any(row.get("event") == "error" and "NotValidForName" in row.get("message", "")
                   for row in rows):
            raise RuntimeError(f"mismatched reference did not report a name error: {rows}")
        return
    rows = connections
    if len(rows) != 1 or rows[0].get("service_identity_matched") is not True:
        raise RuntimeError(f"service identity did not match: {rows}")
    if (rows[0].get("sent"), rows[0].get("received")) != ("identity request", "tseuqer ytitnedi"):
        raise RuntimeError("identity case did not exchange application data")


def scenario(kubectl, image, protocol, kind, value, pki, suffix, matched):
    port = PORTS[protocol]
    service = f"identity-{protocol}-{suffix}"
    fqdn = f"{service}.{kubectl.namespace}.svc.cluster.local"
    server_secret = f"server-key-{suffix}"
    client_secret = f"client-ca-{suffix}"
    kubectl("create", "secret", "generic", server_secret,
            f"--from-file=server.pem={pki / 'server.pem'}", f"--from-file=server.key={pki / 'server.key'}")
    kubectl("create", "secret", "generic", client_secret, f"--from-file=ca.pem={pki / 'ca.pem'}")
    is_tcp = protocol == "tcp"
    server_name = f"server-{suffix}"
    client_name = f"client-{suffix}"
    server = pod(server_name, image, ["server" if is_tcp else "dtls-server", "--listen",
        f"0.0.0.0:{port}", "--cert", "/pki/server.pem", "--key", "/pki/server.key",
        "--accept", "1", "--tls", "1.3"] + (["--async"] if is_tcp else []), server_secret)
    service_obj = revocation.resource("Service", service, {"spec": {
        "selector": {"app": server_name}, "ports": [{"port": port, "targetPort": port,
        "protocol": "TCP" if is_tcp else "UDP"}]}})
    kubectl("apply", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "List",
        "items": [service_obj, server]}))
    deadline = time.monotonic() + 60
    listening = False
    while time.monotonic() < deadline:
        if '"event":"listening"' in kubectl("logs", server_name, capture=True, check=False):
            listening = True
            break
        time.sleep(0.5)
    if not listening:
        raise RuntimeError(f"{server_name} did not start listening")
    tested_value = value if matched else ("spiffe://wrong.example.test/service" if kind == "uri"
                                          else "_other.example.test")
    client_args = ["client" if is_tcp else "dtls-client", "--connect", f"{service}:{port}",
                   "--server-name", fqdn, "--reference-id", f"{kind}:{tested_value}",
                   "--ca", "/pki/ca.pem", "--message", "identity request",
                   "--expect-reply", "tseuqer ytitnedi", "--tls", "1.3"]
    if is_tcp:
        client_args.append("--async")
    client = pod(client_name, image, client_args, client_secret)
    kubectl("apply", "-f", "-", data=json.dumps(client))
    if not matched:
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            phase = kubectl("get", "pod", client_name, "-o", "jsonpath={.status.phase}",
                            capture=True).strip()
            if phase in {"Failed", "Succeeded"}:
                if phase != "Failed":
                    raise RuntimeError(f"mismatched {kind} reference unexpectedly succeeded")
                output = kubectl("logs", client_name, capture=True, check=False)
                check_identity_output(output, False)
                return
            time.sleep(0.5)
        raise RuntimeError(f"mismatched {kind} client did not finish")
    output = wait(kubectl, client_name, "Succeeded")
    check_identity_output(output, True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--profile", required=True, help="existing running minikube profile")
    args = parser.parse_args()
    run_id = secrets.token_hex(4)
    namespace, image = f"browntls-identity-{run_id}", f"browntls-e2e:identity-{run_id}"
    minikube = lambda *command, **kwargs: revocation.run("minikube", "--profile", args.profile,
                                                         *command, **kwargs)
    def kubectl(*command, **kwargs):
        return minikube("kubectl", "--", "--context", args.profile, "-n", namespace, *command, **kwargs)
    kubectl.namespace = namespace
    tagged = created = False
    try:
        revocation.run("docker", "tag", args.image, image)
        tagged = True
        with tempfile.TemporaryDirectory(prefix="browntls-identity-") as temporary:
            root = Path(temporary)
            archive = str(root / "image.tar")
            revocation.run("docker", "save", "-o", archive, image)
            minikube("image", "load", archive, seconds=180)
            kubectl("create", "namespace", namespace)
            created = True
            for index, (protocol, kind, san, value) in enumerate(CASES):
                directory = root / protocol
                if not directory.exists():
                    directory.mkdir()
                    certificate(directory, san)
                scenario(kubectl, image, protocol, kind, value, directory,
                         f"{protocol}-{index}-positive", True)
                scenario(kubectl, image, protocol, kind, value, directory,
                         f"{protocol}-{index}-negative", False)
                print(f"{protocol} Service: {kind} matched, exchanged data, and rejected mismatch")
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
        print(f"minikube service identity check failed: {error}", file=sys.stderr)
        return 1
    finally:
        if created:
            kubectl("delete", "namespace", namespace, "--timeout=60s", check=False, seconds=70)
        if tagged:
            minikube("image", "rm", image, check=False, seconds=45)
            revocation.run("docker", "image", "rm", image, check=False, seconds=30)


if __name__ == "__main__":
    sys.exit(main())
