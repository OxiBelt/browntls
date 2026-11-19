#!/usr/bin/env python3
"""Run OCSP interoperability and egress checks in an isolated minikube namespace."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
TARGET = "x86_64-unknown-linux-musl"
RESPONDER = "http://responder:8080/"
SERVER_NAME = "server"


def run(*args, cwd=ROOT, data=None, capture=False, seconds=120, check=True):
    result = subprocess.run(
        args, cwd=cwd, input=data, capture_output=capture, text=True,
        timeout=seconds, check=False,
    )
    if check and result.returncode:
        if capture:
            print(result.stderr, file=sys.stderr)
        raise RuntimeError(f"{args[0]} exited with status {result.returncode}")
    return result.stdout if capture else result.returncode


def generate_pki(directory):
    def openssl(*args):
        run("openssl", *args, cwd=directory, seconds=30)

    openssl(
        "req", "-new", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-noenc", "-days", "2", "-subj", "/CN=browntls revocation test CA",
        "-keyout", "ca.key", "-out", "ca.pem",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    )
    openssl(
        "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
        "-subj", f"/CN={SERVER_NAME}", "-keyout", "server.key", "-out", "server.csr",
    )
    (directory / "leaf.ext").write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{SERVER_NAME}\n"
        f"authorityInfoAccess=OCSP;URI:{RESPONDER}\n",
        encoding="ascii",
    )
    openssl(
        "x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
        "-set_serial", "42", "-days", "1", "-extfile", "leaf.ext", "-out", "server.pem",
    )
    (directory / "index").write_text(
        f"V\t490101000000Z\t\t2A\tunknown\t/CN={SERVER_NAME}\n", encoding="ascii"
    )


def resource(kind, name, body, api="v1"):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **body}


def policy(name, pod_labels, rules):
    return resource("NetworkPolicy", name, {
        "spec": {
            "podSelector": {"matchLabels": pod_labels},
            "policyTypes": ["Egress"],
            "egress": rules,
        },
    }, "networking.k8s.io/v1")


def egress(labels, ports):
    return {
        "to": [{"podSelector": {"matchLabels": labels}}],
        "ports": [{"protocol": "TCP", "port": port} for port in ports],
    }


def pod(name, image, labels, command, mounts, ready=None, responder_ip=None):
    container = {
        "name": name,
        "image": image,
        "imagePullPolicy": "Never",
        "command": command,
        "volumeMounts": [
            {"name": volume, "mountPath": f"/{volume}", "readOnly": True}
            for volume in mounts
        ],
        "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
    }
    if ready:
        # An empty TCP probe can occupy OpenSSL's serial request handler.
        probe = ["grep", "-Eq", f":{ready:04X} 00000000:0000 0A ", "/proc/net/tcp"]
        container["readinessProbe"] = {"exec": {"command": probe}, "periodSeconds": 2}
    body = resource("Pod", name, {
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "activeDeadlineSeconds": 420,
            "containers": [container],
            "volumes": [
                {"name": volume, kind: {field: volume}}
                for volume, (kind, field) in mounts.items()
            ],
        },
    })
    body["metadata"]["labels"] = labels
    if responder_ip:
        body["spec"]["hostAliases"] = [{"ip": responder_ip, "hostnames": ["responder"]}]
    return body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", help="reuse an existing minikube profile with Calico")
    parser.add_argument("--binary", type=Path, help="use an already built static example binary")
    args = parser.parse_args()
    namespace = "browntls-revocation-" + uuid.uuid4().hex[:8]
    profile = args.profile or namespace
    image = "browntls-revocation:" + namespace

    def minikube(*command, **kwargs):
        return run("minikube", "--profile", profile, *command, **kwargs)

    def kubectl(*command, **kwargs):
        return minikube("kubectl", "--", "--context", profile, "-n", namespace, *command, **kwargs)

    def apply(*items):
        kubectl("apply", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "List", "items": items}))

    def address(name):
        return kubectl("get", "pod", name, "-o", "jsonpath={.status.podIP}", capture=True).strip()

    has_namespace = False
    built_image = False
    try:
        if not args.profile:
            minikube(
                "start", "--driver=docker", "--container-runtime=containerd",
                "--kubernetes-version=v1.37.0", "--cni=calico", "--keep-context",
                "--wait-timeout=180s", seconds=360,
            )
        with tempfile.TemporaryDirectory(prefix="browntls-ocsp-") as temp:
            directory = Path(temp)
            binary = args.binary
            if binary is None:
                run(
                    "cargo", "build", "--locked", "--release", "-p", "browntls-tokio",
                    "--features", "ocsp", "--target", TARGET, "--target-dir",
                    str(ROOT / "target"), "--example", "revocation_kubernetes", seconds=360,
                )
                binary = ROOT / "target" / TARGET / "release" / "examples" / "revocation_kubernetes"
            context = directory / "image"
            context.mkdir()
            shutil.copy2(binary, context / "revocation_kubernetes")
            shutil.copy2(Path(__file__).with_name("revocation.Dockerfile"), context / "Dockerfile")
            run("docker", "build", "-t", image, str(context), seconds=180)
            built_image = True
            run("docker", "save", "-o", str(directory / "image.tar"), image)
            minikube("image", "load", str(directory / "image.tar"), seconds=180)
            generate_pki(directory)

            apply(resource("Namespace", namespace, {}))
            has_namespace = True
            public = {"public": ("configMap", "name")}
            serving = {**public, "serving-key": ("secret", "secretName")}
            responder = {**public, "issuer-key": ("secret", "secretName")}
            kubectl(
                "create", "configmap", "public",
                *(f"--from-file={directory / file}" for file in ("ca.pem", "server.pem", "index")),
            )
            kubectl("create", "secret", "generic", "serving-key", f"--from-file={directory / 'server.key'}")
            kubectl("create", "secret", "generic", "issuer-key", f"--from-file={directory / 'ca.key'}")
            apply(
                policy("deny-egress", {}, []),
                policy("client-tls", {"component": "client"}, [egress({"component": "server"}, [8443, 8444])]),
                policy("authorized-ocsp", {"responder-access": "true"}, [egress({"component": "responder"}, [8080])]),
                pod("responder", image, {"component": "responder"}, [
                    "openssl", "ocsp", "-index", "/public/index", "-port", "8080",
                    "-rsigner", "/public/ca.pem", "-rkey", "/issuer-key/ca.key",
                    "-CA", "/public/ca.pem", "-ndays", "1", "-timeout", "3", "-ignore_err",
                ], responder, ready=8080),
            )
            kubectl("wait", "--for=condition=Ready", "pod/responder", "--timeout=60s")
            responder_ip = address("responder")
            apply(
                pod("server", image, {"component": "server", "responder-access": "true"}, [
                    "/revocation_kubernetes", "server", "--cert", "/public/server.pem",
                    "--key", "/serving-key/server.key", "--ca", "/public/ca.pem",
                    "--responder", RESPONDER, "--plain-listen", "0.0.0.0:8443",
                    "--staple-listen", "0.0.0.0:8444",
                ], serving, ready=8443, responder_ip=responder_ip),
            )
            kubectl("wait", "--for=condition=Ready", "pod/server", "--timeout=90s")
            server_ip = address("server")
            for scenario in ("live", "denied", "staple"):
                name = f"client-{scenario}"
                labels = {"component": "client", "responder-access": str(scenario == "live").lower()}
                apply(pod(name, image, labels, [
                    "/revocation_kubernetes", "client", "--scenario", scenario,
                    "--ca", "/public/ca.pem", "--responder", RESPONDER, "--name", SERVER_NAME,
                    "--plain", f"{server_ip}:8443", "--staple", f"{server_ip}:8444",
                ], public, responder_ip=responder_ip))
                deadline = time.monotonic() + 115
                phase = "Unknown"
                while time.monotonic() < deadline:
                    phase = kubectl("get", "pod", name, "-o", "jsonpath={.status.phase}", capture=True).strip()
                    if phase in {"Succeeded", "Failed"}:
                        break
                    time.sleep(2)
                kubectl("logs", name, check=False)
                if phase != "Succeeded":
                    raise RuntimeError(f"{name} ended in {phase}")
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"revocation suite failed: {error}", file=sys.stderr)
        if has_namespace:
            kubectl("get", "pods", "-o", "wide", check=False, seconds=15)
            for name in ("server", "responder"):
                kubectl("logs", name, "--tail=60", check=False, seconds=15)
        return 1
    finally:
        if has_namespace:
            kubectl("delete", "namespace", namespace, "--timeout=60s", check=False, seconds=70)
        if built_image:
            minikube("image", "rm", image, check=False, seconds=45)
            run("docker", "image", "rm", image, check=False, seconds=30)
        if not args.profile:
            minikube("delete", check=False, seconds=90)
    return 0


if __name__ == "__main__":
    sys.exit(main())
