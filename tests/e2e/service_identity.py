#!/usr/bin/env python3
"""Check RFC 9525 reference identifiers against the pinned OpenSSL peer."""

import argparse
import json
import secrets
import subprocess
import sys

import e2e

ROOT = e2e.REPO_ROOT
PORT = 4433
CASES = (
    ("dns", "DNS:service.example.test", "service.example.test"),
    ("ip", "IP:127.0.0.1", "127.0.0.1"),
    ("uri", "URI:spiffe://example.test/service", "spiffe://example.test/service"),
    ("srv", "otherName:1.3.6.1.5.5.7.8.7;IA5STRING:_http.example.test", "_http.example.test"),
)


def run(*args, timeout=90, check=True):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True,
                            timeout=timeout, check=False)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}: {result.stderr[-2000:]}")
    return result


def check_client(output, reference, matched):
    rows = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    rows = [row for row in rows if row.get("event") == "connection"]
    if len(rows) != 1 or rows[0].get("service_identity_matched") is not matched:
        raise RuntimeError(f"unexpected authenticated identity result for {reference}: {rows}")
    if matched and (rows[0].get("sent") != "identity request" or
                    rows[0].get("received") != "tseuqer ytitnedi"):
        raise RuntimeError("positive identity case did not exchange application data")


def certificate(peer, volume, san):
    generate = """
umask 077
cd /pki
openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -days 1 \
  -subj /CN=identity-fixture-ca -keyout ca.key -out ca.pem \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
  -subj /CN=transport.example.test -keyout key.pem -out leaf.csr
printf '%s\n' basicConstraints=critical,CA:FALSE keyUsage=critical,digitalSignature \
  extendedKeyUsage=serverAuth "subjectAltName=$1" > leaf.ext
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -set_serial 2 \
  -days 1 -extfile leaf.ext -out cert.pem
chmod 0644 ca.pem cert.pem
rm ca.key leaf.csr leaf.ext
"""
    run("docker", "run", "--rm", "-v", f"{volume}:/pki", "--entrypoint", "sh", peer,
        "-ec", generate, "cert-fixture", san)


def scenario(image, peer, network, volume, reference, positive, suffix):
    server_name = f"browntls-identity-{suffix}"
    client_name = server_name + "-client"
    run("docker", "run", "-d", "--name", server_name, "--network", network,
        "--network-alias", "identity-peer", "-v", f"{volume}:/pki:ro", peer,
        "openssl", "s_server", "-accept", str(PORT), "-cert", "/pki/cert.pem",
        "-key", "/pki/key.pem", "-rev", "-naccept", "1")
    try:
        result = run("docker", "run", "--rm", "--name", client_name, "--network", network,
                     "-v", f"{volume}:/pki:ro", image, "client", "--connect",
                     f"identity-peer:{PORT}", "--server-name", "transport.example.test",
                     "--reference-id", reference, "--ca", "/pki/ca.pem",
                     "--async", "--wait", "10", "--message", "identity request",
                     "--expect-reply", "tseuqer ytitnedi",
                     check=False, timeout=75)
        if positive:
            if result.returncode:
                raise RuntimeError(f"positive {reference} client failed: "
                                   f"{result.stdout[-1200:]} {result.stderr[-1500:]}")
            check_client(result.stdout, reference, True)
        else:
            if result.returncode == 0:
                raise RuntimeError(f"mismatched {reference} unexpectedly authenticated")
            if "NotValidForName" not in result.stdout:
                raise RuntimeError(f"mismatched {reference} did not report a name error: "
                                   f"{result.stdout[-1200:]} {result.stderr[-1000:]}")
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        log = run("docker", "logs", server_name, check=False)
        raise RuntimeError(f"{error}; server: {log.stdout[-1200:]} {log.stderr[-1600:]}") from error
    finally:
        run("docker", "rm", "-f", server_name, check=False)
        run("docker", "rm", "-f", client_name, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="built browntls-e2e image")
    parser.add_argument("--peer-image", default=e2e.peer_image_tag("alpine"))
    parser.add_argument("--build-peer", action="store_true")
    args = parser.parse_args()
    run_id = secrets.token_hex(5)
    label = f"{e2e.LABEL}={run_id}"
    network, volume = f"browntls-identity-{run_id}", f"browntls-identity-{run_id}"
    try:
        if args.build_peer:
            e2e.build_peer_image("alpine")
        if not e2e.image_exists(args.image) or not e2e.image_exists(args.peer_image):
            raise RuntimeError("browntls and pinned OpenSSL peer images must exist")
        run("docker", "network", "create", "--label", label, network)
        run("docker", "volume", "create", "--label", label, volume)
        wrong = {"dns": "wrong.example.test", "ip": "127.0.0.2",
                 "uri": "spiffe://wrong.example.test/service", "srv": "_other.example.test"}
        for index, (kind, san, value) in enumerate(CASES):
            certificate(args.peer_image, volume, san)
            scenario(args.image, args.peer_image, network, volume, f"{kind}:{value}", True,
                     f"{run_id}-{index}")
            scenario(args.image, args.peer_image, network, volume, f"{kind}:{wrong[kind]}", False,
                     f"{run_id}-{index}-negative")
            print(f"{kind}: matched, exchanged data, and rejected the mismatched reference")
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"service identity Docker check failed: {error}", file=sys.stderr)
        return 1
    finally:
        run("docker", "network", "rm", network, check=False)
        run("docker", "volume", "rm", "-f", volume, check=False)


if __name__ == "__main__":
    sys.exit(main())
