#!/usr/bin/env python3
"""Compare diagnostic key-log records from browntls and OpenSSL."""

import argparse
import shlex
import subprocess
import sys

import e2e

NAME = e2e.SERVER_ALIAS
MESSAGE = "key log qualification payload"
REPLY = MESSAGE[::-1]
BROWN_LOG = "/key-log/browntls/traffic.keys"
OPENSSL_LOG = "/key-log/openssl/traffic.keys"
TLS12_LABELS = {"CLIENT_RANDOM"}
TLS13_LABELS = {
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
}
HEX = frozenset("0123456789abcdef")


def entries(output: str, expected: set[str]) -> dict[str, tuple[str, str]]:
    """Validate the required rows without echoing their contents on failure."""
    parsed = {}
    for line in output.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(" ")
        if len(fields) != 3:
            raise RuntimeError("invalid key-log record")
        label, random, secret = fields
        # OpenSSL can record additional labels. Compare those defined for
        # the negotiated handshake in RFC 9850 sections 2.1 and 2.2.
        if label not in expected:
            continue
        random, secret = random.lower(), secret.lower()
        secret_lengths = {96} if label == "CLIENT_RANDOM" else {64, 96}
        if len(random) != 64 or not set(random) <= HEX or len(secret) not in secret_lengths \
                or not set(secret) <= HEX or label in parsed:
            raise RuntimeError("invalid or duplicate expected key-log record")
        parsed[label] = (random, secret)
    if parsed.keys() != expected:
        raise RuntimeError("required key-log labels are missing")
    return parsed


class DiagnosticRun(e2e.Run):
    def _common(self, name: str, browntls: bool) -> list[str]:
        return [*super()._common(name, browntls), "-v", f"{self.volume}:/key-log"]

    def prepare_key_logs(self):
        e2e.docker(
            "run", "--rm", *self.label(), "-v", f"{self.volume}:/key-log",
            "--entrypoint", "sh", self.peer, "-ec",
            "mkdir -m 700 /key-log/browntls /key-log/openssl && "
            "chown 65532:65532 /key-log/browntls && umask 077 && "
            "touch /key-log/openssl/traffic.keys",
        )

    def read_log(self, path: str) -> str:
        # Disable container logging and suppress subprocess errors containing
        # captured output. Only the comparison process sees the file bytes.
        try:
            proc = subprocess.run(
                ["docker", "run", "--rm", "--log-driver=none", *self.label(),
                 "-v", f"{self.volume}:/key-log:ro", "--entrypoint", "cat", self.peer, path],
                capture_output=True, text=True, timeout=20, check=False,
            )
        except (OSError, UnicodeError, subprocess.TimeoutExpired):
            raise RuntimeError("could not read the temporary key log") from None
        if proc.returncode:
            raise RuntimeError("temporary key log is unavailable")
        return proc.stdout


def commands(version: str, role: str) -> tuple[list[str], list[str]]:
    tlsflag = "-tls1_2" if version == "1.2" else "-tls1_3"
    ca = "/pki/ecdsa-p256/ca.pem"
    server_cert = "/pki/ecdsa-p256/server.pem"
    server_key = "/pki/ecdsa-p256/server.key"
    client_cert = "/pki/ecdsa-p256/client.pem"
    client_key = "/pki/ecdsa-p256/client.key"
    address = f"{NAME}:{e2e.PORT}"
    if role == "client":
        server = [
            "openssl", "s_server", "-accept", f"0.0.0.0:{e2e.PORT}", "-naccept", "1",
            tlsflag, "-cert", server_cert, "-key", server_key, "-CAfile", ca, "-Verify", "2",
            "-verify_return_error", "-keylogfile", OPENSSL_LOG, "-rev",
        ]
        client = [
            "client", "--connect", address, "--server-name", NAME, "--tls", version,
            "--ca", ca, "--cert", client_cert, "--key", client_key, "--key-log",
            "--wait", str(e2e.CONNECT_WAIT), "--message", MESSAGE, "--expect-reply", REPLY,
        ]
    else:
        server = [
            "server", "--listen", f"0.0.0.0:{e2e.PORT}", "--accept", "1",
            "--tls", version, "--cert", server_cert, "--key", server_key,
            "--client-ca", ca, "--key-log",
        ]
        openssl_client = [
            "openssl", "s_client", "-connect", address, "-servername", NAME, tlsflag,
            "-cert", client_cert, "-key", client_key, "-CAfile", ca, "-verify_return_error",
            "-verify_hostname", NAME, "-keylogfile", OPENSSL_LOG, "-quiet",
        ]
        client = ["sh", "-c", f"printf '%s\\n' {shlex.quote(MESSAGE)} | {shlex.join(openssl_client)}"]
    return server, client


def qualify(run: DiagnosticRun, version: str, role: str) -> None:
    run.generate_pki(NAME)
    run.prepare_key_logs()
    server_cmd, client_cmd = commands(version, role)
    env = {"SSLKEYLOGFILE": BROWN_LOG}
    if role == "client":
        server = run.start_server(run.peer, server_cmd, {})
        client = run.run_client(run.image, client_cmd, env)
    else:
        server = run.start_server(run.image, server_cmd, env)
        if not run.wait_for_log(server, '"event":"listening"', e2e.CONNECT_WAIT):
            raise RuntimeError("browntls server did not become ready")
        client = run.run_client(run.peer, client_cmd, {})

    finished = run.finish_server(server, 20)
    if client.exit_code != 0 or finished.exit_code != 0:
        raise RuntimeError(f"peer failed (client status {client.exit_code}, "
                           f"server status {finished.exit_code})")
    brown = client if role == "client" else finished
    sent, received = (MESSAGE, REPLY) if role == "client" else (REPLY, MESSAGE)
    protocol = "TLSv1_2" if version == "1.2" else "TLSv1_3"
    if not any(row.get("event") == "connection" and row.get("version") == protocol
               and row.get("peer_certificates", 0) >= 1 and row.get("sent") == sent
               and row.get("received") == received for row in e2e.events(brown.stdout)):
        raise RuntimeError("browntls did not complete the authenticated application exchange")
    if role == "server" and REPLY not in client.stdout.splitlines():
        raise RuntimeError("OpenSSL did not receive the expected reply")

    expected = TLS12_LABELS if version == "1.2" else TLS13_LABELS
    brown_rows = entries(run.read_log(BROWN_LOG), expected)
    peer_rows = entries(run.read_log(OPENSSL_LOG), expected)
    if brown_rows != peer_rows:
        raise RuntimeError("browntls and OpenSSL key logs differ")
    print(f"TLS {version}, browntls as {role}: {len(expected)} matching key-log labels",
          flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="key-log-enabled browntls e2e image")
    args = parser.parse_args()
    suite = e2e.SUITES["openssl-3.0"]
    if not e2e.image_exists(args.image) or not e2e.image_exists(e2e.peer_image_tag(suite.peer_image)):
        print("key-log qualification requires both local images", file=sys.stderr)
        return 1
    for version in ("1.2", "1.3"):
        for role in ("client", "server"):
            try:
                with DiagnosticRun(e2e.ARCHES["amd64"], suite, args.image) as run:
                    qualify(run, version, role)
            except (OSError, RuntimeError) as error:
                print(f"TLS {version}, browntls as {role}: {error}", file=sys.stderr)
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
