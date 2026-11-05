#!/usr/bin/env python3
"""Docker end-to-end interoperability matrix for browntls.

Each matrix entry pairs a target architecture with a peer suite. A run
starts the `browntls-e2e` image (tests/e2e/Dockerfile) and a peer image on a
run-specific Docker network, runs every scenario in both directions where it
applies, and checks what the browntls side negotiated (protocol version,
cipher suite, key exchange group, handshake kind) together with the
application data exchanged.

Commands (run from the repository root; see tests/e2e/README.md):

    python3 tests/e2e/e2e.py matrix images|e2e     GitHub Actions matrix JSON
    python3 tests/e2e/e2e.py list [--suite S]      scenarios
    python3 tests/e2e/e2e.py build --arch A [--save TAR]
    python3 tests/e2e/e2e.py run --arch A --suite S [--scenario N]...

Only resources labelled with the run's identifier are created and removed.
Certificates are generated per run inside a Docker volume, so the commands
also work against a remote Docker daemon (no bind mounts).
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
E2E_DIR = Path(__file__).resolve().parent

LABEL = "org.oxibelt.browntls-e2e.run"
SERVER_ALIAS = "tls-server"
PORT = 4433
MESSAGE = "browntls end-to-end check"
# How long a client may retry connecting while the server starts up, and how
# long a single scenario may take before it is abandoned.
CONNECT_WAIT = 30
SCENARIO_TIMEOUT = 120
SHARE = "/usr/local/share/browntls-e2e"


# ------------------------------------------------------------------ targets


@dataclasses.dataclass(frozen=True)
class Arch:
    name: str
    label: str
    platform: str
    runner: str
    rust_target: str
    rustflags: tuple[str, ...] = ()
    # Algorithm families (as `browntls-e2e info` names them) that must use an
    # accelerated backend on this target, so that a silent fallback to the
    # portable code fails the run instead of passing unnoticed.
    accelerated: tuple[str, ...] = ()
    # QEMU CPU model when the target runs under user-mode emulation on an
    # x86-64 runner (QEMU_CPU for the binfmt_misc interpreter).
    qemu_cpu: str | None = None


ARCHES: dict[str, Arch] = {
    a.name: a
    for a in (
        # x86-64-v3 is the minimum supported x86-64 level.
        Arch(
            "amd64",
            "x86-64-v3",
            "linux/amd64",
            "ubuntu-26.04",
            "x86_64-unknown-linux-musl",
            ("-C", "target-cpu=x86-64-v3"),
            accelerated=("AES", "GHASH", "SHA-256", "ChaCha20", "Poly1305", "X25519", "P-256"),
        ),
        # The GitHub Arm runners implement the Armv8 AES, PMULL and SHA2
        # extensions.
        Arch(
            "arm64",
            "aarch64",
            "linux/arm64",
            "ubuntu-26.04-arm",
            "aarch64-unknown-linux-musl",
            accelerated=("AES", "GHASH", "SHA-256"),
        ),
        # RISE native RISC-V runners (RV64GC hardware without RVV 1.0, so
        # mostly the portable backends).
        Arch(
            "riscv64",
            "riscv64",
            "linux/riscv64",
            "ubuntu-24.04-riscv",
            "riscv64gc-unknown-linux-musl",
        ),
        # RVV 1.0 with the vector crypto extensions under QEMU user-mode
        # emulation. QEMU's riscv_hwprobe does not report the vector crypto
        # extensions, so the build asserts them (as scripts/cross-test.sh does
        # for its zvk profiles).
        Arch(
            "riscv64-zvk",
            "riscv64 RVV+Zvk (QEMU)",
            "linux/riscv64",
            "ubuntu-26.04",
            "riscv64gc-unknown-linux-musl",
            tuple(
                arg
                for ext in ("v", "zvkned", "zvknhb", "zvkg", "zvbc", "zvbb", "zvkb")
                for arg in ("--cfg", f'browntls_assume_riscv="{ext}"')
            ),
            accelerated=("AES", "GHASH", "SHA-256", "SHA-512", "ChaCha20"),
            qemu_cpu=(
                "rv64,v=true,vlen=256,zbb=true,zvkned=true,zvknha=true,zvknhb=true,"
                "zvkg=true,zvbc=true,zvbb=true,zvkb=true,zvkt=true"
            ),
        ),
    )
}


@dataclasses.dataclass(frozen=True)
class Suite:
    """A peer implementation and the image that provides it."""

    name: str
    description: str
    implementation: str  # "openssl", "gnutls" or "browntls"
    peer_image: str  # Dockerfile under tests/e2e/peer/ (also used for PKI)
    features: frozenset[str]


SUITES: dict[str, Suite] = {
    s.name: s
    for s in (
        Suite(
            "openssl",
            "OpenSSL 3.5+ (Alpine 3.24)",
            "openssl",
            "alpine",
            frozenset({"mlkem", "etm-toggle"}),
        ),
        Suite(
            "openssl-3.0",
            "OpenSSL 3.0 (Ubuntu 24.04)",
            "openssl",
            "ubuntu",
            frozenset({"etm-toggle"}),
        ),
        Suite(
            "gnutls",
            "GnuTLS 3.8 (Alpine 3.24)",
            "gnutls",
            "alpine",
            frozenset({"etm-toggle"}),
        ),
        Suite(
            "browntls",
            "browntls client and server in separate containers",
            "browntls",
            "alpine",
            frozenset({"mlkem"}),
        ),
    )
}


def peer_image_tag(peer_image: str) -> str:
    return f"browntls-e2e-peer:{peer_image}"


def image_tag(arch: str) -> str:
    return f"browntls-e2e:{arch}"


# ---------------------------------------------------------------- scenarios

# browntls cipher suite name -> (OpenSSL name, GnuTLS priority elements).
SUITE_NAMES: dict[str, tuple[str, str]] = {
    "TLS13_AES_128_GCM_SHA256": ("TLS_AES_128_GCM_SHA256", "+AES-128-GCM:+AEAD"),
    "TLS13_AES_256_GCM_SHA384": ("TLS_AES_256_GCM_SHA384", "+AES-256-GCM:+AEAD"),
    "TLS13_CHACHA20_POLY1305_SHA256": (
        "TLS_CHACHA20_POLY1305_SHA256",
        "+CHACHA20-POLY1305:+AEAD",
    ),
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": (
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "+AES-128-GCM:+AEAD:+ECDHE-ECDSA",
    ),
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": (
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "+AES-256-GCM:+AEAD:+ECDHE-ECDSA",
    ),
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": (
        "ECDHE-RSA-AES128-GCM-SHA256",
        "+AES-128-GCM:+AEAD:+ECDHE-RSA",
    ),
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": (
        "ECDHE-RSA-AES256-GCM-SHA384",
        "+AES-256-GCM:+AEAD:+ECDHE-RSA",
    ),
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": (
        "ECDHE-RSA-CHACHA20-POLY1305",
        "+CHACHA20-POLY1305:+AEAD:+ECDHE-RSA",
    ),
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": (
        "ECDHE-RSA-AES128-SHA256",
        "+AES-128-CBC:+SHA256:+ECDHE-RSA",
    ),
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": (
        "ECDHE-ECDSA-AES256-SHA",
        "+AES-256-CBC:+SHA1:+ECDHE-ECDSA",
    ),
}

# browntls group name -> (OpenSSL name, GnuTLS priority element).
GROUP_NAMES: dict[str, tuple[str, str | None]] = {
    "X25519": ("X25519", "+GROUP-X25519"),
    "secp256r1": ("P-256", "+GROUP-SECP256R1"),
    "secp384r1": ("P-384", "+GROUP-SECP384R1"),
    # GnuTLS builds without a post-quantum backend lack the hybrid group;
    # scenarios that use it require the "mlkem" suite feature.
    "X25519MLKEM768": ("X25519MLKEM768", None),
}

ROLES = ("client", "server")


@dataclasses.dataclass(frozen=True)
class Scenario:
    """One handshake configuration.

    `groups` restricts both sides unless `server_only_groups` is set, in
    which case only the server is restricted and the browntls client keeps
    its default groups (and key shares). Expected values of `None` are not
    checked.
    """

    name: str
    key: str
    tls: str | None = None
    suite: str | None = None
    groups: tuple[str, ...] = ()
    server_only_groups: bool = False
    client_auth: bool = False
    connections: int = 1
    # "default", "peer-disabled" (refused) or "peer-disabled-allowed"
    etm: str = "default"
    roles: tuple[str, ...] = ROLES
    requires: frozenset[str] = frozenset()
    excludes: frozenset[str] = frozenset()
    expect_version: str | None = None
    expect_suite: str | None = None
    expect_group: str | None = None
    expect_handshake: str | None = "Full"

    @property
    def refused(self) -> bool:
        return self.etm == "peer-disabled"

    @property
    def refusal(self) -> tuple[str, ...]:
        """Error fragments that show a refused handshake failed for its reason.

        A browntls client reports the missing extension; a browntls server
        cannot select a CBC suite without it.
        """
        return ("EncryptThenMacExtensionRequired", "NoCipherSuitesInCommon")

    def applies_to(self, suite: Suite) -> bool:
        return self.requires <= suite.features and not (self.excludes & suite.features)

    def roles_for(self, suite: Suite) -> tuple[str, ...]:
        """The browntls roles to run against `suite`.

        Against itself one run covers both: browntls is client and server,
        and both sides are checked.
        """
        return ("client",) if suite.implementation == "browntls" else self.roles


def _tls13(name: str, suite: str, group: str, key: str, **kw) -> Scenario:
    kw.setdefault("expect_group", group)
    return Scenario(
        name,
        key,
        tls="1.3",
        suite=suite,
        groups=(group,),
        expect_version="TLSv1_3",
        expect_suite=suite,
        **kw,
    )


def _tls12(name: str, suite: str, groups: tuple[str, ...], key: str, **kw) -> Scenario:
    kw.setdefault("expect_group", groups[0])
    return Scenario(
        name,
        key,
        tls="1.2",
        suite=suite,
        groups=groups,
        expect_version="TLSv1_2",
        expect_suite=suite,
        **kw,
    )


SCENARIOS: tuple[Scenario, ...] = (
    # Both sides on their defaults, as most deployments are.
    Scenario(
        "defaults-pq",
        "ecdsa-p256",
        requires=frozenset({"mlkem"}),
        expect_version="TLSv1_3",
        expect_group="X25519MLKEM768",
    ),
    # The browntls client also sends an X25519 key share: no
    # HelloRetryRequest for a peer without post-quantum groups.
    Scenario(
        "defaults-classical",
        "ecdsa-p256",
        excludes=frozenset({"mlkem"}),
        expect_version="TLSv1_3",
        expect_group="X25519",
    ),
    _tls13("tls13-aes128gcm-x25519", "TLS13_AES_128_GCM_SHA256", "X25519", "ecdsa-p256"),
    _tls13("tls13-aes256gcm-p384-rsa", "TLS13_AES_256_GCM_SHA384", "secp384r1", "rsa-2048"),
    _tls13(
        "tls13-chacha20-p256-ed25519",
        "TLS13_CHACHA20_POLY1305_SHA256",
        "secp256r1",
        "ed25519",
    ),
    _tls13(
        "tls13-x25519mlkem768",
        "TLS13_AES_128_GCM_SHA256",
        "X25519MLKEM768",
        "ecdsa-p256",
        requires=frozenset({"mlkem"}),
    ),
    # The browntls client's default key shares do not include P-256.
    Scenario(
        "tls13-hello-retry-request",
        "ecdsa-p256",
        tls="1.3",
        groups=("secp256r1",),
        server_only_groups=True,
        roles=("client",),
        expect_version="TLSv1_3",
        expect_group="secp256r1",
        expect_handshake="FullWithHelloRetryRequest",
    ),
    _tls13(
        "tls13-client-auth",
        "TLS13_AES_256_GCM_SHA384",
        "X25519",
        "ecdsa-p256",
        client_auth=True,
    ),
    _tls13(
        "tls13-resumption",
        "TLS13_AES_128_GCM_SHA256",
        "X25519",
        "ecdsa-p256",
        connections=2,
        roles=("client",),
    ),
    _tls12(
        "tls12-ecdsa-aes128gcm",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        # OpenSSL requires the certificate's curve among the groups in
        # TLS 1.2 (RFC 8422 §5.1.1).
        ("X25519", "secp256r1"),
        "ecdsa-p256",
    ),
    _tls12(
        "tls12-rsa-chacha20",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ("secp256r1",),
        "rsa-2048",
    ),
    _tls12(
        "tls12-rsa-aes256gcm-p384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        ("secp384r1",),
        "rsa-2048",
    ),
    _tls12(
        "tls12-rsa-aes128cbc-sha256-etm",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        ("X25519",),
        "rsa-2048",
    ),
    _tls12(
        "tls12-ecdsa-aes256cbc-sha-etm",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        ("secp256r1",),
        "ecdsa-p256",
    ),
    # A peer without Encrypt-then-MAC: refused by default, MAC-then-encrypt
    # when explicitly allowed.
    _tls12(
        "tls12-cbc-without-etm-refused",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        ("X25519",),
        "rsa-2048",
        etm="peer-disabled",
        requires=frozenset({"etm-toggle"}),
    ),
    _tls12(
        "tls12-cbc-without-etm-allowed",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        ("X25519",),
        "rsa-2048",
        etm="peer-disabled-allowed",
        requires=frozenset({"etm-toggle"}),
    ),
    _tls12(
        "tls12-client-auth",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        ("secp256r1",),
        "ecdsa-p256",
        client_auth=True,
    ),
    _tls12(
        "tls12-resumption",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        ("X25519",),
        "rsa-2048",
        connections=2,
        roles=("client",),
    ),
)


def scenarios_for(suite: Suite) -> list[Scenario]:
    return [s for s in SCENARIOS if s.applies_to(suite)]


# ------------------------------------------------------- command generation


def pki(key: str, name: str) -> str:
    return f"/pki/{key}/{name}"


def browntls_args(sc: Scenario, role: str) -> list[str]:
    """Arguments for the browntls side of `sc` acting as `role`."""
    if role == "server":
        args = [
            "server",
            "--listen",
            f"0.0.0.0:{PORT}",
            "--cert",
            pki(sc.key, "server.pem"),
            "--key",
            pki(sc.key, "server.key"),
            "--accept",
            str(sc.connections),
        ]
        if sc.client_auth:
            args += ["--client-ca", pki(sc.key, "ca.pem")]
    else:
        args = [
            "client",
            "--connect",
            f"{SERVER_ALIAS}:{PORT}",
            "--server-name",
            SERVER_ALIAS,
            "--ca",
            pki(sc.key, "ca.pem"),
            "--message",
            MESSAGE,
            "--connections",
            str(sc.connections),
            "--wait",
            str(CONNECT_WAIT),
        ]
        if sc.client_auth:
            args += ["--cert", pki(sc.key, "client.pem"), "--key", pki(sc.key, "client.key")]
    if sc.tls:
        args += ["--tls", sc.tls]
    if sc.suite:
        args += ["--suite", sc.suite]
    if role == "server" or not sc.server_only_groups:
        for group in sc.groups:
            args += ["--group", group]
    if sc.etm == "peer-disabled-allowed":
        args.append("--allow-mac-then-encrypt")
    return args


def openssl_protocol_args(sc: Scenario) -> list[str]:
    args: list[str] = []
    if sc.tls == "1.3":
        args.append("-tls1_3")
        if sc.suite:
            args += ["-ciphersuites", SUITE_NAMES[sc.suite][0]]
    elif sc.tls == "1.2":
        args.append("-tls1_2")
        if sc.suite:
            args += ["-cipher", SUITE_NAMES[sc.suite][0]]
    if sc.groups:
        args += ["-groups", ":".join(GROUP_NAMES[g][0] for g in sc.groups)]
    return args


def gnutls_priority(sc: Scenario) -> str:
    parts = ["NORMAL"]
    if sc.tls:
        parts += ["-VERS-ALL", f"+VERS-TLS{sc.tls}"]
    if sc.suite:
        parts += ["-CIPHER-ALL", "-MAC-ALL", "-KX-ALL", SUITE_NAMES[sc.suite][1]]
    if sc.groups:
        parts.append("-GROUP-ALL")
        for g in sc.groups:
            element = GROUP_NAMES[g][1]
            if element is None:
                raise ValueError(f"GnuTLS has no priority element for {g}")
            parts.append(element)
    if sc.etm != "default":
        parts.append("%NO_ETM")
    return ":".join(parts)


def peer_env(sc: Scenario, implementation: str) -> dict[str, str]:
    if implementation == "openssl" and sc.etm != "default":
        return {"OPENSSL_CONF": f"{SHARE}/no-etm.cnf"}
    return {}


def peer_server_command(sc: Scenario, implementation: str) -> list[str]:
    cert, key, ca = (pki(sc.key, n) for n in ("server.pem", "server.key", "ca.pem"))
    if implementation == "openssl":
        cmd = ["openssl", "s_server", "-accept", str(PORT), "-naccept", str(sc.connections)]
        cmd += ["-rev", "-cert", cert, "-key", key]
        cmd += openssl_protocol_args(sc)
        if sc.client_auth:
            cmd += ["-Verify", "1", "-verify_return_error", "-CAfile", ca]
        return cmd
    if implementation == "gnutls":
        cmd = ["gnutls-serv", "--echo", "--port", str(PORT)]
        cmd += ["--x509certfile", cert, "--x509keyfile", key]
        cmd += ["--priority", gnutls_priority(sc)]
        if sc.client_auth:
            cmd += ["--require-client-cert", "--verify-client-cert", "--x509cafile", ca]
        return cmd
    raise ValueError(implementation)


def peer_client_command(sc: Scenario, implementation: str) -> list[str]:
    """A shell command: the peer clients read the message from standard input."""
    cert, key, ca = (pki(sc.key, n) for n in ("client.pem", "client.key", "ca.pem"))
    line = shlex.quote(MESSAGE)
    if implementation == "openssl":
        # `-quiet` implies `-ign_eof`: s_client keeps the connection open
        # until the browntls server closes it after replying.
        cmd = ["openssl", "s_client", "-connect", f"{SERVER_ALIAS}:{PORT}"]
        cmd += ["-servername", SERVER_ALIAS, "-verify_hostname", SERVER_ALIAS]
        cmd += ["-CAfile", ca, "-verify_return_error", "-quiet"]
        cmd += openssl_protocol_args(sc)
        if sc.client_auth:
            cmd += ["-cert", cert, "-key", key]
        script = f"printf '%s\\n' {line} | {shlex.join(cmd)}"
    elif implementation == "gnutls":
        # gnutls-cli ends the session at end of input: keep standard input
        # open until the browntls server has replied and closed.
        cmd = ["gnutls-cli", "--port", str(PORT), "--x509cafile", ca]
        cmd += ["--priority", gnutls_priority(sc)]
        if sc.client_auth:
            cmd += ["--x509certfile", cert, "--x509keyfile", key]
        cmd.append(SERVER_ALIAS)
        script = f"{{ printf '%s\\n' {line}; sleep 4; }} | {shlex.join(cmd)}"
    else:
        raise ValueError(implementation)
    # Wait for the server: the peer clients do not retry connecting.
    return ["sh", "-c", script]


def expected_reply(server_impl: str) -> str:
    """What a client receives for MESSAGE from a server implementation."""
    return MESSAGE if server_impl == "gnutls" else MESSAGE[::-1]


# ------------------------------------------------------------------- docker


class DockerError(RuntimeError):
    pass


def docker(
    *args: str, timeout: float | None = 120, check: bool = True, stdin: str | None = None
) -> subprocess.CompletedProcess[str]:
    try:
        proc = subprocess.run(
            ["docker", *args],
            input=stdin,
            stdin=None if stdin is not None else subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise DockerError(f"docker {args[0]} timed out after {timeout}s") from e
    if check and proc.returncode != 0:
        raise DockerError(f"docker {shlex.join(args)} failed:\n{proc.stderr.strip()}")
    return proc


def qemu_env(arch: Arch) -> list[str]:
    return ["-e", f"QEMU_CPU={arch.qemu_cpu}"] if arch.qemu_cpu else []


def image_exists(tag: str) -> bool:
    return docker("image", "inspect", tag, check=False).returncode == 0


def build_peer_image(peer_image: str) -> None:
    dockerfile = E2E_DIR / "peer" / f"{peer_image}.Dockerfile"
    print(f"building {peer_image_tag(peer_image)} from {dockerfile.relative_to(REPO_ROOT)}")
    docker(
        "build",
        "--pull",
        "-t",
        peer_image_tag(peer_image),
        "-f",
        str(dockerfile),
        str(E2E_DIR / "peer"),
        timeout=1800,
    )


@dataclasses.dataclass
class Container:
    name: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""


class Run:
    """Docker resources of one run, all labelled with the run identifier."""

    def __init__(self, arch: Arch, suite: Suite, image: str) -> None:
        self.arch = arch
        self.suite = suite
        self.image = image
        self.peer = peer_image_tag(suite.peer_image)
        self.id = f"browntls-e2e-{os.getpid()}-{secrets.token_hex(4)}"
        self.network = self.id
        self.volume = f"{self.id}-pki"
        self.counter = 0

    def label(self) -> list[str]:
        return ["--label", f"{LABEL}={self.id}"]

    def __enter__(self) -> "Run":
        docker("network", "create", *self.label(), self.network)
        docker("volume", "create", *self.label(), self.volume)
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        names = docker(
            "ps", "-aq", "--filter", f"label={LABEL}={self.id}", check=False
        ).stdout.split()
        if names:
            docker("rm", "-f", *names, check=False)
        docker("network", "rm", self.network, check=False)
        docker("volume", "rm", "-f", self.volume, check=False)

    def generate_pki(self) -> None:
        docker(
            "run",
            "--rm",
            *self.label(),
            "-v",
            f"{self.volume}:/pki",
            "--entrypoint",
            "sh",
            self.peer,
            f"{SHARE}/gen-pki.sh",
            "/pki",
            timeout=600,
        )

    def _common(self, name: str, browntls: bool) -> list[str]:
        args = ["--name", name, *self.label(), "--network", self.network]
        args += ["-v", f"{self.volume}:/pki:ro"]
        if browntls:
            args += ["--platform", self.arch.platform, *qemu_env(self.arch)]
        return args

    def next_name(self, what: str) -> str:
        self.counter += 1
        return f"{self.id}-{self.counter}-{what}"

    def start_server(self, image: str, cmd: Sequence[str], env: dict[str, str]) -> Container:
        browntls = image == self.image
        name = self.next_name("server")
        args = ["run", "-d", *self._common(name, browntls)]
        args += ["--network-alias", SERVER_ALIAS]
        for k, v in env.items():
            args += ["-e", f"{k}={v}"]
        if not browntls:
            args += ["--entrypoint", cmd[0]]
            cmd = cmd[1:]
        docker(*args, image, *cmd)
        return Container(name)

    def run_client(self, image: str, cmd: Sequence[str], env: dict[str, str]) -> Container:
        browntls = image == self.image
        name = self.next_name("client")
        args = ["run", *self._common(name, browntls)]
        for k, v in env.items():
            args += ["-e", f"{k}={v}"]
        if not browntls:
            args += ["--entrypoint", cmd[0]]
            cmd = cmd[1:]
        c = Container(name)
        try:
            proc = docker(*args, image, *cmd, timeout=SCENARIO_TIMEOUT, check=False)
            c.exit_code, c.stdout, c.stderr = proc.returncode, proc.stdout, proc.stderr
        except DockerError as e:
            c.stderr = str(e)
        docker("rm", "-f", name, check=False)
        return c

    def wait_for_log(self, c: Container, needle: str, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            logs = docker("logs", c.name, check=False)
            if needle in logs.stdout:
                return True
            state = docker("inspect", "-f", "{{.State.Running}}", c.name, check=False)
            if state.stdout.strip() == "false":
                return False
            time.sleep(0.2)
        return False

    def finish_server(self, c: Container, wait: float) -> Container:
        """Waits up to `wait` seconds for the server to exit, then stops it."""
        try:
            proc = docker("wait", c.name, timeout=wait, check=False)
            if proc.returncode == 0 and proc.stdout.strip():
                c.exit_code = int(proc.stdout.strip())
        except DockerError:
            docker("kill", c.name, check=False)
        logs = docker("logs", c.name, check=False)
        c.stdout, c.stderr = logs.stdout, logs.stderr
        docker("rm", "-f", c.name, check=False)
        return c


# ----------------------------------------------------------------- checking


def events(output: str) -> list[dict]:
    out = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def check_browntls(sc: Scenario, role: str, c: Container, reply: str | None) -> list[str]:
    """Problems with the browntls side's output; empty when it passed."""
    evs = events(c.stdout)
    conns = [e for e in evs if e.get("event") == "connection" and e.get("role") == role]
    errors = [e.get("message", "") for e in evs if e.get("event") == "error"]
    if sc.refused:
        problems = []
        if conns:
            problems.append(f"browntls {role} completed a handshake that must be refused")
        if c.exit_code == 0:
            problems.append(f"browntls {role} exited successfully")
        if not any(r in m for m in errors for r in sc.refusal):
            problems.append(
                f"browntls {role} did not fail for the expected reason "
                f"({' or '.join(sc.refusal)}): {errors}"
            )
        return problems
    problems = [f"browntls {role} error: {m}" for m in errors]
    if c.exit_code != 0:
        problems.append(f"browntls {role} exit status {c.exit_code}")
    if len(conns) != sc.connections:
        problems.append(f"browntls {role}: {len(conns)} connections, expected {sc.connections}")
    for e in conns:
        first = e.get("index") == 0
        want = {
            "version": sc.expect_version,
            "suite": sc.expect_suite,
            "handshake": sc.expect_handshake if first else "Resumed",
        }
        # A resumed TLS 1.2 handshake has no key exchange.
        if first or sc.tls != "1.2":
            want["group"] = sc.expect_group
        for k, v in want.items():
            if v is not None and e.get(k) != v:
                problems.append(f"browntls {role} #{e.get('index')}: {k}={e.get(k)!r}, expected {v!r}")
        if role == "client" and e.get("peer_certificates", 0) < 1:
            problems.append("browntls client saw no server certificate")
        if role == "server" and sc.client_auth and e.get("peer_certificates", 0) < 1:
            problems.append("browntls server saw no client certificate")
        if role == "client" and reply is not None and e.get("received") != reply:
            problems.append(f"browntls client received {e.get('received')!r}, expected {reply!r}")
        if role == "server" and e.get("received") != MESSAGE:
            problems.append(f"browntls server received {e.get('received')!r}")
    return problems


def summarize(c: Container, role: str) -> str:
    conns = [e for e in events(c.stdout) if e.get("event") == "connection" and e.get("role") == role]
    if not conns:
        return "-"
    return ", ".join(
        f"{e.get('version')} {e.get('suite')} {e.get('group')} {e.get('handshake')}" for e in conns
    )


@dataclasses.dataclass
class Result:
    scenario: str
    role: str
    passed: bool
    seconds: float
    negotiated: str
    problems: list[str]


def run_scenario(run: Run, sc: Scenario, role: str, artifacts: Path | None) -> Result:
    """Runs `sc` with browntls in `role` against the suite's peer."""
    impl = run.suite.implementation
    start = time.monotonic()
    env = peer_env(sc, impl)
    problems: list[str] = []

    if role == "client":
        if impl == "browntls":
            server = run.start_server(run.image, browntls_args(sc, "server"), {})
            server_impl = "browntls"
        else:
            server = run.start_server(run.peer, peer_server_command(sc, impl), env)
            server_impl = impl
        client = run.run_client(run.image, browntls_args(sc, "client"), {})
        # gnutls-serv keeps running; the other servers exit after the
        # expected number of connections.
        server = run.finish_server(server, wait=1 if impl == "gnutls" else 20)
        problems += check_browntls(sc, "client", client, expected_reply(server_impl))
        if impl == "browntls":
            problems += check_browntls(sc, "server", server, None)
        negotiated = summarize(client, "client")
    else:
        server = run.start_server(run.image, browntls_args(sc, "server"), {})
        if not run.wait_for_log(server, '"event":"listening"', CONNECT_WAIT):
            problems.append("browntls server did not start listening")
            client = Container("-")
        else:
            client = run.run_client(run.peer, peer_client_command(sc, impl), env)
        server = run.finish_server(server, wait=20)
        problems += check_browntls(sc, "server", server, None)
        reply = expected_reply("browntls")
        got_reply = any(line.strip() == reply for line in client.stdout.splitlines())
        if sc.refused:
            if got_reply:
                problems.append(f"{impl} client received data although the handshake must fail")
        else:
            if not got_reply:
                problems.append(f"{impl} client did not print the reply {reply!r}")
            if client.exit_code != 0:
                problems.append(f"{impl} client exit status {client.exit_code}")
        negotiated = summarize(server, "server")

    seconds = time.monotonic() - start
    if artifacts is not None:
        d = artifacts / f"{sc.name}--browntls-{role}"
        d.mkdir(parents=True, exist_ok=True)
        for who, c in (("server", server), ("client", client)):
            (d / f"{who}.stdout").write_text(c.stdout)
            (d / f"{who}.stderr").write_text(c.stderr)
        (d / "problems.txt").write_text("\n".join(problems) + ("\n" if problems else ""))
    return Result(sc.name, role, not problems, seconds, negotiated, problems)


# ----------------------------------------------------------------- commands


def matrix(kind: str) -> dict:
    if kind == "images":
        include = [
            {
                "arch": a.name,
                "label": a.label,
                "platform": a.platform,
                "rust_target": a.rust_target,
                "emulated": a.qemu_cpu is not None,
            }
            for a in ARCHES.values()
        ]
    else:
        include = [
            {
                "arch": a.name,
                "label": a.label,
                "platform": a.platform,
                "runner": a.runner,
                "suite": s.name,
                "description": s.description,
                "emulated": a.qemu_cpu is not None,
            }
            for a in ARCHES.values()
            for s in SUITES.values()
        ]
    return {"include": include}


def cmd_matrix(args: argparse.Namespace) -> int:
    print(json.dumps(matrix(args.kind), separators=(",", ":")))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    suites = [SUITES[args.suite]] if args.suite else list(SUITES.values())
    for suite in suites:
        print(f"{suite.name}: {suite.description}")
        for sc in scenarios_for(suite):
            print(f"  {sc.name} (browntls as {', '.join(sc.roles_for(suite))})")
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    arch = ARCHES[args.arch]
    target = arch.rust_target
    env = dict(os.environ)
    triple = target.upper().replace("-", "_")
    # Static musl binaries linked by rust-lld: no C cross toolchain needed.
    env[f"CARGO_TARGET_{triple}_LINKER"] = "rust-lld"
    env[f"CARGO_TARGET_{triple}_RUSTFLAGS"] = " ".join(
        ["-C", "target-feature=+crt-static", *arch.rustflags]
    )
    # Targets that share a triple differ in RUSTFLAGS: separate directories
    # keep them from rebuilding each other.
    target_dir = Path(env.get("CARGO_TARGET_DIR", REPO_ROOT / "target")) / "e2e" / arch.name
    env["CARGO_TARGET_DIR"] = str(target_dir)
    binary = target_dir / target / "release" / "browntls-e2e"
    cargo = ["cargo", "build", "--release", "--locked", "-p", "browntls-e2e", "--target", target]
    print("+", shlex.join(cargo), flush=True)
    subprocess.run(cargo, cwd=REPO_ROOT, env=env, check=True)
    tag = args.tag or image_tag(arch.name)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()
    with tempfile.TemporaryDirectory(prefix="browntls-e2e-image-") as ctx:
        shutil.copy2(binary, Path(ctx) / "browntls-e2e")
        shutil.copy2(E2E_DIR / "Dockerfile", Path(ctx) / "Dockerfile")
        build = ["build", "--platform", arch.platform, "-t", tag]
        build += ["--label", f"org.opencontainers.image.revision={revision or 'unknown'}"]
        build += ["--label", f"org.oxibelt.browntls-e2e.target-cpu={arch.label}"]
        print("+ docker", shlex.join(build + [ctx]), flush=True)
        docker(*build, ctx, timeout=600)
    print(f"built {tag} ({arch.platform}, {arch.label})")
    if args.save:
        Path(args.save).parent.mkdir(parents=True, exist_ok=True)
        docker("save", "-o", args.save, tag, timeout=600)
        print(f"saved {tag} to {args.save}")
    return 0


def select(suite: Suite, names: Iterable[str]) -> list[Scenario]:
    names = list(names)
    available = scenarios_for(suite)
    if not names:
        return available
    by_name = {s.name: s for s in available}
    unknown = [n for n in names if n not in by_name]
    if unknown:
        raise SystemExit(f"scenarios not in suite {suite.name}: {', '.join(unknown)}")
    return [by_name[n] for n in names]


def write_summary(arch: Arch, suite: Suite, info: list[dict], peer_versions: str,
                  results: list[Result]) -> str:
    passed = sum(r.passed for r in results)
    lines = [
        f"### browntls E2E: {arch.name} ({arch.label}) vs {suite.description}",
        "",
        f"{passed}/{len(results)} passed.",
        "",
    ]
    if peer_versions:
        lines += [f"Peer: `{peer_versions}`", ""]
    accelerated = [f"{e['algorithm']}: {e['backend']}" for e in info if e.get("event") == "accel"]
    if accelerated:
        lines += ["<details><summary>browntls backends</summary>", ""]
        lines += [f"- {a}" for a in accelerated]
        lines += ["", "</details>", ""]
    lines += ["| Scenario | browntls role | Result | Negotiated (browntls side) | Time |"]
    lines += ["| --- | --- | --- | --- | --- |"]
    for r in results:
        verdict = "pass" if r.passed else "**FAIL**: " + "; ".join(r.problems).replace("|", "\\|")
        lines.append(
            f"| {r.scenario} | {r.role} | {verdict} | {r.negotiated} | {r.seconds:.1f}s |"
        )
    return "\n".join(lines) + "\n"


def cmd_run(args: argparse.Namespace) -> int:
    arch = ARCHES[args.arch]
    suite = SUITES[args.suite]
    image = args.image or image_tag(arch.name)
    chosen = select(suite, args.scenario)
    if not image_exists(image):
        raise SystemExit(f"image {image} not found; run `build --arch {arch.name}` or load it first")
    image_arch = docker("image", "inspect", "-f", "{{.Architecture}}", image).stdout.strip()
    if image_arch != arch.platform.split("/")[1]:
        raise SystemExit(f"{image} is built for {image_arch}, not {arch.platform}")
    if not args.skip_peer_build:
        build_peer_image(suite.peer_image)
    elif not image_exists(peer_image_tag(suite.peer_image)):
        raise SystemExit(f"--skip-peer-build given but {peer_image_tag(suite.peer_image)} is missing")

    artifacts = Path(args.artifact_dir) if args.artifact_dir else None
    results: list[Result] = []
    info_proc = docker(
        "run", "--rm", "--platform", arch.platform, *qemu_env(arch), image, "info", check=False
    )
    info = events(info_proc.stdout)
    backends = {e["algorithm"]: e for e in info if e.get("event") == "accel"}
    missing = [a for a in arch.accelerated if not backends.get(a, {}).get("accelerated")]
    if info_proc.returncode != 0 or missing:
        print(info_proc.stdout + info_proc.stderr, file=sys.stderr)
        raise SystemExit(
            f"{image} on {arch.label}: no accelerated backend for {', '.join(missing) or '?'}"
        )
    peer_versions = ""
    if suite.implementation != "browntls":
        probe = "openssl version" if suite.implementation == "openssl" else "gnutls-cli --version | head -n 1"
        peer_versions = docker(
            "run", "--rm", "--entrypoint", "sh", peer_image_tag(suite.peer_image), "-c", probe,
            check=False,
        ).stdout.strip()
    print(f"browntls image {image} ({arch.platform}); peer: {peer_versions or suite.description}")
    for e in info:
        if e.get("event") == "accel":
            print(f"  {e['algorithm']}: {e['backend']}")

    with Run(arch, suite, image) as run:
        print(f"run {run.id}: generating certificates")
        run.generate_pki()
        for sc in chosen:
            for role in sc.roles_for(suite):
                result = run_scenario(run, sc, role, artifacts)
                status = "ok  " if result.passed else "FAIL"
                print(f"{status} {sc.name} (browntls {role}) {result.seconds:.1f}s {result.negotiated}",
                      flush=True)
                for p in result.problems:
                    print(f"     {p}", flush=True)
                results.append(result)

    summary = write_summary(arch, suite, info, peer_versions, results)
    if artifacts is not None:
        artifacts.mkdir(parents=True, exist_ok=True)
        (artifacts / "summary.md").write_text(summary)
        (artifacts / "results.json").write_text(
            json.dumps([dataclasses.asdict(r) for r in results], indent=2) + "\n"
        )
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(summary)
    failed = [r for r in results if not r.passed]
    print(f"{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    m = sub.add_parser("matrix", help="print a GitHub Actions matrix as JSON")
    m.add_argument("kind", choices=("images", "e2e"))
    m.set_defaults(func=cmd_matrix)

    ls = sub.add_parser("list", help="list scenarios")
    ls.add_argument("--suite", choices=sorted(SUITES))
    ls.set_defaults(func=cmd_list)

    b = sub.add_parser("build", help="build the browntls-e2e image for an architecture")
    b.add_argument("--arch", required=True, choices=sorted(ARCHES))
    b.add_argument("--tag", help=f"image tag (default {image_tag('<arch>')})")
    b.add_argument("--save", metavar="TAR", help="also write the image to TAR")
    b.set_defaults(func=cmd_build)

    r = sub.add_parser("run", help="run a suite's scenarios")
    r.add_argument("--arch", required=True, choices=sorted(ARCHES))
    r.add_argument("--suite", required=True, choices=sorted(SUITES))
    r.add_argument("--image", help=f"browntls image (default {image_tag('<arch>')})")
    r.add_argument("--scenario", action="append", default=[], help="run only this scenario")
    r.add_argument("--artifact-dir", help="write logs, results.json and summary.md here")
    r.add_argument(
        "--skip-peer-build",
        action="store_true",
        help="use an already present peer image instead of building it",
    )
    r.set_defaults(func=cmd_run)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.func(args)
    except DockerError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
