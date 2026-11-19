"""Regression tests for the Docker end-to-end harness (tests/e2e/e2e.py).

These tests need neither Docker nor a Rust toolchain: they cover the matrix,
the scenario definitions and the command lines and checks the harness
derives from them.
"""

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

_SPEC = importlib.util.spec_from_file_location("e2e", Path(__file__).with_name("e2e.py"))
e2e = importlib.util.module_from_spec(_SPEC)
sys.modules["e2e"] = e2e
_SPEC.loader.exec_module(e2e)


def connection(role, index=0, **fields):
    event = {
        "event": "connection",
        "role": role,
        "index": index,
        "peer_certificates": 1,
        "received": e2e.MESSAGE if role == "server" else e2e.MESSAGE[::-1],
    }
    event.update(fields)
    return json.dumps(event)


class MatrixTest(unittest.TestCase):
    def test_e2e_matrix_covers_every_arch_and_suite(self):
        include = e2e.matrix("e2e")["include"]
        pairs = {(m["arch"], m["suite"]) for m in include}
        self.assertEqual(len(pairs), len(include))
        self.assertEqual(
            pairs,
            {
                (a, s)
                for a in e2e.ARCHES
                for s in e2e.SUITES
                if a not in e2e.SUITES[s].skip_arches
            },
        )
        for m in include:
            self.assertEqual(m["runner"], e2e.ARCHES[m["arch"]].runner)

    def test_e2e_matrix_names_the_peer_image_for_the_cache_key(self):
        for m in e2e.matrix("e2e")["include"]:
            peer_image = e2e.SUITES[m["suite"]].peer_image
            self.assertEqual(m["peer_image"], peer_image)
            self.assertTrue((e2e.E2E_DIR / "peer" / f"{peer_image}.Dockerfile").is_file())

    def test_ubuntu_lts_peers(self):
        # Ubuntu 24.04 (OpenSSL 3.0) runs everywhere; Ubuntu 26.04's riscv64
        # image needs RVA23, which the native riscv64 runner lacks.
        pairs = {(m["arch"], m["suite"]) for m in e2e.matrix("e2e")["include"]}
        for arch in e2e.ARCHES:
            self.assertIn((arch, "openssl-3.0"), pairs)
        self.assertNotIn(("riscv64", "openssl-ubuntu-26.04"), pairs)
        for arch in ("amd64", "arm64", "riscv64-zvk"):
            self.assertIn((arch, "openssl-ubuntu-26.04"), pairs)
        dockerfile = e2e.E2E_DIR / "peer" / "ubuntu-26.04.Dockerfile"
        self.assertIn("FROM ubuntu:26.04@sha256:", dockerfile.read_text())

    def test_run_refuses_a_skipped_arch(self):
        args = mock.Mock(arch="riscv64", suite="openssl-ubuntu-26.04")
        with self.assertRaisesRegex(SystemExit, "does not run on riscv64"):
            e2e.cmd_run(args)

    def test_image_matrix_has_one_entry_per_arch(self):
        include = e2e.matrix("images")["include"]
        self.assertEqual([m["arch"] for m in include], list(e2e.ARCHES))

    def test_target_architectures(self):
        amd64 = e2e.ARCHES["amd64"]
        self.assertIn("target-cpu=x86-64-v3", amd64.rustflags)
        self.assertEqual(e2e.ARCHES["arm64"].runner, "ubuntu-26.04-arm")
        self.assertEqual(e2e.ARCHES["riscv64"].runner, "ubuntu-24.04-riscv")
        self.assertIsNone(e2e.ARCHES["riscv64"].qemu_cpu)
        zvk = e2e.ARCHES["riscv64-zvk"]
        self.assertIsNotNone(zvk.qemu_cpu)
        self.assertIn('browntls_assume_riscv="zvkned"', zvk.rustflags)
        self.assertEqual(e2e.matrix("images")["include"][3]["emulated"], True)


class ScenarioTest(unittest.TestCase):
    def test_names_are_unique(self):
        names = [s.name for s in e2e.SCENARIOS]
        self.assertEqual(len(names), len(set(names)))

    def test_peer_names_exist_for_every_suite_and_group(self):
        for sc in e2e.SCENARIOS:
            if sc.suite:
                self.assertIn(sc.suite, e2e.SUITE_NAMES, sc.name)
            for g in sc.groups:
                self.assertIn(g, e2e.GROUP_NAMES, sc.name)
            self.assertIn(sc.key, ("ecdsa-p256", "rsa-2048", "ed25519"), sc.name)
            self.assertTrue(set(sc.roles) <= set(e2e.ROLES), sc.name)

    def test_gnutls_scenarios_have_priority_strings(self):
        for sc in e2e.scenarios_for(e2e.SUITES["gnutls"]):
            e2e.gnutls_priority(sc)

    def test_post_quantum_scenarios_follow_peer_support(self):
        def names(suite):
            return {s.name for s in e2e.scenarios_for(e2e.SUITES[suite])}

        self.assertIn("tls13-x25519mlkem768", names("openssl"))
        self.assertIn("defaults-pq", names("openssl"))
        self.assertIn("tls13-x25519mlkem768", names("openssl-ubuntu-26.04"))
        self.assertNotIn("tls13-x25519mlkem768", names("openssl-3.0"))
        self.assertIn("defaults-classical", names("openssl-3.0"))
        self.assertNotIn("tls13-x25519mlkem768", names("gnutls"))
        self.assertNotIn("tls12-cbc-without-etm-refused", names("browntls"))

    def test_browntls_suite_runs_each_scenario_once(self):
        suite = e2e.SUITES["browntls"]
        for sc in e2e.scenarios_for(suite):
            self.assertEqual(sc.roles_for(suite), ("client",))


class CommandTest(unittest.TestCase):
    def scenario(self, name):
        return next(s for s in e2e.SCENARIOS if s.name == name)

    def test_hello_retry_request_restricts_only_the_server(self):
        sc = self.scenario("tls13-hello-retry-request")
        self.assertNotIn("--group", e2e.browntls_args(sc, "client"))
        server = e2e.browntls_args(sc, "server")
        self.assertEqual(server[server.index("--group") + 1], "secp256r1")
        self.assertIn("-groups", e2e.peer_server_command(sc, "openssl"))

    def test_openssl_tls12_cbc_without_etm(self):
        sc = self.scenario("tls12-cbc-without-etm-refused")
        cmd = e2e.peer_server_command(sc, "openssl")
        self.assertEqual(cmd[cmd.index("-cipher") + 1], "ECDHE-RSA-AES128-SHA256")
        self.assertIn("-tls1_2", cmd)
        self.assertEqual(e2e.peer_env(sc, "openssl"), {"OPENSSL_CONF": f"{e2e.SHARE}/no-etm.cnf"})
        self.assertTrue(e2e.gnutls_priority(sc).endswith("%NO_ETM"))
        self.assertNotIn("--allow-mac-then-encrypt", e2e.browntls_args(sc, "client"))
        allowed = self.scenario("tls12-cbc-without-etm-allowed")
        self.assertIn("--allow-mac-then-encrypt", e2e.browntls_args(allowed, "server"))

    def test_optional_extension_arguments(self):
        sc = self.scenario("tls13-optional-extensions")
        client = e2e.browntls_args(sc, "client")
        server = e2e.browntls_args(sc, "server")
        for flag in ("--grease", "--ticket-request", "--padding"):
            self.assertIn(flag, client)
            self.assertNotIn(flag, server)
        for args in (client, server):
            self.assertEqual(
                args[args.index("--record-size-limit") + 1], str(e2e.OPTIONAL_RECORD_SIZE_LIMIT)
            )
        plain = self.scenario("tls13-aes128gcm-x25519")
        self.assertNotIn("--grease", e2e.browntls_args(plain, "client"))
        self.assertNotIn("--record-size-limit", e2e.browntls_args(plain, "server"))

    def test_client_auth_arguments(self):
        sc = self.scenario("tls13-client-auth")
        self.assertIn("--client-ca", e2e.browntls_args(sc, "server"))
        self.assertIn("--cert", e2e.browntls_args(sc, "client"))
        self.assertIn("-Verify", e2e.peer_server_command(sc, "openssl"))
        self.assertIn("--require-client-cert", e2e.peer_server_command(sc, "gnutls"))

    def test_async_scenarios_pass_the_flag_to_both_roles(self):
        scenarios = [s for s in e2e.SCENARIOS if s.async_io]
        self.assertEqual(len(scenarios), 3)
        for sc in scenarios:
            for role in sc.roles:
                self.assertIn("--async", e2e.browntls_args(sc, role))
        plain = self.scenario("tls13-aes128gcm-x25519")
        self.assertNotIn("--async", e2e.browntls_args(plain, "client"))

    def test_peer_clients_connect_to_the_server_alias(self):
        sc = self.scenario("tls12-rsa-chacha20")
        for impl in ("openssl", "gnutls"):
            cmd = e2e.peer_client_command(sc, impl)
            self.assertEqual(cmd[:2], ["sh", "-c"])
            self.assertIn(e2e.SERVER_ALIAS, cmd[2])

    def test_resumption_uses_two_connections(self):
        sc = self.scenario("tls13-resumption")
        args = e2e.browntls_args(sc, "client")
        self.assertEqual(args[args.index("--connections") + 1], "2")
        server = e2e.peer_server_command(sc, "openssl")
        self.assertEqual(server[server.index("-naccept") + 1], "2")


class CheckTest(unittest.TestCase):
    def scenario(self, name):
        return next(s for s in e2e.SCENARIOS if s.name == name)

    def test_expected_negotiation_passes(self):
        sc = self.scenario("tls13-aes128gcm-x25519")
        out = connection(
            "client",
            version="TLSv1_3",
            suite="TLS13_AES_128_GCM_SHA256",
            group="X25519",
            handshake="Full",
        )
        c = e2e.Container("c", 0, out)
        self.assertEqual(e2e.check_browntls(sc, "client", c, e2e.MESSAGE[::-1]), [])

    def test_wrong_group_and_reply_fail(self):
        sc = self.scenario("tls13-aes128gcm-x25519")
        out = connection(
            "client",
            version="TLSv1_3",
            suite="TLS13_AES_128_GCM_SHA256",
            group="secp256r1",
            handshake="Full",
            received="something else",
        )
        problems = e2e.check_browntls(sc, "client", e2e.Container("c", 0, out), e2e.MESSAGE[::-1])
        self.assertEqual(len(problems), 2, problems)

    def test_missing_connection_and_exit_status_fail(self):
        sc = self.scenario("tls12-rsa-chacha20")
        out = '{"event":"error","message":"peer is incompatible"}'
        problems = e2e.check_browntls(sc, "server", e2e.Container("s", 1, out), None)
        self.assertEqual(len(problems), 3, problems)

    def test_async_scenarios_require_async_output(self):
        sc = self.scenario("async-tls12")
        common = dict(
            version="TLSv1_2",
            suite="TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            group="secp256r1",
            handshake="Full",
        )
        reply = e2e.MESSAGE[::-1]
        ok = e2e.Container("c", 0, connection("client", io="async", **common))
        self.assertEqual(e2e.check_browntls(sc, "client", ok, reply), [])
        blocking = e2e.Container("c", 0, connection("client", **common))
        self.assertEqual(len(e2e.check_browntls(sc, "client", blocking, reply)), 1)

    def test_resumed_connection_must_be_resumed(self):
        sc = self.scenario("tls12-resumption")
        common = dict(version="TLSv1_2", suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        first = connection("client", 0, group="X25519", handshake="Full", **common)
        resumed = connection("client", 1, group="none", handshake="Resumed", **common)
        full = connection("client", 1, group="X25519", handshake="Full", **common)
        reply = e2e.MESSAGE[::-1]
        ok = e2e.Container("c", 0, first + "\n" + resumed)
        self.assertEqual(e2e.check_browntls(sc, "client", ok, reply), [])
        bad = e2e.Container("c", 0, first + "\n" + full)
        self.assertEqual(len(e2e.check_browntls(sc, "client", bad, reply)), 1)

    def test_refusal_must_fail_for_its_reason(self):
        sc = self.scenario("tls12-cbc-without-etm-refused")
        why = '{"event":"error","message":"peer is incompatible: EncryptThenMacExtensionRequired"}'
        self.assertEqual(e2e.check_browntls(sc, "client", e2e.Container("c", 1, why), None), [])
        other = '{"event":"error","message":"invalid peer certificate: UnknownIssuer"}'
        self.assertEqual(len(e2e.check_browntls(sc, "client", e2e.Container("c", 1, other), None)), 1)
        accepted = connection("client", version="TLSv1_2")
        self.assertEqual(
            len(e2e.check_browntls(sc, "client", e2e.Container("c", 0, accepted), None)), 3
        )

    def test_client_auth_requires_a_client_certificate(self):
        sc = self.scenario("tls12-client-auth")
        out = connection(
            "server",
            version="TLSv1_2",
            suite="TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            group="secp256r1",
            handshake="Full",
            peer_certificates=0,
        )
        problems = e2e.check_browntls(sc, "server", e2e.Container("s", 0, out), None)
        self.assertEqual(problems, ["browntls server saw no client certificate"])


class EchTest(unittest.TestCase):
    def scenario(self, name):
        return next(s for s in e2e.SCENARIOS if s.name == name)

    def names(self, suite):
        return {s.name for s in e2e.scenarios_for(e2e.SUITES[suite])}

    def test_suites_and_roles(self):
        go = e2e.SUITES["go"]
        self.assertTrue(all(s.ech is not None for s in e2e.scenarios_for(go)))
        for suite in ("openssl", "openssl-3.0", "openssl-ubuntu-26.04", "gnutls"):
            self.assertFalse(any(n.startswith("ech-") for n in self.names(suite)), suite)
        browntls = self.names("browntls")
        for sc in e2e.SCENARIOS:
            if sc.ech is not None:
                self.assertIn(sc.name, browntls)
        # Go has no split-mode server, nor GREASE or random identifiers.
        self.assertEqual(self.scenario("ech-split").roles_for(go), ("server",))
        self.assertEqual(self.scenario("ech-shared").roles_for(go), ("client", "server"))
        self.assertNotIn("ech-split-grease", self.names("go"))
        self.assertNotIn("ech-split-random-config-id", self.names("go"))

    def test_split_mode_commands(self):
        sc = self.scenario("ech-split-hello-retry-request")
        front = e2e.ech_client_facing_args(sc)
        self.assertEqual(front[0], "client-facing")
        self.assertIn(f"{e2e.SERVER_ALIAS}={e2e.BACKEND_ALIAS}:{e2e.PORT}", front)
        self.assertIn(e2e.pki(sc.key, "public.pem"), front)
        self.assertNotIn("--group", front)
        backend = e2e.ech_terminating_server_args(sc, 1, backend=True)
        self.assertIn("--ech-backend", backend)
        self.assertNotIn("--ech-config", backend)
        self.assertEqual(backend[backend.index("--group") + 1], "secp256r1")
        client = e2e.ech_browntls_client_args(sc)
        self.assertEqual(client[client.index("--server-name") + 1], e2e.SERVER_ALIAS)
        self.assertIn(e2e.ech_file("current", "ech-config-list"), client)

    def test_client_variants(self):
        stale = self.scenario("ech-split-retry-configs")
        client = e2e.ech_browntls_client_args(stale)
        self.assertIn(e2e.ech_file("stale", "ech-config-list"), client)
        self.assertIn("--ech-retry", client)
        self.assertIn("-retry", e2e.ech_go_client_command(stale))
        front = e2e.ech_client_facing_args(stale)
        self.assertEqual(front[front.index("--accept") + 1], "2")
        grease = self.scenario("ech-split-grease")
        client = e2e.ech_browntls_client_args(grease)
        self.assertIn("--ech-grease", client)
        self.assertNotIn("--ech-config-list", client)
        self.assertEqual(client[client.index("--server-name") + 1], e2e.ECH_PUBLIC_NAME)
        random = self.scenario("ech-split-random-config-id")
        self.assertIn("--ech-random-config-id", e2e.ech_browntls_client_args(random))
        front = e2e.ech_client_facing_args(random)
        self.assertIn("--ech-trial-decryption", front)
        self.assertIn("--ech-public-name-check", front)

    def test_shared_mode_commands(self):
        sc = self.scenario("ech-shared-hello-retry-request")
        server = e2e.ech_terminating_server_args(sc, 1, backend=False)
        self.assertIn("--ech-config", server)
        self.assertNotIn("--ech-backend", server)
        self.assertTrue(any(a.startswith(e2e.ECH_PUBLIC_NAME + ",") for a in server))
        go = e2e.ech_go_server_command(sc)
        self.assertIn("-p256-only", go)
        self.assertEqual(go.count("-cert"), 2)

    def test_checks(self):
        sc = self.scenario("ech-split-retry-configs")
        reply = e2e.MESSAGE[::-1]
        rejected = '{"event":"ech-rejected","index":0,"retry_configs":true}'
        accepted = connection(
            "client", version="TLSv1_3", handshake="Full", ech="Accepted", received=reply
        )
        good = e2e.Container("c", 0, rejected + "\n" + accepted)
        self.assertEqual(e2e.check_ech_client(sc, "browntls", good), [])
        # The retry must follow exactly one rejection.
        self.assertEqual(
            len(e2e.check_ech_client(sc, "browntls", e2e.Container("c", 0, accepted))), 1
        )
        go = json.dumps(
            {
                "event": "connection",
                "role": "client",
                "version": "TLSv1_3",
                "handshake": "Full",
                "ech_accepted": False,
                "received": reply,
            }
        )
        problems = e2e.check_ech_client(sc, "go", e2e.Container("c", 0, rejected + "\n" + go))
        self.assertEqual(problems, ["go client: ECH not accepted"])

        decisions = "\n".join(
            [
                '{"event":"client-facing","decision":"Local","ech":"Rejected"}',
                '{"event":"ech-required","role":"server","index":0}',
                '{"event":"client-facing","decision":"Forward","ech":"Accepted",'
                f'"server_name":"{e2e.SERVER_ALIAS}"}}',
            ]
        )
        self.assertEqual(e2e.check_client_facing(sc, e2e.Container("f", 0, decisions)), [])
        wrong = decisions.replace('"Forward"', '"Local"')
        self.assertEqual(len(e2e.check_client_facing(sc, e2e.Container("f", 0, wrong))), 1)

        backend = connection(
            "server", version="TLSv1_3", handshake="Full", ech="Accepted", server_name="tls-server"
        )
        self.assertEqual(
            e2e.check_ech_server(sc, "browntls", "b", e2e.Container("b", 0, backend), 1, 0, 0), []
        )
        outer = backend.replace("tls-server", e2e.ECH_PUBLIC_NAME)
        self.assertEqual(
            len(e2e.check_ech_server(sc, "browntls", "b", e2e.Container("b", 0, outer), 1, 0, 0)), 1
        )


class DockerTest(unittest.TestCase):
    def test_timeout_reports_the_last_output(self):
        lines = [f"#{i} step {i}".encode() for i in range(100)]
        expired = subprocess.TimeoutExpired(
            ["docker", "build"], 1800, output=b"", stderr=b"\n".join(lines) + b"\n"
        )
        with mock.patch.object(e2e.subprocess, "run", side_effect=expired):
            with self.assertRaises(e2e.DockerError) as raised:
                e2e.docker("build", ".", timeout=1800)
        message = str(raised.exception)
        self.assertIn("docker build timed out after 1800s", message)
        self.assertIn("#99 step 99", message)
        self.assertIn(f"#{100 - e2e.TIMEOUT_TAIL_LINES} step", message)
        self.assertNotIn(f"#{99 - e2e.TIMEOUT_TAIL_LINES} step", message)

    def test_timeout_without_output(self):
        expired = subprocess.TimeoutExpired(["docker", "build"], 5)
        with mock.patch.object(e2e.subprocess, "run", side_effect=expired):
            with self.assertRaises(e2e.DockerError) as raised:
                e2e.docker("build", ".", timeout=5)
        self.assertEqual(str(raised.exception), "docker build timed out after 5s")

    def test_peer_build_uses_plain_progress_and_can_be_saved(self):
        calls = []

        def fake_docker(*args, **kwargs):
            calls.append((args, kwargs))
            return subprocess.CompletedProcess(["docker", *args], 0, "", "")

        args = e2e.parser().parse_args(["build-peer", "--suite", "go", "--save", "/nonexistent/peer.tar"])
        with mock.patch.object(e2e, "docker", side_effect=fake_docker), \
                mock.patch.object(e2e.Path, "mkdir"), \
                mock.patch("builtins.print"):
            self.assertEqual(args.func(args), 0)
        (build, build_kwargs), (save, _) = calls
        self.assertEqual(build[0], "build")
        self.assertIn("browntls-e2e-peer:go", build)
        self.assertEqual(build_kwargs["env"], {"BUILDKIT_PROGRESS": "plain"})
        self.assertEqual(save, ("save", "-o", "/nonexistent/peer.tar", "browntls-e2e-peer:go"))


if __name__ == "__main__":
    unittest.main()
