"""Regression tests for the Docker end-to-end harness (tests/e2e/e2e.py).

These tests need neither Docker nor a Rust toolchain: they cover the matrix,
the scenario definitions and the command lines and checks the harness
derives from them.
"""

import importlib.util
import json
import sys
import unittest
from pathlib import Path

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
        self.assertEqual(pairs, {(a, s) for a in e2e.ARCHES for s in e2e.SUITES})
        for m in include:
            self.assertEqual(m["runner"], e2e.ARCHES[m["arch"]].runner)

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

    def test_client_auth_arguments(self):
        sc = self.scenario("tls13-client-auth")
        self.assertIn("--client-ca", e2e.browntls_args(sc, "server"))
        self.assertIn("--cert", e2e.browntls_args(sc, "client"))
        self.assertIn("-Verify", e2e.peer_server_command(sc, "openssl"))
        self.assertIn("--require-client-cert", e2e.peer_server_command(sc, "gnutls"))

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


if __name__ == "__main__":
    unittest.main()
