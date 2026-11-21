"""Docker-free regression checks for the DTLS runner's interop gates."""

import contextlib
import io
import json
import unittest
from unittest import mock

import dtls
from e2e import ARCHES, Container, Run


OPENSSL_SUCCESS = (
    "verified DTLSv1.2, ECDHE-ECDSA-AES128-GCM-SHA256, EMS, mTLS, "
    "full handshake, payloads and close_notify"
)


class DtlsTest(unittest.TestCase):
    def run_exchange(self, role="client", versions=("1.2",), peer="openssl",
                     fields=None, brown_exit=0, peer_exit=0, marker=None, ready=True,
                     copies=1, group=None):
        suite = (dtls.CID_SUITE if peer == "wolfssl-cid" else
                 dtls.PQC_SUITE if peer == "wolfssl-pqc" else dtls.SUITES[peer])
        runner = Run(ARCHES["amd64"], suite, "brown:test")
        runner.start_server = mock.Mock()
        runner.wait_for_log = mock.Mock(return_value=ready)
        runner.run_client = mock.Mock()
        runner.finish_server = mock.Mock()
        server = role == "server"
        record = {
            "event": "connection", "role": role,
            "version": "DTLSv1_2" if peer == "openssl" or versions == ("1.2",) else "DTLSv1_3",
            "suite": dtls.TLS12_SUITE,
            "handshake": "FullWithHelloRetryRequest" if group else "Full",
            "peer_certificates": 1, "closed": True,
            "sent": dtls.REPLY if server else dtls.REQUEST,
            "received": dtls.REQUEST if server else dtls.REPLY,
        }
        if group is not None:
            record["group"] = group
        record.update(fields or {})
        brown = Container("brown", brown_exit, (json.dumps(record) + "\n") * copies, "")
        oracle = Container("peer", peer_exit, marker if marker is not None else (
            OPENSSL_SUCCESS if peer == "openssl" else
            (f"verified DTLSv1.3, {group}, mTLS, full handshake, payloads and close_notify"
             if peer == "wolfssl-pqc" else
            (f"verified DTLSv1.{versions[0][-1]}, bidirectional CID, mTLS, "
             "full handshake, payloads and close_notify") if peer == "wolfssl-cid" else
            "verified DTLSv1.3, payloads and close_notify")
        ), "")
        runner.run_client.return_value = oracle if server else brown
        runner.finish_server.return_value = brown if server else oracle
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            passed = dtls.exchange(runner, role, versions, group=group)
        return passed, runner

    def test_both_openssl_roles_and_explicit_mixed_versions(self):
        for versions in dtls.version_sets(dtls.SUITES["openssl"]):
            for role in ("client", "server"):
                with self.subTest(role=role, versions=versions):
                    passed, runner = self.run_exchange(role, versions)
                    self.assertTrue(passed)
                    server = runner.start_server.call_args.args
                    client = runner.run_client.call_args.args
                    brown, peer = (server, client) if role == "server" else (client, server)
                    self.assertEqual(brown[0], runner.image)
                    self.assertEqual(peer[0], runner.peer)
                    self.assertEqual(peer[1][0], "openssl-dtls")
                    command = brown[1]
                    offered = [command[i + 1] for i, flag in enumerate(command) if flag == "--tls"]
                    self.assertEqual(offered, list(versions))
                    self.assertIn(dtls.TLS12_SUITE, command)
                    self.assertEqual("TLS13_AES_128_GCM_SHA256" in command, "1.3" in versions)
                    self.assertIn(f"{dtls.PKI}/ca.pem", command)
                    self.assertIn(f"{dtls.PKI}/{role}.pem", command)
                    self.assertIn(f"{dtls.PKI}/{role}.key", command)
                    self.assertIn("--client-ca" if role == "server" else "--ca", command)
                    if role == "client":
                        self.assertIn("--server-name", command)
                        self.assertIn(dtls.SERVER_NAME, command)

    def test_wolfssl_roles_still_select_dtls13(self):
        self.assertEqual(dtls.version_sets(dtls.SUITES["wolfssl"]), (("1.3",),))
        for role in ("client", "server"):
            self.assertTrue(self.run_exchange(role, ("1.3",), "wolfssl")[0])

    def test_rfc10024_groups_are_forced_and_verified_in_both_roles(self):
        for group in dtls.PQC_GROUPS:
            for role in ("client", "server"):
                with self.subTest(group=group, role=role):
                    passed, runner = self.run_exchange(role, ("1.3",), "wolfssl-pqc",
                                                       group=group)
                    self.assertTrue(passed)
                    brown_command = (runner.run_client.call_args.args[1]
                                     if role == "client" else
                                     runner.start_server.call_args.args[1])
                    peer_command = (runner.start_server.call_args.args[1]
                                    if role == "client" else
                                    runner.run_client.call_args.args[1])
                    self.assertIn("--group", brown_command)
                    self.assertEqual(brown_command[brown_command.index("--group") + 1], group)
                    self.assertEqual(peer_command[-2:], ["--group", group])
                    for overrides in (
                        {"fields": {"group": "X25519"}},
                        {"fields": {"handshake": "Full"}},
                        {"fields": {"peer_certificates": 0}},
                        {"fields": {"received": "wrong"}},
                        {"peer_exit": 1},
                    ):
                        self.assertFalse(self.run_exchange(role, ("1.3",), "wolfssl-pqc",
                                                           group=group, **overrides)[0])

    def test_opt_in_cid_versions_roles_and_evidence(self):
        self.assertEqual(dtls.version_sets(dtls.CID_SUITE), (("1.2",), ("1.3",)))
        for versions in dtls.version_sets(dtls.CID_SUITE):
            for role in ("client", "server"):
                with self.subTest(versions=versions, role=role):
                    passed, runner = self.run_exchange(role, versions, "wolfssl-cid")
                    self.assertTrue(passed)
                    server = runner.start_server.call_args.args[1]
                    client = runner.run_client.call_args.args[1]
                    brown, peer = (server, client) if role == "server" else (client, server)
                    self.assertIn("--dtls-cid", brown)
                    self.assertEqual(peer[-2:], ["--cid", versions[0]])
                    for kwargs in ({"marker": "verified DTLSv1.3, payloads and close_notify"},
                                   {"fields": {"peer_certificates": 0}},
                                   {"fields": {"closed": False}},
                                   {"fields": {"handshake": "Resumed"}},
                                   {"fields": {"received": "wrong"}},
                                   {"peer_exit": 1}):
                        self.assertFalse(self.run_exchange(role, versions, "wolfssl-cid",
                                                           **kwargs)[0])

    def test_cid_is_explicitly_selected(self):
        with mock.patch.object(dtls, "Run") as factory, \
             mock.patch.object(dtls, "image_exists", return_value=True), \
             mock.patch.object(dtls, "build_peer_image"), \
             mock.patch.object(dtls, "exchange", return_value=True) as exchange, \
             mock.patch("sys.argv", ["dtls.py", "--arch", "amd64", "--suite", "wolfssl-cid"]):
            self.assertEqual(dtls.main(), 0)
            factory.assert_called_once_with(ARCHES["amd64"], dtls.CID_SUITE, mock.ANY)
            self.assertEqual(exchange.call_count, 4)

    def test_rfc10024_suite_is_explicit_and_runs_all_groups_in_both_roles(self):
        with mock.patch.object(dtls, "Run") as factory, \
             mock.patch.object(dtls, "image_exists", return_value=True), \
             mock.patch.object(dtls, "build_peer_image") as build, \
             mock.patch.object(dtls, "exchange", return_value=True) as exchange, \
             mock.patch("sys.argv", ["dtls.py", "--arch", "amd64", "--suite", "wolfssl-pqc"]):
            self.assertEqual(dtls.main(), 0)
            factory.assert_called_once_with(ARCHES["amd64"], dtls.PQC_SUITE, mock.ANY)
            build.assert_called_once_with("wolfssl")
            self.assertEqual(exchange.call_args_list, [
                mock.call(factory.return_value, role, ("1.3",), group=group)
                for group in dtls.PQC_GROUPS
                for role in ("client", "server")
            ])

    def test_refuses_missing_or_wrong_evidence_in_either_role(self):
        for role in ("client", "server"):
            for fields in (
                {"version": "DTLSv1_3"}, {"suite": "TLS13_AES_128_GCM_SHA256"},
                {"peer_certificates": 0}, {"handshake": "Resumed"},
                {"closed": False}, {"received": "wrong"}, {"sent": "wrong"},
                {"role": "wrong"},
            ):
                with self.subTest(role=role, fields=fields):
                    self.assertFalse(self.run_exchange(role, fields=fields)[0])
            for overrides in (
                {"brown_exit": 1}, {"peer_exit": 1}, {"copies": 0}, {"copies": 2},
                {"marker": "verified DTLSv1.3, payloads and close_notify"},
                {"marker": ""}, {"ready": False},
            ):
                with self.subTest(role=role, overrides=overrides):
                    passed, runner = self.run_exchange(role, **overrides)
                    self.assertFalse(passed)
                    if overrides.get("ready") is False:
                        runner.run_client.assert_not_called()
                        runner.finish_server.assert_called_once()

    def test_default_runs_all_six_exchanges_and_keeps_failure(self):
        with mock.patch.object(dtls, "Run") as factory, \
             mock.patch.object(dtls, "image_exists", return_value=True), \
             mock.patch.object(dtls, "build_peer_image") as build, \
             mock.patch.object(dtls, "exchange", side_effect=[False, True, True, True, True, True]) as exchange, \
             mock.patch("sys.argv", ["dtls.py", "--arch", "amd64"]):
            runner = factory.return_value
            self.assertEqual(dtls.main(), 1)
            self.assertEqual(build.call_args_list, [mock.call("wolfssl"), mock.call("openssl-dtls")])
            self.assertEqual(exchange.call_count, 6)
            self.assertEqual(exchange.call_args_list, [
                mock.call(runner, role, versions)
                for versions in (("1.3",), ("1.2",), ("1.2", "1.3"))
                for role in ("client", "server")
            ])
            self.assertEqual(runner.generate_pki.call_args_list,
                             [mock.call(dtls.SERVER_NAME), mock.call(dtls.SERVER_NAME)])
            self.assertEqual(runner.__exit__.call_count, 2)

    def test_openssl_only_reuses_image_when_requested(self):
        with mock.patch.object(dtls, "Run") as factory, \
             mock.patch.object(dtls, "image_exists", return_value=True), \
             mock.patch.object(dtls, "build_peer_image") as build, \
             mock.patch.object(dtls, "exchange", return_value=True) as exchange, \
             mock.patch("sys.argv", ["dtls.py", "--arch", "amd64", "--suite", "openssl",
                                     "--skip-peer-build"]):
            self.assertEqual(dtls.main(), 0)
            build.assert_not_called()
            factory.assert_called_once_with(ARCHES["amd64"], dtls.SUITES["openssl"], mock.ANY)
            self.assertEqual(exchange.call_count, 4)


if __name__ == "__main__":
    unittest.main()
