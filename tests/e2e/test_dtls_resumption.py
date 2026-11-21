"""Docker-free checks for DTLS 1.2 resumption evidence and isolation."""

import contextlib
import io
import json
import unittest
from unittest import mock

import dtls
from e2e import ARCHES, Container, Run


def records(role, mechanism):
    return [dict(
        event="connection", role=role, index=index, mechanism=mechanism,
        version="DTLSv1_2", suite=dtls.TLS12_SUITE,
        handshake="Full" if index == 0 else "Resumed", peer_certificates=1,
        sent=dtls.REPLY if role == "server" else dtls.REQUEST,
        received=dtls.REQUEST if role == "server" else dtls.REPLY,
        closed=True, ems=True,
    ) for index in range(2)]


class ResumptionTest(unittest.TestCase):
    def exchange(self, role, mechanism, mutate=None, brown_exit=0, peer_exit=0):
        runner = Run(ARCHES["amd64"], dtls.SUITES["openssl"], "brown:test")
        peer_role = "client" if role == "server" else "server"
        logs = {"brown": records(role, mechanism), "peer": records(peer_role, mechanism)}
        if mutate:
            mutate(logs)
        brown = Container("brown", brown_exit, "\n".join(map(json.dumps, logs["brown"])), "")
        peer = Container("peer", peer_exit, "\n".join(map(json.dumps, logs["peer"])), "")
        runner.start_server = mock.Mock()
        runner.wait_for_log = mock.Mock(return_value=True)
        runner.run_client = mock.Mock(return_value=peer if role == "server" else brown)
        runner.finish_server = mock.Mock(return_value=brown if role == "server" else peer)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            passed = dtls.exchange(runner, role, ("1.2",), mechanism)
        return passed, runner

    def test_four_cases_select_two_connections_and_one_mechanism(self):
        for role in ("client", "server"):
            for mechanism in ("session-id", "ticket"):
                with self.subTest(role=role, mechanism=mechanism):
                    passed, runner = self.exchange(role, mechanism)
                    self.assertTrue(passed)
                    server = runner.start_server.call_args.args[1]
                    client = runner.run_client.call_args.args[1]
                    brown, peer = (server, client) if role == "server" else (client, server)
                    self.assertEqual(peer, ["openssl-dtls", "client" if role == "server" else "server",
                                            dtls.SERVER_NAME, dtls.PORT, mechanism])
                    self.assertEqual(brown[-4:], ["--dtls12-resumption", mechanism,
                                                 "--accept" if role == "server" else "--connections",
                                                 "2"])
                    self.assertEqual(brown.count("--tls"), 1)
                    self.assertEqual(brown[brown.index("--tls") + 1], "1.2")
                    self.assertIn("--client-ca" if role == "server" else "--ca", brown)

    def test_both_peers_must_prove_full_then_resumed_with_data_and_closure(self):
        for role in ("client", "server"):
            for mechanism in ("session-id", "ticket"):
                for peer in ("brown", "peer"):
                    for index in (0, 1):
                        for key, value in (
                            ("role", "wrong"), ("index", 7), ("mechanism", "wrong"),
                            ("version", "DTLSv1_3"), ("suite", "wrong"),
                            ("handshake", "Resumed" if index == 0 else "Full"),
                            ("peer_certificates", 0), ("sent", "wrong"),
                            ("received", "wrong"), ("closed", False),
                        ):
                            with self.subTest(role=role, mechanism=mechanism, peer=peer,
                                              index=index, field=key):
                                def mutate(logs):
                                    logs[peer][index][key] = value
                                self.assertFalse(self.exchange(role, mechanism, mutate)[0])
                for peer in ("brown", "peer"):
                    for length in (0, 1, 3):
                        with self.subTest(role=role, mechanism=mechanism, peer=peer, length=length):
                            def mutate(logs):
                                logs[peer] = (logs[peer] * 2)[:length]
                            self.assertFalse(self.exchange(role, mechanism, mutate)[0])
                for index in (0, 1):
                    def no_ems(logs):
                        logs["peer"][index].pop("ems")
                    self.assertFalse(self.exchange(role, mechanism, no_ems)[0])
                self.assertFalse(self.exchange(role, mechanism, brown_exit=1)[0])
                self.assertFalse(self.exchange(role, mechanism, peer_exit=1)[0])

    def test_resumption_cli_is_bounded_and_keeps_failure(self):
        with mock.patch.object(dtls, "Run") as factory, \
             mock.patch.object(dtls, "image_exists", return_value=True), \
             mock.patch.object(dtls, "build_peer_image") as build, \
             mock.patch.object(dtls, "exchange", side_effect=[False, True, True, True]) as exchange, \
             mock.patch("sys.argv", ["dtls.py", "--arch", "amd64", "--suite", "openssl",
                                     "--resumption"]):
            self.assertEqual(dtls.main(), 1)
            build.assert_called_once_with("openssl-dtls")
            self.assertEqual(exchange.call_args_list, [
                mock.call(factory.return_value, role, ("1.2",), mechanism)
                for mechanism in ("session-id", "ticket") for role in ("client", "server")
            ])
            factory.return_value.__exit__.assert_called_once()

    def test_rejects_resumption_with_default_or_wolfssl_suite(self):
        for suite in ("all", "wolfssl"):
            with mock.patch("sys.argv", ["dtls.py", "--arch", "amd64", "--suite", suite,
                                         "--resumption"]), \
                 mock.patch.object(dtls, "Run") as factory, \
                 contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    dtls.main()
                self.assertEqual(error.exception.code, 2)
                factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
