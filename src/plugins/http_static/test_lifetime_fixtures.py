# SPDX-License-Identifier: Apache-2.0
"""Compiler-free HSS witness fixtures; these do not run VPP or its harness."""

import ast
import contextlib
import errno
import http.client
import io
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
SUITE = ast.parse((ROOT / "test/asf/test_http_static.py").read_text())
CLI = next(
    node
    for node in SUITE.body
    if isinstance(node, ast.ClassDef) and node.name == "TestHttpStaticCli"
)


def helper(name):
    node = next(node for node in CLI.body if getattr(node, "name", None) == name)
    namespace = {
        "subprocess": subprocess,
        "sys": sys,
        "re": re,
        "unittest": unittest,
        "config": types.SimpleNamespace(excluded_plugins=[]),
    }
    exec(
        compile(ast.Module(body=[node], type_ignores=[]), "hss-helper", "exec"),
        namespace,
    )
    return namespace[name]


def script(name):
    method = next(node for node in CLI.body if getattr(node, "name", None) == name)
    return next(
        node.value.value
        for node in ast.walk(method)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "script"
            for target in node.targets
        )
    )


class TestClientWitnesses(unittest.TestCase):
    ns_name = "fixture-only"

    def pending_response(self, outcome):
        response = types.SimpleNamespace(
            status=200, length=1024, getheader=lambda name: "http_static_server_0"
        )
        response.read = lambda size: outcome() if callable(outcome) else outcome
        connection = types.SimpleNamespace(
            connect=lambda: None,
            sock=types.SimpleNamespace(setsockopt=lambda *args: None),
            request=lambda *args: None,
            getresponse=lambda: response,
            close=lambda: None,
        )
        output = io.StringIO()
        with (
            patch.object(http.client, "HTTPConnection", return_value=connection),
            patch.object(
                sys, "argv", ["fixture", json.dumps([8082, "/large.txt", False, True])]
            ),
            patch.object(sys, "stdin", io.StringIO("drain\n")),
            contextlib.redirect_stdout(output),
        ):
            exec(compile(script("_client"), "hss-client", "exec"), {})
        return json.loads(output.getvalue().splitlines()[-1])

    def test_pending_timeout_is_failure(self):
        def timeout():
            raise TimeoutError("fixture timeout")

        with self.assertRaises(TimeoutError):
            self.pending_response(timeout)
        with self.assertRaises(AssertionError):
            helper("_assert_closed")(self, {"closed": "TimeoutError"})

    def test_pending_eof_and_reset_are_close_evidence(self):
        helper("_assert_closed")(self, self.pending_response(b""))

        def reset():
            raise ConnectionResetError(errno.ECONNRESET, "fixture reset")

        helper("_assert_closed")(self, self.pending_response(reset))

    def test_complete_response_is_not_close_evidence(self):
        with self.assertRaises(AssertionError):
            helper("_assert_closed")(self, self.pending_response(b"x" * 1024))

    def test_connect_probe_requires_econnrefused(self):
        probe = compile(script("_refused"), "hss-connect", "exec")
        with patch.object(sys, "argv", ["fixture", "8085"]):
            with (
                patch.object(
                    socket,
                    "create_connection",
                    side_effect=ConnectionRefusedError(errno.ECONNREFUSED, "refused"),
                ),
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                exec(probe, {})
            self.assertEqual(output.getvalue(), "ECONNREFUSED\n")
            for error in (
                TimeoutError("timeout"),
                OSError(errno.ENETUNREACH, "unreachable"),
            ):
                with self.subTest(error=error):
                    with patch.object(socket, "create_connection", side_effect=error):
                        with self.assertRaises(type(error)):
                            exec(probe, {})
            connection = types.SimpleNamespace(close=lambda: None)
            with patch.object(socket, "create_connection", return_value=connection):
                with self.assertRaisesRegex(RuntimeError, "still accepts TCP"):
                    exec(probe, {})

    def test_refusal_helper_rejects_arbitrary_process_failures(self):
        for code, output in ((52, b""), (7, b""), (1, b"ECONNREFUSED"), (0, b"")):
            with self.subTest(code=code, output=output):
                result = subprocess.CompletedProcess([], code, output, b"fixture error")
                with patch.object(subprocess, "run", return_value=result):
                    with self.assertRaises(AssertionError):
                        helper("_refused")(self, 8085)
        result = subprocess.CompletedProcess([], 0, b"ECONNREFUSED\n", b"")
        with patch.object(subprocess, "run", return_value=result) as run:
            helper("_refused")(self, 8085)
        self.assertNotIn("curl", run.call_args.args[0])

    def test_uri_identity_reports_explicit_tls_exclusions(self):
        method = helper("test_http_static_listener_uri_identity")
        for excluded in ([], ["tlsopenssl"]):
            with self.subTest(excluded=excluded):
                method.__globals__["config"] = types.SimpleNamespace(
                    excluded_plugins=excluded
                )
                case_type = type(
                    "IdentityFixture",
                    (unittest.TestCase,),
                    {method.__name__: method},
                )
                case = case_type(method.__name__)
                case.vapi = types.SimpleNamespace(
                    cli=unittest.mock.Mock(),
                    cli_return_response=unittest.mock.Mock(
                        return_value=types.SimpleNamespace(retval=0, reply="")
                    ),
                )
                case._client = unittest.mock.Mock(return_value=object())
                case._response = unittest.mock.Mock(return_value={"status": 200})
                case._stop_client = unittest.mock.Mock()
                case._refused = unittest.mock.Mock()
                result = unittest.TestResult()
                case.run(result)
                self.assertEqual(result.testsRun, 1)
                self.assertEqual(result.failures, [])
                self.assertEqual(result.errors, [])
                if excluded:
                    self.assertEqual(len(result.skipped), 2)
                    for (subtest, reason), protocol in zip(
                        result.skipped, ("tls", "https")
                    ):
                        self.assertIn(f"protocol='{protocol}'", str(subtest))
                        self.assertEqual(
                            reason,
                            f"{protocol} identity: tlsopenssl explicitly excluded",
                        )
                else:
                    self.assertEqual(result.skipped, [])
                secure_calls = [
                    call.kwargs["secure"] for call in case._client.call_args_list
                ]
                self.assertEqual(
                    secure_calls, [False] * 4 + ([] if excluded else [True] * 4)
                )
                self.assertEqual(case._response.call_count, len(secure_calls))
                self.assertEqual(case._refused.call_count, len(secure_calls))
                commands = [call.args[0] for call in case.vapi.cli.call_args_list]
                deletions = [
                    call.args[0]
                    for call in case.vapi.cli_return_response.call_args_list
                ]
                self.assertEqual(len(deletions), len(secure_calls))
                protocols = (
                    ("tcp", "http") if excluded else ("tcp", "http", "tls", "https")
                )
                for protocol in protocols:
                    uri = f"{protocol}://10.10.1.2:8085"
                    self.assertEqual(
                        commands.count(
                            f"http static listener add uri {uri} url-handlers http1-only"
                        ),
                        2,
                    )
                    self.assertEqual(
                        deletions.count(f"http static listener del uri {uri}"), 2
                    )

    def test_uri_identity_rejects_failed_delete_reply(self):
        method = helper("test_http_static_listener_uri_identity")
        method.__globals__["config"] = types.SimpleNamespace(excluded_plugins=[])
        case_type = type(
            "IdentityDeleteFixture", (unittest.TestCase,), {method.__name__: method}
        )
        case = case_type(method.__name__)
        message = "http static listener: Listener with given endpoint not found"

        def delete(command):
            if command == "http static listener del uri tcp://10.10.1.2:8085":
                return types.SimpleNamespace(retval=-1, reply=message)
            return types.SimpleNamespace(retval=0, reply="")

        case.vapi = types.SimpleNamespace(
            cli=unittest.mock.Mock(),
            cli_return_response=unittest.mock.Mock(side_effect=delete),
        )
        case._client = unittest.mock.Mock(return_value=object())
        case._response = unittest.mock.Mock(return_value={"status": 200})
        case._stop_client = unittest.mock.Mock()
        case._refused = unittest.mock.Mock()
        result = unittest.TestResult()
        case.run(result)
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.skipped, [])
        self.assertEqual(len(result.failures), 1)
        failed_subtest, traceback = result.failures[0]
        self.assertIn("protocol='tcp'", str(failed_subtest))
        self.assertIn("AssertionError: -1 != 0", traceback)
        self.assertIn(message, traceback)
        self.assertEqual(case._client.call_count, 7)
        self.assertEqual(case._refused.call_count, 6)

    def test_http3_identity_queries_added_session_details(self):
        method = helper("test_http_static_listener_http3_identity")
        for alpn in ("h3", "http/1.1"):
            with self.subTest(alpn=alpn):
                active = False
                summary = "[0:2][Q] existing\n"

                def cli(command):
                    nonlocal active
                    if command.startswith("http static listener add"):
                        active = True
                    if command == "show session listeners quic verbose 2":
                        return summary + ("[1:5][Q] http\n" if active else "")
                    if command == "show session thread 1 index 5":
                        return f"QUIC listener ALPN: {alpn}"
                    return ""

                def delete(command):
                    nonlocal active
                    active = False
                    return types.SimpleNamespace(retval=0, reply="")

                case = unittest.TestCase()
                case.vapi = types.SimpleNamespace(
                    cli=unittest.mock.Mock(side_effect=cli),
                    cli_return_response=unittest.mock.Mock(side_effect=delete),
                )
                case._wait_released = unittest.mock.Mock()
                try:
                    if alpn == "h3":
                        method(case)
                        self.assertEqual(case.vapi.cli_return_response.call_count, 2)
                        self.assertEqual(case._wait_released.call_count, 2)
                        self.assertEqual(
                            case.vapi.cli.call_args_list.count(
                                unittest.mock.call("show session thread 1 index 5")
                            ),
                            2,
                        )
                    else:
                        with self.assertRaises(AssertionError):
                            method(case)
                        case.vapi.cli_return_response.assert_not_called()
                finally:
                    case.doCleanups()


class TestLifecycleObservations(unittest.TestCase):
    def test_diagnostic_parsers_preserve_resource_identity(self):
        listeners = (
            "listener 2, uri 10.10.1.2:8080, www-root , cache-size 10m url-handlers 1 retiring 1\n"
            "listener 3, uri 10.10.1.2:8080, www-root /tmp, cache-size 10m url-handlers 0 retiring 0\n"
        )
        self.vapi = types.SimpleNamespace(
            cli=unittest.mock.Mock(return_value=listeners)
        )
        self.assertEqual(helper("_listener_states")(self), ({2: 1, 3: 0}, listeners))
        records = {
            "5": "app:\t http_static_server_9 app-index 5 ns 0:default\n",
            "7": "app:\t http_static_server_10 app-index 7 ns 0:default\n",
        }
        summary = "5         http_static_server_9default\n7         http_static_server_1default\n"

        def cli(command):
            if command in ("show app", "show app verbose"):
                return summary
            index = command.split()[2]
            self.assertEqual(command, f"show app {index} verbose")
            return records[index]

        self.vapi.cli.side_effect = cli
        self.vapi.cli.reset_mock()
        apps = "\n".join(records.values())
        self.assertEqual(
            helper("_hss_apps")(self),
            ({("5", "http_static_server_9"), ("7", "http_static_server_10")}, apps),
        )
        self.assertEqual(
            self.vapi.cli.call_args_list,
            [
                unittest.mock.call("show app"),
                unittest.mock.call("show app 5 verbose"),
                unittest.mock.call("show app 7 verbose"),
            ],
        )
        previous = None
        for generation in (1, 9, 10, 11, 13):
            with self.subTest(generation=generation):
                name = f"http_static_server_{generation}"
                summary = f"3         {name[:20]}default\n"
                records = {"3": f"app:\t {name} app-index 3 ns 0:default\n"}
                self.vapi.cli.reset_mock()
                identities, output = helper("_hss_apps")(self)
                self.assertEqual(identities, {("3", name)})
                self.assertEqual(output, records["3"])
                self.assertEqual(
                    self.vapi.cli.call_args_list,
                    [
                        unittest.mock.call("show app"),
                        unittest.mock.call("show app 3 verbose"),
                    ],
                )
                if previous is not None:
                    self.assertTrue(previous.isdisjoint(identities))
                previous = identities
        for record in (
            "app:\t http_static_server_13 app-index 4 ns 0:default\n",
            "No app with index 3\n",
            "app:\t http_static_server_13 app-index broken ns 0:default\n",
            records["3"] * 2,
            "app:\t http_static_server_13 app-index 3 ns 0:default\n"
            "app:\t http_static_server_14 app-index 4 ns 0:default\n",
        ):
            with self.subTest(record=record):
                records = {"3": record}
                with self.assertRaises(AssertionError):
                    helper("_hss_apps")(self)

    def test_destroy_observer_rejects_each_retained_resource(self):
        old_app = ("5", "http_static_server_9")
        new_app = ("7", "http_static_server_10")
        method = helper("_wait_destroyed")
        clock = types.SimpleNamespace(
            monotonic=unittest.mock.Mock(side_effect=[0, 11]),
            sleep=unittest.mock.Mock(),
        )
        method.__globals__["time"] = clock
        self._hss_apps = unittest.mock.Mock(return_value=({new_app}, "new app"))
        self._listener_states = unittest.mock.Mock(
            return_value=({3: 0}, "new listener")
        )
        self.vapi = types.SimpleNamespace(cli=unittest.mock.Mock(return_value=""))
        method(self, old_app)
        for resource in ("app", "listener", "session"):
            with self.subTest(resource=resource):
                clock.monotonic.side_effect = [0, 11]
                self._hss_apps.return_value = ({new_app}, "new app")
                self._listener_states.return_value = ({3: 0}, "new listener")
                self.vapi.cli.return_value = ""
                if resource == "app":
                    self._hss_apps.return_value = (
                        {old_app, new_app},
                        "old app retained",
                    )
                elif resource == "listener":
                    self._listener_states.return_value = (
                        {2: 1, 3: 0},
                        "old listener retained",
                    )
                else:
                    self.vapi.cli.return_value = "path /tmp/large.txt retained"
                with self.assertRaisesRegex(AssertionError, "retained"):
                    method(self, old_app)
        clock.sleep.assert_not_called()

    def test_delete_reuse_requires_old_listener_before_next_request(self):
        method = helper("test_http_static_listener_delete_reuse")
        for retired in ({4: 1}, {}):
            with self.subTest(retired=retired):
                case_type = type(
                    "RetirementFixture", (unittest.TestCase,), {method.__name__: method}
                )
                case = case_type(method.__name__)
                case.vapi = types.SimpleNamespace(cli=unittest.mock.Mock())
                case._listener_states = unittest.mock.Mock(
                    side_effect=[
                        ({4: 0}, "active"),
                        (retired, "after deletion"),
                        ({4: 1, 5: 0}, "after readd"),
                    ]
                )
                case._client = unittest.mock.Mock(return_value=object())
                case._response = unittest.mock.Mock(
                    side_effect=[
                        {
                            "status": 200,
                            "body": "original",
                            "server": "http_static_server_0",
                        },
                        {"body": "original", "server": "http_static_server_0"},
                        {"body": "original", "server": "http_static_server_0"},
                        {"status": 404, "server": "http_static_server_0"},
                    ]
                )
                case._hss_apps = unittest.mock.Mock(
                    return_value=({("1", "http_static_server_0")}, "app")
                )
                case._refused = unittest.mock.Mock()
                case._stop_client = unittest.mock.Mock()
                case._wait_listener_gone = unittest.mock.Mock()
                case._wait_released = unittest.mock.Mock()
                result = unittest.TestResult()
                case.run(result)
                self.assertEqual(result.errors, [])
                self.assertEqual(len(result.failures), 0 if retired else 1)
                self.assertEqual(case._response.call_count, 4 if retired else 1)
                if retired:
                    case._wait_listener_gone.assert_called_once_with(4)
                else:
                    self.assertIn("after deletion", result.failures[0][1])
                    case._refused.assert_not_called()

    def test_cached_listener_distinguishes_disk_replacement(self):
        import os
        import tempfile

        method = helper("test_http_static_cached_listener_retirement")
        method.__globals__.update(os=os, tempfile=tempfile)
        case_type = type(
            "CacheFixture", (unittest.TestCase,), {method.__name__: method}
        )
        case = case_type(method.__name__)
        files = []

        def cli(command):
            if "listener add" in command:
                files.append(
                    Path(command.split("www-root ")[1].split()[0]) / "file.txt"
                )
                expected = (
                    "original listener" if len(files) == 1 else "replacement listener"
                )
                self.assertEqual(files[-1].read_text(), expected)

        case.vapi = types.SimpleNamespace(cli=unittest.mock.Mock(side_effect=cli))
        case._client = unittest.mock.Mock(return_value=object())
        case._response = unittest.mock.Mock(
            side_effect=[
                {"body": "original listener"},
                {"body": "original listener", "cache": "max-age=123"},
                {"body": "replacement listener", "cache": "max-age=456"},
            ]
        )
        case._listener_states = unittest.mock.Mock(
            side_effect=[({4: 0}, "active"), ({4: 1}, "retired")]
        )
        case._stop_client = unittest.mock.Mock()
        case._wait_released = unittest.mock.Mock()
        result = unittest.TestResult()
        case.run(result)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.failures, [])
        self.assertEqual(len(files), 2)

    def test_destroy_observation_precedes_new_client_and_old_drain(self):
        import os
        import tempfile

        method = helper("test_http_static_destroy_ownership")
        method.__globals__.update(os=os, tempfile=tempfile)
        case_type = type(
            "DestroyFixture", (unittest.TestCase,), {method.__name__: method}
        )
        case = case_type(method.__name__)
        calls = unittest.mock.Mock()
        calls.cli.return_value = ""
        calls.client.side_effect = range(6)
        calls.response.side_effect = [
            response
            for _ in range(3)
            for response in (
                {"status": 200},
                {"status": 200},
                {"closed": "IncompleteRead"},
            )
        ]
        case.vapi = types.SimpleNamespace(cli=calls.cli)
        case._client = calls.client
        case._response = calls.response
        case._hss_apps = unittest.mock.Mock(
            side_effect=[
                ({(str(index), f"http_static_server_{index}")}, "old app")
                for index in range(3)
            ]
        )
        case._wait_destroyed = calls.observe
        case._assert_closed = helper("_assert_closed").__get__(case)
        case._stop_client = calls.stop
        case._wait_released = unittest.mock.Mock()
        result = unittest.TestResult()
        case.run(result)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.failures, [])
        ordered = calls.mock_calls
        for iteration in range(3):
            observed = ordered.index(
                unittest.mock.call.observe(
                    (str(iteration), f"http_static_server_{iteration}")
                )
            )
            new_client = ordered.index(unittest.mock.call.response(2 * iteration + 1))
            drained = ordered.index(unittest.mock.call.response(2 * iteration, "drain"))
            stopped = ordered.index(unittest.mock.call.stop(2 * iteration))
            self.assertLess(observed, new_client)
            self.assertLess(observed, drained)
            self.assertLess(observed, stopped)


class TestDestroyDispatchContract(unittest.TestCase):
    def test_early_close_requires_owned_empty_response_and_releases_once(self):
        source = (ROOT / "src/plugins/http_static/static_server.c").read_text()
        callback = source.split("\nhss_ts_transport_closed (session_t *s)", 1)[1].split(
            "\nstatic void", 1
        )[0]
        for guard in (
            "hs->vpp_session_handle != session_handle (s)",
            "app_worker_get_if_valid (s->app_wrk_index)",
            "app_wrk->app_index != hs->app_index",
            "SESSION_F_APP_CLOSED",
            "hs->data_len",
            "!s->tx_fifo",
            "svm_fifo_max_dequeue (s->tx_fifo)",
        ):
            self.assertLess(callback.index(guard), callback.index("s->opaque = ~0;"))
        self.assertLess(
            callback.index("s->opaque = ~0;"), callback.index("hss_session_cleanup")
        )
        self.assertIn(
            ".session_transport_closed_callback = hss_ts_transport_closed", source
        )

        def early(session, owner, releases):
            if session["opaque"] is None or owner["handle"] != session["handle"]:
                return
            if (
                session["app"] != owner["app"]
                or not session["app_closed"]
                or owner["data_len"]
                or session["fifo"] is None
                or session["fifo"]
            ):
                return
            session["opaque"] = None
            releases.append(owner["handle"])

        owner = {"handle": 7, "app": 3, "data_len": 0}
        baseline = {"opaque": 2, "handle": 7, "app": 3, "app_closed": True, "fifo": []}
        for changed in (
            {"handle": 8},
            {"app": 4},
            {"app_closed": False},
            {"fifo": None},
            {"fifo": ["pending header pointer"]},
        ):
            session, releases = dict(baseline, **changed), []
            early(session, owner, releases)
            self.assertEqual(releases, [])
            self.assertEqual(session["opaque"], 2)
        session, releases = dict(baseline), []
        early(session, dict(owner, data_len=8 << 20), releases)
        self.assertEqual(releases, [])
        self.assertEqual(session["opaque"], 2)
        early(session, owner, releases)
        early(session, owner, releases)
        if session["opaque"] is not None:
            releases.append(owner["handle"])
        self.assertEqual(releases, [7])

    def test_source_uses_persistent_batches_and_cleanup_before_ack(self):
        source = (ROOT / "src/plugins/http_static/static_server.c").read_text()
        destroy = source.split("\nhss_destroy (vlib_main_t *vm)", 1)[1].split(
            "\nstatic clib_error_t *", 1
        )[0]
        cleanup = source.split("\nhss_destroy_sessions (hss_destroy_ctx_t *ctx)", 1)[
            1
        ].split("\nstatic uword", 1)[0]
        consumer = source.split("\nhss_destroy_node_fn (", 1)[1].split(
            "\nVLIB_REGISTER_NODE", 1
        )[0]
        self.assertIn("ASSERT (vlib_thread_is_main_w_barrier ());", destroy)
        self.assertIn("vec_add1 (hss_pending_destroys[i], ctx);", destroy)
        self.assertIn("vlib_node_set_interrupt_pending", destroy)
        self.assertNotIn("session_send_rpc", destroy)
        self.assertNotIn("while (", destroy)
        self.assertIn("if (!hss_destroy_sessions (*ctx))", consumer)
        self.assertIn("pending[remaining++] = *ctx;", consumer)
        self.assertIn("vec_set_len (pending, remaining);", consumer)
        self.assertIn("vlib_node_set_interrupt_pending", consumer)
        self.assertIn("for (i = 0;", destroy)
        self.assertLess(
            cleanup.index("app_wrk_flush_wrk_events"),
            cleanup.index("hss_session_cleanup"),
        )
        self.assertLess(
            cleanup.index("if (pending)"), cleanup.index("pool_foreach (hs")
        )
        self.assertGreater(
            cleanup.index("clib_atomic_sub_fetch"), cleanup.index("hss_session_cleanup")
        )
        self.assertIn("vlib_rpc_call_main_thread (hss_detach_rpc", cleanup)

    def test_model_batches_survive_session_mq_failures(self):
        # This model checks the protocol, not execution of the C implementation.
        for workers in (0, 1, 3):
            for mq_failure in ("locked", "full"):
                with self.subTest(workers=workers, mq_failure=mq_failure):
                    pending = [[] for _ in range(workers + 1)]
                    queues = {}
                    remaining = {}
                    cleaned = set()
                    detached = []
                    interrupts = set()
                    session_mq = unittest.mock.Mock(
                        return_value=-1 if mq_failure == "locked" else -2
                    )
                    self.assertLess(session_mq(), 0)
                    session_mq.reset_mock()

                    def ack(generation, thread):
                        self.assertNotIn((generation, thread), cleaned)
                        cleaned.add((generation, thread))
                        remaining[generation] -= 1
                        if remaining[generation] == 0:
                            detached.append(generation)

                    def consume(thread):
                        retained = []
                        for generation in pending[thread]:
                            key = (generation, thread)
                            queues[key] = max(0, queues[key] - 128)
                            if queues[key]:
                                retained.append(generation)
                            else:
                                ack(generation, thread)
                        pending[thread] = retained

                    for generation in range(3):
                        remaining[generation] = workers + 1
                        for thread, queue in enumerate(pending):
                            queue.append(generation)
                            queues[generation, thread] = 129
                            interrupts.add(thread)
                    session_mq.assert_not_called()
                    self.assertEqual(detached, [])
                    self.assertEqual(interrupts, set(range(workers + 1)))
                    for thread in sorted(interrupts):
                        consume(thread)
                        self.assertTrue(pending[thread])
                        self.assertFalse(any(owner == thread for _, owner in cleaned))
                        consume(thread)
                        self.assertEqual(pending[thread], [])
                        acknowledged = len(cleaned)
                        consume(thread)
                        self.assertEqual(len(cleaned), acknowledged)
                    self.assertEqual(detached, [0, 1, 2])
                    self.assertEqual(len(cleaned), 3 * (workers + 1))
                    self.assertTrue(all(value == 0 for value in remaining.values()))


class TestPendingAcceptWitness(unittest.TestCase):
    def test_actual_method_rejects_failed_or_incomplete_selftest(self):
        method = helper("test_http_static_pending_accept_identity")
        method.__globals__["config"] = types.SimpleNamespace(vpp_tag="vpp_debug")
        success = (
            "synthetic queued accept: 129 events, batches 128+1, "
            "130 old owners released"
        )
        for retval, reply in ((0, success), (-1, "snapshot failed"), (0, "")):
            with self.subTest(retval=retval, reply=reply):
                case_type = type(
                    "PendingAcceptFixture",
                    (unittest.TestCase,),
                    {method.__name__: method},
                )
                case = case_type(method.__name__)
                case.vapi = types.SimpleNamespace(
                    cli_return_response=unittest.mock.Mock(
                        return_value=types.SimpleNamespace(retval=retval, reply=reply)
                    )
                )
                result = unittest.TestResult()
                case.run(result)
                self.assertEqual(result.errors, [])
                self.assertEqual(result.skipped, [])
                self.assertEqual(len(result.failures), int(retval != 0 or not reply))
                case.vapi.cli_return_response.assert_called_once_with(
                    "test http static pending accept"
                )

    def test_source_captures_before_unlisten_and_transfers_once(self):
        source = (ROOT / "src/plugins/http_static/static_server.c").read_text()
        deletion = source.split("\nhss_listener_del (hss_listener_t *l_cfg)", 1)[
            1
        ].split("\nint\n", 1)[0]
        callback = source.split("\nhss_ts_accept_callback (session_t *ts)", 1)[1].split(
            "\nstatic void", 1
        )[0]
        self.assertLess(
            deletion.index("hss_preserve_pending_accepts"),
            deletion.index("vnet_unlisten (&args)"),
        )
        self.assertIn("if (pending)", callback)
        self.assertIn("vec_del1 (hss_pending_accepts", callback)
        self.assertIn("else\n    clib_atomic_add_fetch", callback)
        self.assertNotIn("listener_handle", callback)
        witness = source.split("\nhss_test_pending_accept_command_fn (", 1)[1].split(
            "\nVLIB_CLI_COMMAND", 1
        )[0]
        self.assertLess(
            witness.index("hss_listener_del (&cfg)"),
            witness.index("hss_preserve_pending_accepts"),
        )
        self.assertIn("if (error)\n    hss_test_accept_recover", witness)
        self.assertLess(
            witness.index("pending accept cleanup queue retained"),
            witness.index("hss_test_accept_free (handles[i])"),
        )
        self.assertNotIn("hss_ts_accept_callback", witness)
        self.assertNotIn("clib_fifo_advance_head", witness)

    def test_initialization_queue_is_checked_before_real_flush(self):
        source = (ROOT / "src/plugins/http_static/static_server.c").read_text()
        flush = source.split("\nhss_test_flush_init_events (", 1)[1].split(
            "\nstatic void", 1
        )[0]
        for guard in (
            "SESSION_CTRL_EVT_APP_ADD_SEGMENT",
            "sm != expected",
            "sm->app_wrk_index != app_wrk->wrk_index",
            "pool_is_free_index (sm->segments, segment_index)",
            "segment_manager_make_segment_handle",
        ):
            self.assertLess(flush.index(guard), flush.index("app_wrk_flush_wrk_events"))
        self.assertIn("clib_fifo_elts (app_wrk->wrk_evts[0]) >= before", flush)
        self.assertNotIn("clib_fifo_advance_head", flush)
        self.assertNotIn("clib_fifo_reset", flush)
        allocation = source.split("\nhss_test_accept_alloc (", 1)[1].split(
            "\nstatic clib_error_t", 1
        )[0]
        self.assertNotIn("app_worker_accept_notify", allocation)

        def drain(queue, flush_batch):
            for kind, owner in queue:
                if kind != "APP_ADD_SEGMENT" or owner != "listener-worker":
                    raise ValueError("unexpected initialization event")
            for _ in range(len(queue)):
                if not queue:
                    return
                before = len(queue)
                flush_batch(queue)
                if len(queue) >= before:
                    raise ValueError("no progress")
            if queue:
                raise ValueError("retained queue")

        flush_batch = unittest.mock.Mock(
            side_effect=lambda queue: queue.__delitem__(slice(128))
        )
        queue = [("APP_ADD_SEGMENT", "listener-worker")] * 129
        drain(queue, flush_batch)
        self.assertEqual(queue, [])
        self.assertEqual(flush_batch.call_count, 2)
        for unexpected in (
            ("ACCEPTED", "listener-worker"),
            ("APP_ADD_SEGMENT", "other"),
        ):
            flush_batch.reset_mock()
            queue = [("APP_ADD_SEGMENT", "listener-worker"), unexpected]
            with self.assertRaises(ValueError):
                drain(queue, flush_batch)
            flush_batch.assert_not_called()
            self.assertEqual(len(queue), 2)
        with self.assertRaisesRegex(ValueError, "no progress"):
            drain([("APP_ADD_SEGMENT", "listener-worker")], lambda queue: None)

    def test_model_129_callbacks_survive_listener_handle_reuse(self):
        # This model verifies the ownership protocol, not C execution or HTTP scheduling.
        for preserve in (False, True):
            with self.subTest(preserve=preserve):
                active = {7: 2}
                references = {2: 1}
                queue = list(range(129))
                pending = {}
                if preserve:
                    for session in queue:
                        pending[session] = active[7]
                        references[2] += 1
                references[2] -= 1
                active[7] = 3
                owners = []
                for size in (128, 1):
                    batch, queue = queue[:size], queue[size:]
                    owners.extend(pending.pop(session, active[7]) for session in batch)
                self.assertEqual(queue, [])
                self.assertEqual(pending, {})
                if preserve:
                    self.assertEqual(owners, [2] * 129)
                    self.assertEqual(references[2], 129)
                    for listener in owners:
                        references[listener] -= 1
                    self.assertEqual(references[2], 0)
                else:
                    with self.assertRaises(AssertionError):
                        self.assertEqual(owners, [2] * 129)


class TestCacheWitnesses(unittest.TestCase):
    def test_read_error_method_requires_both_paths_and_success_evidence(self):
        import os
        import tempfile

        method = helper("test_http_static_cache_read_error")
        method.__globals__.update(
            config=types.SimpleNamespace(vpp_tag="vpp_debug"), os=os, tempfile=tempfile
        )
        success = "cache read error: lock released, valid owner reused and cleared"
        for broken in (None, "missing.txt", "/child", "missing evidence"):
            with self.subTest(broken=broken):
                case_type = type(
                    "CacheReadErrorFixture",
                    (unittest.TestCase,),
                    {method.__name__: method},
                )
                case = case_type(method.__name__)
                seen = []

                def cli(command):
                    prefix = "test http static cache read-error "
                    self.assertTrue(command.startswith(prefix))
                    invalid, valid = command[len(prefix) :].split()
                    self.assertEqual(Path(valid).read_text(), "cache remains usable")
                    self.assertFalse(Path(invalid).exists())
                    seen.append(invalid)
                    return types.SimpleNamespace(
                        retval=-1 if broken and invalid.endswith(broken) else 0,
                        reply="" if broken == "missing evidence" else success,
                    )

                case.vapi = types.SimpleNamespace(cli_return_response=cli)
                result = unittest.TestResult()
                case.run(result)
                self.assertEqual(result.errors, [])
                self.assertEqual(result.skipped, [])
                self.assertEqual(
                    len(result.failures),
                    2 if broken == "missing evidence" else int(broken is not None),
                )
                self.assertEqual(len(seen), 2)
                self.assertTrue(seen[0].endswith("/missing.txt"))
                self.assertTrue(seen[1].endswith("/valid.txt/child"))

    def test_owner_method_requires_both_real_c_modes(self):
        import os
        import tempfile

        method = helper("test_http_static_cache_owners")
        method.__globals__.update(
            config=types.SimpleNamespace(vpp_tag="vpp_debug"), os=os, tempfile=tempfile
        )
        for broken in (None, "pressure", "clear", "missing"):
            with self.subTest(broken=broken):
                case_type = type(
                    "CacheOwnerFixture", (unittest.TestCase,), {method.__name__: method}
                )
                case = case_type(method.__name__)
                seen = []

                def cli(command):
                    mode = command.split()[5]
                    seen.append(mode)
                    message = (
                        "cache pressure: zero/finite owners passed"
                        if mode == "pressure"
                        else "cache clear: 121 states passed"
                    )
                    return types.SimpleNamespace(
                        retval=-1 if broken == mode else 0,
                        reply="" if broken == "missing" else message,
                    )

                case.vapi = types.SimpleNamespace(cli_return_response=cli)
                result = unittest.TestResult()
                case.run(result)
                self.assertEqual(result.errors, [])
                self.assertEqual(result.skipped, [])
                self.assertEqual(
                    len(result.failures),
                    2 if broken == "missing" else int(broken is not None),
                )
                self.assertEqual(seen, ["pressure", "clear"])

    def test_relocation_method_requires_real_moves_and_registry_baseline(self):
        import os
        import tempfile

        method = helper("test_http_static_cache_relocation")
        method.__globals__.update(
            config=types.SimpleNamespace(vpp_tag="vpp_debug"),
            os=os,
            tempfile=tempfile,
            re=re,
        )
        success = (
            "listener pool moved 1000 -> 2000\nlistener pool moved 2000 -> 3000\n"
            "cache registry: 2 explicit pool moves, unique stable hashes"
        )
        for retval, reply in ((0, success), (-1, success), (0, "")):
            with self.subTest(retval=retval, reply=reply):
                case_type = type(
                    "RelocationFixture", (unittest.TestCase,), {method.__name__: method}
                )
                case = case_type(method.__name__)
                hashes = iter((0, 2, 2, 0))

                def cli(command):
                    if command == "show bihash":
                        return "Hash table 'http cache'\n" * next(hashes)
                    if command.startswith("show http static server cache"):
                        return "listener 2 has no file cache"
                    if command.startswith("clear http static cache"):
                        return "Cache cleared..."
                    return ""

                case.vapi = types.SimpleNamespace(
                    cli=cli,
                    cli_return_response=lambda command: types.SimpleNamespace(
                        retval=retval, reply=reply
                    ),
                )
                case._client = unittest.mock.Mock(return_value=object())
                case._response = unittest.mock.Mock(
                    return_value={"body": "stable cache"}
                )
                case._listener_states = unittest.mock.Mock(
                    side_effect=[
                        ({0: 1, 1: 0, 2: 0, 3: 0}, "before spare delete"),
                        ({0: 1, 1: 0, 2: 0}, "listener 2, uri 10.10.1.2:8090,"),
                    ]
                )
                case._wait_listener_gone = unittest.mock.Mock()
                case._stop_client = unittest.mock.Mock()
                case._wait_released = unittest.mock.Mock()
                result = unittest.TestResult()
                case.run(result)
                self.assertEqual(result.errors, [])
                self.assertEqual(result.skipped, [])
                self.assertEqual(len(result.failures), int(retval != 0 or not reply))

    def test_straight_prev_clear_model_and_distinct_restorations(self):
        from itertools import product

        failures = {"old": 0, "only_remove_next": 0, "fixed": 0}
        states = 0
        for count in range(5):
            for refs in product((-1, 0, 1), repeat=count):
                states += 1
                expected = {index for index, ref in enumerate(refs) if ref}
                for version in failures:
                    live = list(range(count))
                    index = live[0] if live else None
                    busy = 0
                    visits = 0
                    while index is not None:
                        visits += 1
                        self.assertLessEqual(visits, 2 * count + 1)
                        position = live.index(index)
                        previous = (
                            live[position + 1] if position + 1 < len(live) else None
                        )
                        if refs[index]:
                            busy += 1
                            if version == "old":
                                index = live[position - 1] if position else None
                            else:
                                index = previous
                        else:
                            live.remove(index)
                            if version == "fixed":
                                index = previous
                            else:
                                index = live[0] if live else None
                    failures[version] += busy != len(expected) or set(live) != expected
        self.assertEqual(states, 121)
        self.assertEqual(failures["fixed"], 0)
        self.assertGreater(failures["old"], 0)
        self.assertGreater(failures["only_remove_next"], 0)


if __name__ == "__main__":
    unittest.main()
