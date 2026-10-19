# SPDX-License-Identifier: Apache-2.0
"""Compiler-free HSS witness fixtures; these do not run VPP or its harness."""

import ast
import contextlib
import errno
import http.client
import io
import json
from pathlib import Path
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
    namespace = {"subprocess": subprocess, "sys": sys}
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
        response = types.SimpleNamespace(status=200, length=1024)
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


class TestDestroyDispatchContract(unittest.TestCase):
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
        self.assertIn("hss_destroy_sessions (*ctx);", consumer)
        self.assertGreater(
            consumer.index("vec_reset_length"), consumer.index("hss_destroy_sessions")
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
                    pending = [[] for _ in range(workers)]
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
                        for generation in pending[thread - 1]:
                            ack(generation, thread)
                        pending[thread - 1].clear()

                    for generation in range(3):
                        remaining[generation] = workers + 1
                        for thread, queue in enumerate(pending, 1):
                            queue.append(generation)
                            interrupts.add(thread)
                        ack(generation, 0)
                    session_mq.assert_not_called()
                    self.assertEqual(detached, [] if workers else [0, 1, 2])
                    self.assertEqual(interrupts, set(range(1, workers + 1)))
                    for thread in sorted(interrupts):
                        consume(thread)
                        acknowledged = len(cleaned)
                        consume(thread)
                        self.assertEqual(len(cleaned), acknowledged)
                    self.assertEqual(detached, [0, 1, 2])
                    self.assertEqual(len(cleaned), 3 * (workers + 1))
                    self.assertTrue(all(value == 0 for value in remaining.values()))


if __name__ == "__main__":
    unittest.main()
