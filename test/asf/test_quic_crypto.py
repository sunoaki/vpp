#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""QUIC outbound credential failure must release context, hostname and crypto state."""

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
import unittest
import uuid

from asfframework import VppAsfTestCase, VppTestRunner
from config import config
from vpp_ip_route import VppIpRoute, VppIpTable, VppRoutePath

DIAGNOSTIC = "unable to initialize certificate/key pair"
ATTEMPTS = 100
# Cleanup never relies on a single long wait. Closing stdin is the graceful
# path; a helper stuck inside a C call never sees the EOF, so it gets
# EOF_TIMEOUT_S, then each escalation signal in turn with its own bound. The
# steps add up to the single wait this replaced, so a healthy helper is never
# cut short and a hung one is reported instead of silently killed.
EOF_TIMEOUT_S = 20
ESCALATION_SIGNALS = ((signal.SIGTERM, 5), (signal.SIGKILL, 5))
# Each peer gets its own loopback, FIB table and app namespace. Both peers on
# one loopback in the default table share an address, so the connecting peer
# sends from the listener's own receive address and ip4-local drops every
# packet as a spoofed local-address packet. loop0 stays in the default table
# and loop1 gets table 1, the layout the TCP and UDP session suites use.
SERVER_NAMESPACE, SERVER_TABLE = "quic-crypto-server", 0
CLIENT_NAMESPACE, CLIENT_TABLE = "quic-crypto-client", 1
# A traceback record keeps at most 12 frames (clib_mem_trace_t.callers in
# src/vppinfra/mem.h) and save_memory_trace writes only those. srv_hostname is
# built by format (0, "%U", format_ip46_address, ...) in quic.c, and that chain
# runs through format, va_format and do_percent before the vector allocator.
# It is longer than 12 frames, so quic_connect_connection() is never part of a
# recorded traceback and an assertion that looks for that frame cannot pass.
# The format frames of that chain are the ones the window keeps, so they are
# what attribution keys on; the tests guard the case where even they are absent
# instead of reporting an empty selection as a product regression.
FORMAT_FRAME = re.compile(
    r"\b(?:format|va_format|format_ip4_address|format_ip6_address"
    r"|format_ip46_address)\b"
)
# b332ab4cd returns from quic_connect_connection() without freeing the context
# and its hostname; 40b52275d adds exactly those two frees.
LEAKS = {"fixed": False, "original": True}


def signame(returncode):
    """Name the signal behind a negative subprocess return code."""
    if returncode is not None and returncode < 0:
        try:
            return signal.Signals(-returncode).name
        except ValueError:
            return f"signal {-returncode}"
    return f"exit code {returncode}"


class VclProcess:
    """One quic_crypto_client.py subprocess speaking JSON lines."""

    def __init__(self, test, name, address, namespace):
        self.test = test
        self.name = name
        self.stopped = False
        self.process = None
        self.selector = None
        self.stderr = None
        self.transcript = None
        self.stderr_path = test.evidence / f"{name}-stderr.txt"
        test.addCleanup(self.stop)
        libraries = list(Path(config.vpp_install_dir).rglob("libvppcom.so"))
        test.assertEqual(len(libraries), 1, libraries)
        conf = test.evidence / f"{name}-vcl.conf"
        # The listener is non-blocking in the helper, so accept cannot block
        # inside vppcom_session_accept; ACCEPT_POLL_LIMIT_S bounds the wait.
        # session-timeout 5 bounds the listener's listen request in
        # vppcom_session_listen and the connect wait is bounded by
        # CONNECT_POLL_LIMIT_S.
        conf.write_text("vcl { app-scope-global app-timeout 60 session-timeout 5 }\n")
        # The helper attaches through the namespace socket, so its sessions
        # take that namespace's FIB table instead of the default one.
        env = dict(os.environ, VCL_CONFIG=str(conf))
        env["VCL_VPP_SAPI_SOCKET"] = f"{test.tempdir}/app_ns_sockets/{namespace}"
        self.stderr = self.stderr_path.open("w")
        self.process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).with_name("quic_crypto_client.py")),
                str(libraries[0]),
                address,
                "4433",
            ],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            text=True,
        )
        self.sequence = 0
        self.transcript = (test.evidence / f"{name}-protocol.jsonl").open("w")
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)

    def request(self, operation, timeout=120, **params):
        self.sequence += 1
        request = dict(id=self.sequence, operation=operation, **params)
        self.transcript.write(json.dumps({"request": request}) + "\n")
        self.transcript.flush()
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        if not self.selector.select(timeout):
            raise AssertionError(
                f"{self.name} helper timed out after {timeout}s: {request}"
            )
        line = self.process.stdout.readline()
        self.transcript.write(json.dumps({"reply": line}) + "\n")
        self.transcript.flush()
        if not line:
            self.stderr.flush()
            try:
                code = self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                code = "still running"
            tail = "\n".join(self.stderr_path.read_text().splitlines()[-20:])
            raise AssertionError(
                f"{self.name} helper exited with code {code}: "
                f"{request}\nstderr tail ({self.stderr_path}):\n{tail}"
            )
        reply = json.loads(line)
        self.test.assertEqual(reply["id"], self.sequence)
        # The helper answers a failed operation with "error" and then ends its
        # loop, so the failure surfaces here with its own text and cleanup still
        # sees a helper that exited by itself with status 0.
        if "error" in reply:
            raise AssertionError(
                f"{self.name} helper failed {request}: {reply['error']}"
            )
        return reply["result"]

    def stop(self):
        """End the helper deterministically and fail if it did not exit itself.

        Closing stdin is the graceful path: the request loop ends and the
        helper's finally block runs client.destroy(). A helper blocked inside a
        C call never sees that EOF, so it is escalated through SIGTERM and
        SIGKILL with a bound on each step. The test still fails when a signal
        was needed; what changes is that cleanup reports which one and finishes
        in seconds instead of waiting out one long timeout.
        """
        if self.stopped:
            return
        self.stopped = True
        try:
            if self.process is None:
                return
            if self.process.poll() is None:
                try:
                    self.process.stdin.close()
                except OSError:
                    # The helper exited between poll() and close(); the exit
                    # status is checked below.
                    pass
                if not self.exited(EOF_TIMEOUT_S):
                    for signal_number, timeout in ESCALATION_SIGNALS:
                        self.process.send_signal(signal_number)
                        if self.exited(timeout):
                            self.test.fail(
                                f"{self.name} helper needed "
                                f"{signame(-signal_number)} during cleanup, so "
                                f"it never left the operation it was in; see "
                                f"{self.stderr_path}"
                            )
                    self.test.fail(
                        f"{self.name} helper survived "
                        f"{[signame(-number) for number, _ in ESCALATION_SIGNALS]} "
                        f"during cleanup; see {self.stderr_path}"
                    )
            self.test.assertEqual(
                self.process.returncode,
                0,
                f"{self.name} helper failed: {signame(self.process.returncode)}, "
                f"see {self.stderr_path}",
            )
        finally:
            for handle in (self.selector, self.stderr, self.transcript):
                if handle is not None:
                    handle.close()

    def exited(self, timeout):
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return False
        return True


@unittest.skipIf("quic" in config.excluded_plugins, "QUIC plugin excluded")
@unittest.skipIf("quic_quicly" in config.excluded_plugins, "quicly plugin excluded")
class QUICCredentialFailure(VppAsfTestCase):
    """QUIC outbound credential failure rollback (no workers)."""

    vpp_worker_count = 0
    helper_count = 1
    timeout = 600
    vapi_response_timeout = 10
    extra_vpp_config = ["session { enable poll-main use-app-socket-api }"]

    @classmethod
    def setUpClass(cls):
        cls.extra_vpp_plugin_config = list(cls.extra_vpp_plugin_config) + [
            "plugin quic_plugin.so { enable }",
            "plugin quic_quicly_plugin.so { enable }",
        ]
        super().setUpClass()

    def setUp(self):
        super().setUp()
        root = Path(os.environ.get("QUIC_CRYPTO_ARTIFACTS", self.tempdir))
        self.evidence = root / f"workers-{self.vpp_worker_count}"
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.cli_log = (self.evidence / "cli.jsonl").open("w")
        self.addCleanup(self.cli_log.close)
        self.create_loopback_interfaces(2)
        self.server_loop, self.client_loop = self.lo_interfaces
        self.tables = {}
        self.routes = []
        self.configured_loops = []
        self.namespaces = []
        # The registry cannot tear this down: loopback interfaces are not
        # registered objects, and a table cannot be removed while an address,
        # a route or a namespace still refers to it.
        self.addCleanup(self.teardown_topology)
        for loop, table in (
            (self.server_loop, SERVER_TABLE),
            (self.client_loop, CLIENT_TABLE),
        ):
            loop.admin_up()
            # Recorded before the rest of the per-loop configuration so a
            # failure inside it still gets admin_down, the table reset and the
            # address removal on the way out.
            self.configured_loops.append((loop, table))
            # Table 0 always exists; only the extra table is created here.
            if table:
                self.tables[table] = VppIpTable(
                    self, table, register=False
                ).add_vpp_config()
            loop.set_table_ip4(table)
            loop.config_ip4()
        # Each peer speaks from its own table, so each table needs a route to
        # the other peer's address. Without one the source lookup finds no
        # path and the connection has nowhere to go.
        self.routes.append(
            VppIpRoute(
                self,
                self.client_loop.local_ip4,
                32,
                [VppRoutePath("0.0.0.0", 0xFFFFFFFF, nh_table_id=CLIENT_TABLE)],
                table_id=SERVER_TABLE,
                register=False,
            ).add_vpp_config()
        )
        self.routes.append(
            VppIpRoute(
                self,
                self.server_loop.local_ip4,
                32,
                [VppRoutePath("0.0.0.0", 0xFFFFFFFF, nh_table_id=SERVER_TABLE)],
                table_id=CLIENT_TABLE,
                register=False,
            ).add_vpp_config()
        )
        # The namespace binds one loopback, and transport_alloc_local_endpoint()
        # derives the source address from the namespace's sw_if_index, so each
        # peer sends from its own loopback.
        for namespace, loop in (
            (SERVER_NAMESPACE, self.server_loop),
            (CLIENT_NAMESPACE, self.client_loop),
        ):
            self.vapi.app_namespace_add_del_v4(
                namespace_id=namespace, sw_if_index=loop.sw_if_index
            )
            self.namespaces.append((namespace, loop))
        self.run_cli("quic set crypto api engine-lib")
        self.run_cli("show threads")
        self.run_cli("show version verbose")

    def teardown_topology(self):
        for namespace, loop in reversed(self.namespaces):
            self.vapi.app_namespace_add_del_v4(
                is_add=0, namespace_id=namespace, sw_if_index=loop.sw_if_index
            )
        for route in reversed(self.routes):
            route.remove_vpp_config()
        for loop, table in reversed(self.configured_loops):
            loop.unconfig_ip4()
            loop.set_table_ip4(0)
            table_object = self.tables.pop(table, None)
            if table_object is not None:
                table_object.remove_vpp_config()
            loop.admin_down()

    def run_cli(self, command):
        reply = self.vapi.cli(command)
        self.cli_log.write(json.dumps({"command": command, "reply": reply}) + "\n")
        self.cli_log.flush()
        self.assertFalse(re.search(r"unknown input|not initialized|not enabled", reply))
        self.assertIsNone(self.vpp.poll(), "VPP exited")
        return reply.strip()

    def snapshot(self):
        quic = self.run_cli("show quic")
        self.assertIn("quic engine: quicly", quic.lower())
        pools = re.findall(r"Thread (\d+): ctx pool (\d+)/(\d+)", quic)
        self.assertEqual(len(pools), self.vpp_worker_count + 1)
        return {
            "used": {thread: int(used) for thread, used, capacity in pools},
            "crypto": self.run_cli("show quic crypto context"),
            "sessions": self.run_cli("show session"),
            "certificates": self.run_cli("show app certificate"),
        }

    def wait_snapshot(self, expected, timeout=15):
        deadline = time.monotonic() + timeout
        while True:
            actual = self.snapshot()
            if actual == expected:
                return actual
            if time.monotonic() >= deadline:
                self.assertEqual(actual, expected, "cleanup did not restore baseline")
            time.sleep(0.05)

    def trace(self, label):
        filename = f"quic-{uuid.uuid4().hex}.json"
        path = Path("/tmp") / filename
        self.assertFalse(path.exists())
        started = time.time_ns()
        reply = self.run_cli(f"save memory-trace {filename}")
        self.assertIn(f"Saving trace to '{path}'", reply)
        self.assertTrue(path.is_file(), "trace command produced no readable file")
        stat = path.stat()
        self.assertGreaterEqual(stat.st_mtime_ns, started - 1_000_000_000)
        raw = path.read_bytes()
        (self.evidence / f"{label}.json").write_bytes(raw)
        records = json.loads(raw)
        self.assertIsInstance(records, list)
        self.assertTrue(records, "empty allocator trace is not coverage")
        for record in records:
            self.assertIsInstance(record["count"], int)
            self.assertGreater(record["count"], 0)
            self.assertGreater(record["bytes"], 0)
            self.assertTrue(record["traceback"])
        (self.evidence / f"{label}-metadata.json").write_text(
            json.dumps(
                {
                    "file": str(path),
                    "mtime_ns": stat.st_mtime_ns,
                    "started_ns": started,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        )
        path.unlink()
        return records

    @staticmethod
    def signature(record):
        """Name a record by the frames it was allocated through.

        The allocator hashes exactly the frames it kept, so the whole kept
        window names one bucket and a site keeps its bucket across traces. Two
        traces of the same run therefore join on this name.
        """
        return tuple(record["traceback"])

    @staticmethod
    def allocated_by_format(record):
        """True when a kept frame is part of a format() call.

        srv_hostname is built by format (0, "%U", format_ip46_address, ...) in
        quic.c. The quic_connect_connection() frame sits outside the 12 frames a
        record keeps, but the format, va_format and format_ip46_address frames
        inside that chain are among the ones kept, so this test is reachable
        where a quic_connect_connection() test is not.
        """
        return any(FORMAT_FRAME.search(frame) for frame in record["traceback"])

    def hostname_signatures(self, records, baseline=None):
        """Buckets a format call allocated into, optionally only those grown.

        Passing a baseline keeps only the buckets that gained both an
        allocation and bytes since it, which is how the connect's own
        allocation is told apart from a format bucket that was already live and
        only got bigger. Such a bucket can grow in bytes alone: an in-place
        realloc keeps the block offset, so clib_mem_heap_realloc_aligned()
        updates the byte count through clib_mem_trace_put()/clib_mem_trace_get()
        without changing the allocation count (src/vppinfra/mem_dlmalloc.c).
        Requiring both counters matches what the assertions below require.
        """
        seen = {}
        for record in records:
            if self.allocated_by_format(record):
                seen[self.signature(record)] = (record["count"], record["bytes"])
        if baseline is None:
            return set(seen)
        before = {
            self.signature(record): (record["count"], record["bytes"])
            for record in baseline
            if self.allocated_by_format(record)
        }
        return {
            name
            for name, current in seen.items()
            if current[0] > before.get(name, (0, 0))[0]
            and current[1] > before.get(name, (0, 0))[1]
        }

    def hostname_records(self, records, signatures):
        return [record for record in records if self.signature(record) in signatures]

    def hostname_totals(self, records, signatures):
        relevant = self.hostname_records(records, signatures)
        return [
            sum(record[field] for record in relevant) for field in ("count", "bytes")
        ]

    def probe(self, label, valid_cert, key, baseline, signatures=None):
        """Complete handshake, then prove the hostname allocation is released."""
        server = VclProcess(
            self, label + "-server", self.server_loop.local_ip4, SERVER_NAMESPACE
        )
        client = VclProcess(
            self, label + "-client", self.server_loop.local_ip4, CLIENT_NAMESPACE
        )
        for peer in (server, client):
            peer.request("attach", cert=str(valid_cert), key=str(key))
        server.request("listen")
        listening = self.snapshot()
        # Taken after the listener is up and before the client connects, so the
        # only hostname allocation the delta can contain is the connect's.
        before = self.trace(label + "-before")
        connected = client.request("connect", timeout=15)
        # The client dials through its own namespace, so its source address is
        # its own loopback's address and the reply comes back over the route
        # installed above. session_connect returns EINPROGRESS for a
        # non-blocking session by design; "connected" is the settled outcome
        # the helper observed. Assert it before the accept: the accept only has
        # something to accept when the client reached a handshake, so asserting
        # after it would report a silent accept timeout in place of the connect
        # error that actually caused it.
        self.assertEqual(connected["connect"], -115, connected)
        self.assertTrue(connected["connected"], connected)
        self.assertEqual(connected["errors"], [0], connected)
        self.assertLessEqual(connected["waited_s"], 5.0, connected)
        accepted = server.request("accept", timeout=15)
        self.assertGreaterEqual(accepted["accepted"], 0)
        self.assertLessEqual(accepted["waited_s"], 5.0, accepted)
        live = self.snapshot()
        thread = str(min(1, self.vpp_worker_count))
        delta = {
            index: live["used"][index] - used
            for index, used in listening["used"].items()
        }
        self.assertEqual(
            delta, {index: 2 if index == thread else 0 for index in listening["used"]}
        )
        self.run_cli("show session verbose 2")
        records = self.trace(label + "-live")
        # srv_hostname is built by
        # format (0, "%U", format_ip46_address, ...) in quic.c because VCL
        # supplies no hostname, so it lands in a bucket a format frame
        # allocated, and only format buckets that advanced since the listener
        # came up are selected. quic_connect_connection() is outside the 12
        # frames a record keeps (clib_mem_trace_t.callers in
        # src/vppinfra/mem.h), which is why the format frames are the key.
        # vec_terminate_c_string() then appends the NUL; format's growth leaves
        # spare capacity (50% on realloc, allocator rounding on first
        # allocation), so that append normally does not reallocate. If it did,
        # the vector would move to a bucket no format frame allocated, this set
        # would be empty and the guard below fails loudly. The same blind spot
        # in the credential loop is covered by the context-pool assertion in
        # snapshot(), not by the hostname counters; see that branch.
        live_signatures = self.hostname_signatures(records, before)
        # An empty result describes the measurement, not the rollback. Fail on
        # that fact alone so a missing attribution can never be reported later
        # as a count mismatch.
        self.assertTrue(
            live_signatures,
            f"no format-path bucket in {label}-live grew across the connect, so "
            f"the srv_hostname allocation cannot be identified. The format path "
            f'format (0, "%U", format_ip46_address, ...) must appear among the '
            f"12 kept frames of a record and its counters must advance; "
            f"before={len(before)} live={len(records)}",
        )
        if signatures is None:
            signatures = live_signatures
        else:
            # The second probe reuses the first probe's buckets, so they must
            # still appear live. Otherwise the reused set selects nothing and
            # the assertions below would hold over an empty selection.
            self.assertTrue(
                live_signatures & signatures,
                f"hostname buckets from the first probe are absent from "
                f"{label}-live, so the allocation site does not match across "
                f"probes; format buckets are "
                f"{sorted(list(item) for item in live_signatures)}",
            )
            # Keep only the reused buckets that grew in this probe. A reused
            # bucket whose counters dropped between the two traces would
            # otherwise subtract its negative delta from a growing bucket's
            # gain and hide the growth the assertions below look for. A bucket
            # that merely stayed the same adds the same counts to both sides,
            # so it is harmless but is dropped too.
            signatures = live_signatures & signatures
        before_totals = self.hostname_totals(before, signatures)
        live_totals = self.hostname_totals(records, signatures)
        # Every selected bucket grew in count and in bytes, so the totals must
        # advance on both. The property under test is the teardown equality
        # below: those buckets must return to where they started, which a
        # leaked srv_hostname breaks.
        self.assertGreater(live_totals[0], before_totals[0])
        self.assertGreater(live_totals[1], before_totals[1])
        (self.evidence / "hostname-callsite.json").write_text(
            json.dumps(
                {
                    "signatures": [list(item) for item in sorted(signatures)],
                    "thread": thread,
                    "source": "quic.c builds srv_hostname with "
                    'format (0, "%U", format_ip46_address, ...) when the '
                    "caller supplies no hostname, and VCL supplies none",
                    "before": before_totals,
                    "live": live_totals,
                    "tracebacks": [
                        record["traceback"]
                        for record in self.hostname_records(records, signatures)
                    ],
                    "connected": connected,
                    "accepted": accepted,
                },
                indent=2,
            )
        )
        for peer in (client, server):
            peer.request("close")
        for peer in (client, server):
            # Each peer attached its own certificate/key pair, and both pairs
            # live in the global app_crypto_main.cert_key_pair_store in
            # src/vnet/session/application_crypto.c. Only
            # vnet_app_del_cert_key_pair removes one; app_destroy reaches
            # app_crypto_ctx_free, which releases ca-trust stores, TLS profiles
            # and async requests but never the pair. detach deletes the pair
            # before destroying the application, so "show app certificate"
            # returns to the baseline wait_snapshot() compares against.
            peer.request("detach")
            peer.stop()
        deadline = time.monotonic() + 15
        while True:
            actual = self.snapshot()
            if all(
                actual[field] == baseline[field]
                for field in ("used", "sessions", "crypto")
            ):
                break
            self.assertLess(
                time.monotonic(), deadline, "handshake probe cleanup failed"
            )
            time.sleep(0.05)
        self.wait_snapshot(baseline)
        closed = self.trace(label + "-closed")
        closed_totals = self.hostname_totals(closed, signatures)
        # Every bucket the handshake grew must be released again, which is what
        # a leaked srv_hostname breaks. If a format bucket grew for an unrelated
        # reason and outlives the handshake this reports both sides with the
        # evidence file naming the selected buckets, rather than a bare pair.
        self.assertEqual(
            closed_totals,
            before_totals,
            f"{label}: format buckets did not return to their pre-connect "
            f"totals after teardown; before={before_totals} "
            f"live={live_totals} closed={closed_totals}. See "
            f"{(self.evidence / 'hostname-callsite.json')} for the tracebacks",
        )
        return signatures

    def fixture(self):
        key, cert = self.evidence / "key.pem", self.evidence / "valid.pem"
        commands = [
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(key),
            ],
            ["openssl", "pkey", "-in", str(key), "-check", "-noout"],
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-key",
                str(key),
                "-days",
                "1",
                "-subj",
                "/CN=quic-regression",
                "-out",
                str(cert),
            ],
        ]
        for index, command in enumerate(commands):
            result = subprocess.run(command, capture_output=True, timeout=30)
            (self.evidence / f"openssl-{index}.json").write_text(
                json.dumps(
                    {
                        "command": command,
                        "returncode": result.returncode,
                        "stdout": result.stdout.decode(),
                        "stderr": result.stderr.decode(),
                    }
                )
            )
            self.assertEqual(result.returncode, 0)
        return key, cert

    def test_credential_failure_rollback(self):
        """Complete 100 credential failures with fresh diagnostics and allocation evidence."""
        mode = os.environ.get("QUIC_CRYPTO_EXPECT", "fixed")
        self.assertIn(mode, LEAKS)
        key, valid_cert = self.fixture()
        preapp = self.snapshot()
        self.run_cli("memory-trace on main-heap")
        self.addCleanup(self.run_cli, "memory-trace off")
        signatures = self.probe("coverage-before", valid_cert, key, preapp)
        # The attribution buckets are measured, not assumed empty: the same 12
        # kept frames can serve more than one address-formatting site, so the
        # assertions below compare each trace against this baseline instead of
        # against zero. A rollback that leaks one vector per attempt still moves
        # the count by one per attempt, which is what the leak assertion checks.
        hostname_zero = self.hostname_totals(self.trace("baseline"), signatures)
        client = VclProcess(
            self, "failures", self.server_loop.local_ip4, CLIENT_NAMESPACE
        )
        registration = client.request("attach", cert="malformed", key=str(key))
        baseline = self.snapshot()
        self.assertEqual(baseline["used"], preapp["used"])
        expected_cert = (
            f"{registration['pair']} "
            f"(cert:{registration['cert_len']}, key:{registration['key_len']})"
        )
        self.assertEqual(
            baseline["certificates"].splitlines(),
            preapp["certificates"].splitlines() + [expected_cert],
        )
        thread = str(min(1, self.vpp_worker_count))
        bytes_per_attempt = None
        for attempt in range(1, ATTEMPTS + 1):
            self.assertEqual(self.snapshot(), baseline)
            start = len("".join(self.vpp_stderr_deque))
            result = client.request("connect", timeout=60)
            # The helper opens the connect session non-blocking, so
            # session_connect returns VPPCOM_EINPROGRESS (-115) rather than
            # blocking for the VCL session-timeout. It then waits on
            # vppcom_select, which is what drains the app event queue and
            # therefore what makes the failure visible, and closes the handle
            # if the session never becomes writable. Each attempt is bounded by
            # CONNECT_POLL_LIMIT_S plus one snapshot and one trace.
            self.assertIn(result["connect"], (0, -115), result)
            self.assertLessEqual(result["waited_s"], 5.0, result)
            # A wait that timed out without the session error would also
            # satisfy the assertions above, so require the observed error
            # sequence to end in VPPCOM_EFAULT (-14), which
            # vppcom_session_get_error returns for any non-NONE vpp_error, and
            # keep the poll count under the 5 s / 10 ms ceiling of 500.
            self.assertTrue(result["errors"], result)
            self.assertEqual(result["errors"][-1], -14, result)
            self.assertLess(result["polls"], 500, result)
            deadline = time.monotonic() + 10
            while DIAGNOSTIC not in "".join(self.vpp_stderr_deque)[start:]:
                self.assertLess(
                    time.monotonic(), deadline, "missing fresh credential diagnostic"
                )
                time.sleep(0.01)
            fresh = "".join(self.vpp_stderr_deque)[start:]
            self.assertEqual(fresh.count(DIAGNOSTIC), 1)
            (self.evidence / f"attempt-{attempt:03d}-stderr.txt").write_text(fresh)
            actual = self.snapshot()
            records = self.trace(f"attempt-{attempt:03d}")
            totals = self.hostname_totals(records, signatures)
            grown = [totals[0] - hostname_zero[0], totals[1] - hostname_zero[1]]
            if not LEAKS[mode]:
                # The context-pool counters in this snapshot are the safety net
                # for an unfreed vector this selection cannot see: a leak that
                # moved srv_hostname onto a non-format bucket leaves the
                # hostname counters at zero but still leaves the QUIC context
                # allocated, and snapshot() reads "Thread N: ctx pool used/cap"
                # for every thread. A record-existence guard would be wrong
                # here, because a correct rollback frees the vector and so must
                # leave no hostname record behind.
                self.assertEqual(actual, baseline)
                self.assertEqual(
                    grown,
                    [0, 0],
                    f"attempt {attempt} left a hostname allocation behind: "
                    f"baseline={hostname_zero} attempt={totals}",
                )
            else:
                # A leaked vector has to be visible in the trace. Without this
                # guard a selection that matched nothing would report the
                # expected growth as a mismatch, which reads like a different
                # defect than the one under test.
                self.assertTrue(
                    self.hostname_records(records, signatures),
                    f"attempt {attempt} left no attributable hostname record, "
                    f"so the leaked vector cannot be counted at all",
                )
                expected = dict(baseline, used=dict(baseline["used"]))
                expected["used"][thread] = preapp["used"][thread] + attempt
                self.assertEqual(actual, expected)
                # grown is measured against the pre-failure baseline, so it is
                # cumulative: attempt n must show n leaked vectors. A rollback
                # that freed the vector would leave it at zero throughout.
                if attempt == 1:
                    self.assertEqual(grown[0], 1, grown)
                    self.assertGreater(grown[1], 0, grown)
                    bytes_per_attempt = grown[1]
                self.assertEqual(
                    grown,
                    [attempt, bytes_per_attempt * attempt],
                    f"attempt {attempt} did not leave {attempt} leaked "
                    f"vectors: baseline={hostname_zero} attempt={totals}",
                )
                baseline = actual
            self.run_cli("show version")
            (self.evidence / f"attempt-{attempt:03d}-result.json").write_text(
                json.dumps(
                    {
                        "attempt": attempt,
                        "mode": mode,
                        "vcl": result,
                        "snapshot": actual,
                        "hostname": totals,
                        "hostname_growth": grown,
                    }
                )
            )
        client.request("detach")
        client.stop()
        final = dict(preapp, used=baseline["used"])
        self.wait_snapshot(final)
        self.probe("coverage-after", valid_cert, key, final, signatures)
        self.run_cli("show version")
        (self.evidence / "result.json").write_text(
            json.dumps(
                {
                    "mode": mode,
                    "workers": self.vpp_worker_count,
                    "completed": ATTEMPTS,
                    "leaks": LEAKS[mode],
                    "thread": thread,
                    "failure_diagnostics": sum(
                        (self.evidence / f"attempt-{n:03d}-stderr.txt")
                        .read_text()
                        .count(DIAGNOSTIC)
                        for n in range(1, ATTEMPTS + 1)
                    ),
                    "preapp": preapp,
                    "final": final,
                    "cleanup": "passed",
                    "hostname": self.hostname_totals(self.trace("final"), signatures),
                    "hostname_baseline": hostname_zero,
                },
                indent=2,
            )
        )


class QUICCredentialFailureWorker(QUICCredentialFailure):
    """QUIC outbound credential failure rollback (one worker)."""

    vpp_worker_count = 1


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
