#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""QUIC outbound credential failure must release context, hostname and crypto state."""

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time
import unittest
import uuid

from asfframework import VppAsfTestCase, VppTestRunner
from config import config


DIAGNOSTIC = "unable to initialize certificate/key pair"
ATTEMPTS = 100
CALLSITE = re.compile(r"\bquic_connect_connection\b")
# quic_connect_connection() formats the hostname before the crypto context is
# acquired, so every record below that frame belongs to the connect path.
HOSTNAME_FORMAT = re.compile(r"\bformat\b|format_ip46_address")


class VclProcess:
    """One quic_crypto_client.py subprocess speaking JSON lines."""

    def __init__(self, test, name, address):
        self.test = test
        libraries = list(Path(config.vpp_install_dir).rglob("libvppcom.so"))
        test.assertEqual(len(libraries), 1, libraries)
        conf = test.evidence / f"{name}-vcl.conf"
        conf.write_text("vcl { app-scope-global app-timeout 60 session-timeout 30 }\n")
        env = dict(os.environ, VCL_CONFIG=str(conf))
        env["VCL_VPP_SAPI_SOCKET"] = f"{test.tempdir}/app_ns_sockets/default"
        self.stderr_path = test.evidence / f"{name}-stderr.txt"
        self.stderr = self.stderr_path.open("w")
        self.process = subprocess.Popen(
            [sys.executable, str(Path(__file__).with_name("quic_crypto_client.py")),
             str(libraries[0]), address, "4433"],
            env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.stderr, text=True,
        )
        self.sequence = 0
        self.transcript = (test.evidence / f"{name}-protocol.jsonl").open("w")
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        test.addCleanup(self.stop)

    def request(self, operation, timeout=120, **params):
        self.sequence += 1
        request = dict(id=self.sequence, operation=operation, **params)
        self.transcript.write(json.dumps({"request": request}) + "\n")
        self.transcript.flush()
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        if not self.selector.select(timeout):
            raise AssertionError(f"helper timed out after {timeout}s: {request}")
        line = self.process.stdout.readline()
        self.transcript.write(json.dumps({"reply": line}) + "\n")
        self.transcript.flush()
        reply = json.loads(line)
        self.test.assertEqual(reply["id"], self.sequence)
        return reply["result"]

    def stop(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
                self.test.fail("VCL helper required killing during cleanup")
        self.selector.close()
        self.stderr.close()
        self.transcript.close()
        self.test.assertEqual(self.process.returncode, 0,
                              f"VCL helper failed, see {self.stderr_path}")


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
        self.create_loopback_interfaces(1)
        self.loop0.admin_up()
        self.loop0.config_ip4()
        self.addCleanup(self.loop0.admin_down)
        self.addCleanup(self.loop0.unconfig_ip4)
        self.cli("quic set crypto api engine-lib")
        self.cli("show threads")
        self.cli("show version verbose")

    def cli(self, command):
        reply = self.vapi.cli(command)
        self.cli_log.write(json.dumps({"command": command, "reply": reply}) + "\n")
        self.cli_log.flush()
        self.assertFalse(re.search(r"unknown input|not initialized|not enabled", reply))
        self.assertIsNone(self.vpp.poll(), "VPP exited")
        return reply.strip()

    def snapshot(self):
        quic = self.cli("show quic")
        self.assertIn("quic engine: quicly", quic.lower())
        pools = re.findall(r"Thread (\d+): ctx pool (\d+)/(\d+)", quic)
        self.assertEqual(len(pools), self.vpp_worker_count + 1)
        return {
            "used": {thread: int(used) for thread, used, capacity in pools},
            "crypto": self.cli("show quic crypto context"),
            "sessions": self.cli("show session"),
            "certificates": self.cli("show app certificate"),
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
        reply = self.cli(f"save memory-trace {filename}")
        self.assertIn(f"Saving trace to '{path}'", reply)
        self.assertTrue(path.is_file(), "trace command produced no readable file")
        stat = path.stat()
        self.assertGreaterEqual(stat.st_mtime_ns, started - 1_000_000_000)
        raw = path.read_bytes()
        destination = self.evidence / f"{label}.json"
        destination.write_bytes(raw)
        records = json.loads(raw)
        self.assertIsInstance(records, list)
        self.assertTrue(records, "empty allocator trace is not coverage")
        for record in records:
            self.assertIsInstance(record["count"], int)
            self.assertGreater(record["count"], 0)
            self.assertGreater(record["bytes"], 0)
            self.assertTrue(record["traceback"])
        (self.evidence / f"{label}-metadata.json").write_text(json.dumps({
            "file": str(path), "mtime_ns": stat.st_mtime_ns,
            "started_ns": started, "sha256": hashlib.sha256(raw).hexdigest(),
        }))
        path.unlink()
        return records

    @staticmethod
    def signature(record):
        frames = record["traceback"]
        for index, frame in enumerate(frames):
            if CALLSITE.search(frame):
                return tuple(frames[:index + 1])
        return None

    def hostname_records(self, records, signatures):
        return [record for record in records if self.signature(record) in signatures]

    def hostname_totals(self, records, signatures):
        relevant = self.hostname_records(records, signatures)
        return [sum(record[field] for record in relevant) for field in ("count", "bytes")]

    def probe(self, label, valid_cert, key, baseline, signatures=None):
        """Complete handshake, then prove the hostname allocation is released."""
        server = VclProcess(self, label + "-server", self.loop0.local_ip4)
        client = VclProcess(self, label + "-client", self.loop0.local_ip4)
        for peer in (server, client):
            peer.request("attach", cert=str(valid_cert), key=str(key))
        server.request("listen")
        listening = self.snapshot()
        before = self.trace(label + "-before")
        connected = client.request("connect", success=True)
        accepted = server.request("accept")
        self.assertEqual(connected["connect"], 0)
        self.assertGreaterEqual(accepted["accepted"], 0)
        live = self.snapshot()
        thread = str(min(1, self.vpp_worker_count))
        delta = {index: live["used"][index] - used
                 for index, used in listening["used"].items()}
        self.assertEqual(delta, {index: 2 if index == thread else 0
                                 for index in listening["used"]})
        self.cli("show session verbose 2")
        records = self.trace(label + "-live")
        if signatures is None:
            signatures = {
                self.signature(record) for record in records
                if self.signature(record) is not None
                and HOSTNAME_FORMAT.search(" ".join(self.signature(record)))
            }
            self.assertEqual(len(signatures), 1, "hostname callsite attribution remains OPEN")
            (self.evidence / "hostname-callsite.json").write_text(json.dumps({
                "signatures": sorted(signatures), "thread": thread,
                "source": "quic_connect_connection: format srv_hostname before crypto acquire",
                "connected": connected, "accepted": accepted,
            }, indent=2))
        before_totals = self.hostname_totals(before, signatures)
        live_totals = self.hostname_totals(records, signatures)
        self.assertEqual(live_totals[0], before_totals[0] + 1)
        self.assertGreater(live_totals[1], before_totals[1])
        for peer in (client, server):
            peer.request("close")
        for peer in (client, server):
            peer.request("destroy")
            peer.stop()
        deadline = time.monotonic() + 15
        while True:
            actual = self.snapshot()
            if all(actual[field] == baseline[field] for field in ("used", "sessions", "crypto")):
                break
            self.assertLess(time.monotonic(), deadline, "handshake probe cleanup failed")
            time.sleep(0.05)
        self.wait_snapshot(baseline)
        closed = self.trace(label + "-closed")
        self.assertEqual(self.hostname_totals(closed, signatures), before_totals)
        return signatures

    def fixture(self):
        key, cert = self.evidence / "key.pem", self.evidence / "valid.pem"
        commands = [
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
             "-out", str(key)],
            ["openssl", "pkey", "-in", str(key), "-check", "-noout"],
            ["openssl", "req", "-new", "-x509", "-key", str(key), "-days", "1",
             "-subj", "/CN=quic-regression", "-out", str(cert)],
        ]
        for index, command in enumerate(commands):
            result = subprocess.run(command, capture_output=True, timeout=30)
            (self.evidence / f"openssl-{index}.json").write_text(json.dumps({
                "command": command, "returncode": result.returncode,
                "stdout": result.stdout.decode(), "stderr": result.stderr.decode(),
            }))
            self.assertEqual(result.returncode, 0)
        return key, cert

    def test_credential_failure_rollback(self):
        """Complete 100 credential failures with fresh diagnostics and allocation evidence."""
        mode = os.environ.get("QUIC_CRYPTO_EXPECT", "fixed")
        self.assertIn(mode, ("fixed", "original"))
        key, valid_cert = self.fixture()
        preapp = self.snapshot()
        self.cli("memory-trace on main-heap")
        self.addCleanup(self.cli, "memory-trace off")
        signatures = self.probe("coverage-before", valid_cert, key, preapp)
        self.assertEqual(self.hostname_totals(self.trace("baseline"), signatures), [0, 0])
        client = VclProcess(self, "failures", self.loop0.local_ip4)
        registration = client.request("attach", cert="malformed", key=str(key))
        baseline = self.snapshot()
        self.assertEqual(baseline["used"], preapp["used"])
        expected_cert = (f"{registration['pair']} "
                         f"(cert:{registration['cert_len']}, key:{registration['key_len']})")
        self.assertEqual(baseline["certificates"].splitlines(),
                         preapp["certificates"].splitlines() + [expected_cert])
        count_per_attempt = bytes_per_attempt = None
        for attempt in range(1, ATTEMPTS + 1):
            self.assertEqual(self.snapshot(), baseline)
            before = "".join(self.vpp_stderr_deque)
            self.assertEqual(before.count(DIAGNOSTIC), attempt - 1)
            result = client.request("connect")
            deadline = time.monotonic() + 30
            while "".join(self.vpp_stderr_deque).count(DIAGNOSTIC) < attempt:
                self.assertLess(time.monotonic(), deadline, "missing fresh credential diagnostic")
                time.sleep(0.01)
            after = "".join(self.vpp_stderr_deque)
            self.assertTrue(after.startswith(before), "VPP stderr history changed")
            fresh = after[len(before):]
            self.assertEqual(fresh.count(DIAGNOSTIC), 1)
            (self.evidence / f"attempt-{attempt:03d}-stderr.txt").write_text(fresh)
            actual = self.snapshot()
            records = self.trace(f"attempt-{attempt:03d}")
            totals = self.hostname_totals(records, signatures)
            if mode == "fixed":
                self.assertEqual(actual, baseline)
                self.assertEqual(totals, [0, 0])
            else:
                expected = dict(baseline, used=dict(baseline["used"]))
                thread = str(min(1, self.vpp_worker_count))
                expected["used"][thread] = preapp["used"][thread] + attempt
                self.assertEqual(actual, expected)
                if attempt == 1:
                    count_per_attempt, bytes_per_attempt = totals
                    self.assertEqual(count_per_attempt, 1)
                    self.assertGreater(bytes_per_attempt, 0)
                self.assertEqual(totals, [attempt, attempt * bytes_per_attempt])
                baseline = actual
            self.cli("show version")
            (self.evidence / f"attempt-{attempt:03d}-result.json").write_text(
                json.dumps({"attempt": attempt, "mode": mode, "vcl": result,
                            "snapshot": actual, "hostname": totals})
            )
        client.request("detach")
        client.stop()
        final = dict(preapp, used=baseline["used"])
        self.wait_snapshot(final)
        self.probe("coverage-after", valid_cert, key, final, signatures)
        self.cli("show version")
        (self.evidence / "result.json").write_text(json.dumps({
            "mode": mode, "workers": self.vpp_worker_count, "completed": ATTEMPTS,
            "diagnostics": "".join(self.vpp_stderr_deque).count(DIAGNOSTIC),
            "preapp": preapp, "final": final, "cleanup": "passed",
            "hostname": self.hostname_totals(self.trace("final"), signatures),
        }, indent=2))


class QUICCredentialFailureWorker(QUICCredentialFailure):
    """QUIC outbound credential failure rollback (one worker)."""

    vpp_worker_count = 1


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
