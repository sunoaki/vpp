#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import socket
import threading
import time
import unittest

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from framework import VppTestCase
from asfframework import VppTestRunner


class CliSession(object):
    """A CLI session of our own on the VPP CLI socket.

    The session runs on a process of its own inside VPP, so a command it
    carries executes on that process rather than on the process of the API
    connection this test drives. The session is told it is a `vppctl` client,
    which VPP treats as non-interactive: such a session sends a NUL byte after
    the output of a command, and that byte is the signal the command finished.
    Keeping the session open reuses the connection, so a command costs no
    process start in the measurement of how long the main loop kept it waiting.
    """

    IAC = 0xFF
    SB = 0xFA
    SE = 0xF0

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.sock.settimeout(60.0)
        self.pending = b""
        # Answer the terminal-type negotiation with the name VPP treats as a
        # non-interactive client.
        self.sock.sendall(b"\xff\xfa\x18\x00vppctl\xff\xf0")

    def _read(self):
        """Read more bytes and strip the telnet negotiation around the output.

        VPP opens a socket session with telnet option negotiation, and the
        payload of that negotiation can contain any byte, NUL included, so the
        bytes of the negotiation are removed before the output is examined.
        """
        data = self.sock.recv(1 << 16)
        if not data:
            raise RuntimeError("CLI session closed")
        data = self.pending + data
        out = b""
        i = 0
        n = len(data)
        while i < n:
            if data[i] != self.IAC:
                out += data[i : i + 1]
                i += 1
                continue
            if i + 1 >= n:
                break
            command = data[i + 1]
            if command == self.IAC:
                out += bytes([self.IAC])
                i += 2
            elif command == self.SB:
                end = data.find(bytes([self.IAC, self.SE]), i + 2)
                if end < 0:
                    break
                i = end + 2
            elif command >= 251:  # WILL / WONT / DO / DONT carry one option
                if i + 2 >= n:
                    break
                i += 3
            else:
                i += 2
        self.pending = data[i:]
        return out

    def read_command(self, cmd):
        """Run a command and return its output once VPP said it finished."""
        start = time.monotonic()
        self.sock.sendall(cmd.encode() + b"\n")
        seen = b""
        while b"\0" not in seen:
            seen += self._read()
        self.last_took = time.monotonic() - start
        return seen.split(b"\0", 1)[0].decode(errors="replace")

    def command(self, cmd):
        """Run a command and return the seconds until VPP said it finished."""
        self.read_command(cmd)
        return self.last_took

    def close(self):
        self.sock.close()


class TestVlibErrors(VppTestCase):
    """show errors reports many counters without holding the main thread"""

    # Main thread and worker both have counters to show, which is what a
    # chunked report must keep consistent, and each thread prints a block of
    # every counter, so the report is long enough to span many chunks. One
    # worker keeps the suite at the two cores it needs, so it runs on a runner
    # that has only two physical cores.
    vpp_worker_count = 1

    # Each packet-generator interface registers the pg-tx node error counters,
    # so this many interfaces register this many counters more than a test with
    # the default one interface shows. The report of the box this models has
    # thousands of them. There are enough of them that even a report formatted
    # without handing the main loop back outlasts an idle command by an order
    # of magnitude, so the two differ in the time an answer waits for them
    # rather than in a few milliseconds of noise.
    PG_INTERFACES = 64

    # Lines the report formats before it hands the main loop back; see
    # vlib_error_format_chunk in src/vlib/error.c.
    REPORT_CHUNK_LINES = 1024

    # Packets the test drops, so that there is a non-zero count to find in the
    # report and in its total.
    N_PKTS = 7

    @classmethod
    def setUpClass(cls):
        super(TestVlibErrors, cls).setUpClass()
        cls.create_pg_interfaces(range(cls.PG_INTERFACES))
        for i in cls.pg_interfaces:
            i.admin_up()

        # The first interface takes an address once, so that every test sends
        # from an interface that has one. Configuring it per test would add the
        # same address twice, which the API refuses.
        cls.pg0.config_ip4()
        cls.pg0.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        cls.pg0.unconfig_ip4()
        for i in cls.pg_interfaces:
            i.admin_down()
        super(TestVlibErrors, cls).tearDownClass()

    def send_dropped_packets(self):
        """Send packets the FIB drops for want of a route.

        The destination is in a prefix no route covers, so the forwarding
        lookup answers with the drop adjacency every miss shares, and each
        packet is counted against the error that adjacency names. That counter
        is registered by vlib rather than by this test, so it is present on any
        build and no plugin has to be enabled for it.
        """
        packets = [
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst="198.51.100.17")
            / UDP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 48)
            for _ in range(self.N_PKTS)
        ]

        self.pg0.add_stream(packets)
        self.pg_start()
        self.sleep(0.5)

    def cli_errors(self, cmd):
        """Run a show errors form and return its reply."""
        c = self.vapi.cli_return_response(cmd)
        self.assertEqual(c.retval, 0, f"{cmd} failed: {c.reply}")
        return c.reply

    def test_show_errors_many_counters(self):
        """show errors reports every node and its total with many counters"""

        self.vapi.cli("clear errors")
        self.send_dropped_packets()

        reply = self.cli_errors("show errors")

        # The columns the report has always had, in the order it has had them.
        header = reply.splitlines()[0]
        for column in ("Count", "Node", "Reason", "Severity", "Counter"):
            self.assertIn(column, header)

        # The counter the packets incremented is listed under its node, with
        # the reason vlib registers for the drop adjacency a lookup miss uses.
        self.assertRegex(
            reply,
            r"\s+%d\s+null-node\s+blackholed packets\s+error" % self.N_PKTS,
            "the report did not name the dropped packets",
        )

        # A node that counted nothing is left out of a plain report, so the
        # interfaces this test created, which registered counters they have
        # not filled yet, are absent from it.
        self.assertNotIn("-tx", reply)

        # A plain report carries no total section; it is part of verbose alone.
        self.assertNotIn("Total:", reply)

    def test_show_errors_verbose_total(self):
        """show errors verbose reports the total across threads"""

        self.vapi.cli("clear errors")
        self.send_dropped_packets()

        reply = self.cli_errors("show errors verbose 2")

        # The verbose form names the thread each block of counters belongs to,
        # in the order show run names them, and the total section follows the
        # blocks.
        self.assertIn("Thread 0 (vpp_main", reply)
        self.assertIn("Thread 1 (vpp_wk_0", reply)
        self.assertIn("Total:", reply)

        # Verbose 2 also lists the counters that read zero, so the block of
        # every interface the test created is in the report even though only
        # the first one sent anything.
        self.assertIn("pg0-tx", reply)
        self.assertIn("pg63-tx", reply)

        total = reply.split("Total:", 1)[1]
        self.assertRegex(
            total,
            r"\s+%d\s+null-node\s+blackholed packets" % self.N_PKTS,
            "the total section did not count the dropped packets",
        )

    def open_probe_session(self):
        """Open a CLI session of its own and return it.

        The session runs on one of VPP's own processes, not on the process of
        the API connection this test drives, so a command on it is answered
        between the chunks of a report that hands the main loop back.
        """
        session = CliSession(self.get_cli_sock_path())
        self.addCleanup(session.close)
        return session

    def suspends(self):
        """Return the suspends count of the process that runs API commands.

        VPP records a suspend on the process whose stack the command runs on
        when that stack hands the main loop back, and `show runtime` prints the
        count per process under Suspends. The count only ever rises, since the
        column subtracts the value captured by `clear runtime`, which this test
        never issues.
        """
        reply = self.cli_errors("show runtime")
        total = 0
        found = 0
        for line in reply.splitlines():
            fields = line.split()
            if len(fields) < 6 or fields[0] != "api-rx-from-ring":
                continue
            total += int(fields[-3])
            found += 1
        self.assertTrue(found, "show runtime printed no api-rx-from-ring process row")
        return total

    def test_show_errors_bounded_time(self):
        """show errors hands the main loop back as it formats

        A report of many counters must not keep the main loop to itself. The
        command formats its lines in chunks and hands the main loop back at the
        end of each one, so another session gets the loop between two chunks.

        What this asserts is that hand-back itself. VPP counts a suspend on the
        process whose stack a command runs on each time that stack hands the
        main loop back, and the report runs on the process of the API
        connection, so a report that yields once per chunk raises that
        process's Suspends column by the number of chunks it formatted. A
        report that formats every line before returning never hands the loop
        back from inside itself, so the column rises only by what any command
        costs. The column is read before and after the report and once across a
        command that formats nothing, so the second reading is what the report
        itself added.
        """
        self.vapi.cli("clear errors")
        self.send_dropped_packets()

        # The suspends a command that formats no report costs, which is the
        # floor the report has to rise above.
        idle_before = self.suspends()
        self.cli_errors("show version")
        idle_after = self.suspends()

        probe = self.open_probe_session()

        idle = sorted(probe.command("show version") for _ in range(20))
        idle_max = idle[-1]

        stop = threading.Event()
        waits = []

        def probe_session():
            while not stop.is_set():
                began = time.monotonic()
                took = probe.command("show version")
                waits.append((began, took))

        prober = threading.Thread(target=probe_session)
        prober.start()
        try:
            # Let the prober get into its loop before the report starts, so the
            # two overlap for the whole of the report.
            time.sleep(0.02)
            before = self.suspends()
            start = time.monotonic()
            reply = self.cli_errors("show errors verbose 2")
            end = time.monotonic()
            after = self.suspends()
        finally:
            stop.set()
            prober.join()

        report = end - start
        lines = len(reply.splitlines())
        chunks = lines // self.REPORT_CHUNK_LINES
        # The commands the report met: each of them was answered by the main
        # loop some time after it was sent, and that time is how long the loop
        # kept it waiting.
        during = [wait for began, wait in waits if start <= began <= end]

        self.assertGreater(
            lines,
            1024,
            f"the report showed {lines} lines, too few to span one chunk, "
            "so the test cannot tell a yielding report from one that is not",
        )

        self.assertGreaterEqual(
            chunks,
            2,
            f"the report showed {lines} lines, one chunk of "
            f"{self.REPORT_CHUNK_LINES} lines at most, so it is too short to "
            "require more than one chunk and the suspend count it must raise "
            "would be no more than an empty command's",
        )

        self.assertGreater(
            report,
            4 * idle_max,
            f"the report took {report:.3f}s and an idle show version "
            f"{idle_max:.4f}s, which is too small a ratio to tell whether the "
            "report yields, so the test cannot discriminate",
        )

        self.assertTrue(
            during,
            "the prober issued no command while the report ran, so the test "
            "cannot tell whether the report yields",
        )

        # The report hands the loop back once it has formatted a chunk of its
        # lines, so it adds a suspend per chunk to the command process on top
        # of what the command costs anyway. A report that formats everything
        # before returning adds none, so the count stays at the idle floor.
        # Half the chunk count is asked for, well below what the chunks alone
        # produce, so that a chunk that ends on its time budget rather than its
        # line budget costs the test nothing.
        idle_suspends = idle_after - idle_before
        report_suspends = after - before
        self.assertGreaterEqual(
            report_suspends,
            idle_suspends + chunks // 2,
            f"the report rose the Suspends column of the command process by "
            f"{report_suspends} over {lines} lines, while a command that "
            f"formats nothing rose it by {idle_suspends}: the report held the "
            f"main loop for its {lines} lines instead of handing it back "
            f"between two of its {self.REPORT_CHUNK_LINES}-line chunks, so it "
            "should have risen the column once per chunk",
        )


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
