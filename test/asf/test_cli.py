#!/usr/bin/env python3
"""CLI functional tests"""

import unittest
from tempfile import NamedTemporaryFile
from time import monotonic

from vpp_papi import VPPIOError

from asfframework import VppAsfTestCase, VppTestRunner


class TestCLI(VppAsfTestCase):
    """CLI Test Case"""

    maxDiff = None

    @classmethod
    def setUpClass(cls):
        # using the framework default
        cls.vapi_response_timeout = 5
        super(TestCLI, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCLI, cls).tearDownClass()

    def setUp(self):
        super(TestCLI, self).setUp()

    def tearDown(self):
        super(TestCLI, self).tearDown()

    def test_cli_retval(self):
        """CLI inband retval"""
        rv = self.vapi.papi.cli_inband(cmd="this command does not exist")
        self.assertNotEqual(rv.retval, 0)

        rv = self.vapi.papi.cli_inband(cmd="show version")
        self.assertEqual(rv.retval, 0)

    def test_long_cli_delay(self):
        """Test that VppApiClient raises VppIOError if timeout."""  # noqa
        with self.assertRaises(VPPIOError) as ctx:
            rv = self.vapi.papi.cli_inband(cmd="wait 10")

    def test_long_cli_delay_override(self):
        """Test per-command _timeout option."""  # noqa
        rv = self.vapi.papi.cli_inband(cmd="wait 10", _timeout=15)
        self.assertEqual(rv.retval, 0)


class TestCLIExtendedVapiTimeout(VppAsfTestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.vapi_response_timeout = 15
        cls.__doc__ = (
            " CLI Test Case w/ Extended (%ssec) Vapi Timeout "
            % cls.vapi_response_timeout
        )
        super(TestCLIExtendedVapiTimeout, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCLIExtendedVapiTimeout, cls).tearDownClass()

    def setUp(self):
        super(TestCLIExtendedVapiTimeout, self).setUp()

    def tearDown(self):
        super(TestCLIExtendedVapiTimeout, self).tearDown()

    def test_long_cli_delay(self):
        """Test that delayed result returns with extended timeout."""
        wait_secs = self.vapi_response_timeout - 1

        # get vpp time as float
        start = self.vapi.papi.show_vpe_system_time(
            _no_type_conversion=True
        ).vpe_system_time
        rv = self.vapi.papi.cli_inband(cmd="wait %s" % wait_secs)
        now = self.vapi.papi.show_vpe_system_time(
            _no_type_conversion=True
        ).vpe_system_time

        # assume that the overhead of the measurement is not more that .5 sec.
        self.assertEqual(round(now - start), wait_secs)


class TestCLIWait(VppAsfTestCase):
    """CLI wait completion and worker progress"""

    vpp_worker_count = 1

    def test_wait_completion(self):
        """A short wait returns its completion message after the interval."""
        start = monotonic()
        reply = self.vapi.cli("wait 0.250")
        self.assertGreaterEqual(monotonic() - start, 0.240)
        self.assertEqual(reply.strip(), "waited 0.250 sec.")

    def test_wait_in_exec_allows_worker_progress(self):
        """The worker generates packets between the script's enable and disable."""
        self.assertIn("vpp_wk_0", self.vapi.cli("show threads"))
        stream = "cli-wait"
        packet_limit = 2000
        self.vapi.cli(
            "packet-generator new {\n"
            f" name {stream} worker 0 node ethernet-input\n"
            f" rate 200 limit {packet_limit} size 128-128\n"
            " data {\n"
            "   IP6: 00:d0:2d:5e:86:85 -> 00:0d:ea:d0:00:00\n"
            "   ICMP: db00::1 -> db00::2\n"
            "   incrementing 30\n"
            " }\n"
            "}"
        )
        self.addCleanup(self.vapi.cli, f"packet-generator delete {stream}")

        with NamedTemporaryFile(mode="w", dir=self.tempdir) as script:
            script.write(
                f"packet-generator enable-stream {stream}\n"
                "wait 1\n"
                f"packet-generator disable-stream {stream}\n"
            )
            script.flush()
            start = monotonic()
            self.vapi.cli(f"exec {script.name}")
            self.assertGreaterEqual(monotonic() - start, 0.990)

        reply = self.vapi.cli("show packet-generator")
        row = next(
            (line.split() for line in reply.splitlines() if line.startswith(stream)),
            [],
        )
        self.assertEqual(row[:2], [stream, "No"], reply)
        generated = int(row[2])
        self.assertGreaterEqual(generated, 50, reply)
        self.assertLess(generated, packet_limit, reply)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
