#!/usr/bin/env python3
"""CLI functional tests"""

import subprocess
import unittest
from pathlib import Path
from tempfile import NamedTemporaryFile
from time import monotonic, sleep

from vpp_papi import VPPIOError

from asfframework import VppAsfTestCase, VppTestRunner
from config import config


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

    def wait_script_hits(self):
        hits = dict(
            line.split(": ", 1)
            for line in self.vapi.cli("show cli hit").splitlines()
            if ": " in line
        )
        return int(hits.get("wait", 0)), int(hits.get("echo", 0))

    def worker_loop_count(self):
        reply = self.vapi.cli("show threads")
        for line in reply.splitlines():
            fields = line.split()
            if fields[1:2] == ["vpp_wk_0"]:
                # Count from the right because the scheduling policy contains spaces.
                return int(fields[-6])
        self.fail(f"No vpp_wk_0 row in show threads:\n{reply}")

    def test_wait_in_exec_allows_worker_progress(self):
        """The worker completes more loops while the script is waiting."""
        wait_hits, echo_hits = self.wait_script_hits()
        waiting = (wait_hits + 1, echo_hits)
        finished = (wait_hits + 1, echo_hits + 1)
        wait_seconds = 2
        with NamedTemporaryFile(mode="w", dir=self.tempdir) as script:
            script.write(f"wait {wait_seconds}\necho wait-script-complete\n")
            script.flush()
            command = [
                Path(config.vpp).with_name("vppctl"),
                "-s",
                self.get_cli_sock_path(),
                "exec",
                script.name,
            ]
            start = monotonic()
            with subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            ) as cli:
                try:
                    self.check_worker_progress_during_wait(waiting)
                    stdout, stderr = cli.communicate(timeout=5)
                finally:
                    if cli.poll() is None:
                        cli.kill()
                        cli.communicate(timeout=5)

            self.assertEqual(cli.returncode, 0, stderr)
            self.assertEqual(stdout.strip(), "")
            self.assertGreaterEqual(monotonic() - start, wait_seconds - 0.010)
            self.assertEqual(self.wait_script_hits(), finished)

    def check_worker_progress_during_wait(self, waiting):
        deadline = monotonic() + 5
        while monotonic() < deadline:
            hits = self.wait_script_hits()
            if hits == waiting:
                break
            if hits[1] != waiting[1]:
                self.fail("Script finished waiting before sampling started")
            sleep(0.025)
        else:
            self.fail("Script did not reach wait before the observation deadline")

        # Both loop samples must precede the next script line, even if the
        # client is descheduled between the samples.
        first_count = self.worker_loop_count()
        sleep(0.100)
        second_count = self.worker_loop_count()
        self.assertEqual(
            self.wait_script_hits(), waiting, "Script left wait before sampling ended"
        )
        self.assertNotEqual(
            first_count, second_count, "Worker loop count did not advance during wait"
        )
        self.logger.debug(
            "Worker loops during wait: %d -> %d", first_count, second_count
        )


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
