from config import config
from asfframework import VppAsfTestCase, VppTestRunner, get_testcase_dirname
import unittest
import subprocess
import tempfile
import os
import json
import re
import select
import sys
import time
from vpp_qemu_utils import (
    create_host_interface,
    delete_all_host_interfaces,
    create_namespace,
    delete_all_namespaces,
)


@unittest.skipIf(
    "http_static" in config.excluded_plugins, "Exclude HTTP Static Server plugin tests"
)
@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
class TestHttpStaticVapi(VppAsfTestCase):
    """enable the http static server and send requests [VAPI]"""

    @classmethod
    def setUpClass(cls):
        super(TestHttpStaticVapi, cls).setUpClass()
        # 2 temp files to improve coverage of http_cache.c
        cls.temp = tempfile.NamedTemporaryFile()
        cls.temp.write(b"Hello world")

        cls.temp2 = tempfile.NamedTemporaryFile()
        cls.temp2.write(b"Hello world2")

        cls.ns_history_name = (
            f"{config.tmp_dir}/{get_testcase_dirname(cls.__name__)}/history_ns.txt"
        )
        cls.if_history_name = (
            f"{config.tmp_dir}/{get_testcase_dirname(cls.__name__)}/history_if.txt"
        )

        try:
            # CleanUp
            delete_all_namespaces(cls.ns_history_name)
            delete_all_host_interfaces(cls.if_history_name)

            cls.ns_name = create_namespace(cls.ns_history_name)
            cls.host_if_name, cls.vpp_if_name = create_host_interface(
                cls.if_history_name, cls.ns_name, "10.10.1.1/24"
            )

        except Exception as e:
            cls.logger.warning(f"Unable to complete setup: {e}")
            raise unittest.SkipTest("Skipping tests due to setup failure.")

        cls.vapi.cli(f"create host-interface name {cls.vpp_if_name}")
        cls.vapi.cli(f"set int state host-{cls.vpp_if_name} up")
        cls.vapi.cli(f"set int ip address host-{cls.vpp_if_name} 10.10.1.2/24")

    @classmethod
    def tearDownClass(cls):
        delete_all_namespaces(cls.ns_history_name)
        delete_all_host_interfaces(cls.if_history_name)

        cls.temp.close()
        cls.temp2.close()
        super(TestHttpStaticVapi, cls).tearDownClass()

    def test_http_static_vapi(self):
        self.vapi.http_static_enable_v5(
            www_root="/tmp",
            uri="tcp://0.0.0.0:80",
        )
        # move file pointer to the beginning
        self.temp.seek(0)
        process = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                self.ns_name,
                "curl",
                "--noproxy",
                "10.10.1.2",
                "-v",
                f"10.10.1.2/{self.temp.name[5:]}",
            ],
            capture_output=True,
        )
        if process.returncode != 0:
            self.logger.error(
                f"Subprocess failed with return code {process.returncode}"
            )
            self.logger.error(f"stderr: {process.stderr.decode()}")
            raise RuntimeError("Subprocess execution failed")
        self.logger.info(self.vapi.cli("sh session verbose"))
        self.assertIn(b"Hello world", process.stdout)
        self.assertIn(b"max-age=600", process.stderr)

        self.temp2.seek(0)
        process = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                self.ns_name,
                "curl",
                "--noproxy",
                "10.10.1.2",
                f"10.10.1.2/{self.temp2.name[5:]}",
            ],
            capture_output=True,
        )
        self.assertIn(b"Hello world2", process.stdout)

        self.vapi.http_static_disable()
        self.temp2.seek(0)
        process = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                self.ns_name,
                "curl",
                "--noproxy",
                "10.10.1.2",
                f"10.10.1.2/{self.temp2.name[5:]}",
            ],
            capture_output=True,
        )
        self.assertNotIn(b"Hello world2", process.stdout)

        # Now enable again
        self.vapi.http_static_enable_v5(
            www_root="/tmp",
            uri="http://10.10.1.2:80",
        )
        self.temp2.seek(0)
        process = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                self.ns_name,
                "curl",
                "--noproxy",
                "10.10.1.2",
                f"10.10.1.2/{self.temp2.name[5:]}",
            ],
            capture_output=True,
        )
        self.assertIn(b"Hello world2", process.stdout)

        reply = self.vapi.http_static_get()
        self.assertEqual(reply.www_root, "/tmp")
        self.assertEqual(reply.uri, "http://10.10.1.2:80")


@unittest.skipIf(
    "http_static" in config.excluded_plugins, "Exclude HTTP Static Server plugin tests"
)
@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
class TestHttpStaticCli(VppAsfTestCase):
    """enable the static http server and send requests [CLI]"""

    @classmethod
    def setUpClass(cls):
        super(TestHttpStaticCli, cls).setUpClass()
        # 2 temp files to improve coverage of http_cache.c
        cls.temp = tempfile.NamedTemporaryFile()
        cls.temp.write(b"Hello world")

        cls.temp2 = tempfile.NamedTemporaryFile()
        cls.temp2.write(b"Hello world2")

        cls.ns_history_name = (
            f"{config.tmp_dir}/{get_testcase_dirname(cls.__name__)}/history_ns.txt"
        )
        cls.if_history_name = (
            f"{config.tmp_dir}/{get_testcase_dirname(cls.__name__)}/history_if.txt"
        )

        try:
            delete_all_namespaces(cls.ns_history_name)
            delete_all_host_interfaces(cls.if_history_name)

            cls.ns_name = create_namespace(cls.ns_history_name)
            cls.host_if_name, cls.vpp_if_name = create_host_interface(
                cls.if_history_name, cls.ns_name, "10.10.1.1/24"
            )

        except Exception as e:
            cls.logger.warning(f"Unable to complete setup: {e}")
            raise unittest.SkipTest("Skipping tests due to setup failure.")

        cls.vapi.cli(f"create host-interface name {cls.vpp_if_name}")
        cls.vapi.cli(f"set int state host-{cls.vpp_if_name} up")
        cls.vapi.cli(f"set int ip address host-{cls.vpp_if_name} 10.10.1.2/24")

    @classmethod
    def tearDownClass(cls):
        delete_all_namespaces(cls.ns_history_name)
        delete_all_host_interfaces(cls.if_history_name)

        cls.temp.close()
        cls.temp2.close()
        super(TestHttpStaticCli, cls).tearDownClass()

    def test_http_static_cli(self):
        self.vapi.cli(
            "http static server www-root /tmp uri tcp://0.0.0.0/80 cache-size 2m"
        )
        # move file pointer to the beginning
        self.temp.seek(0)
        process = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                self.ns_name,
                "curl",
                f"10.10.1.2/{self.temp.name[5:]}",
            ],
            capture_output=True,
        )
        self.assertIn(b"Hello world", process.stdout)

        self.temp2.seek(0)
        process = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                self.ns_name,
                "curl",
                f"10.10.1.2/{self.temp2.name[5:]}",
            ],
            capture_output=True,
        )
        self.assertIn(b"Hello world2", process.stdout)

        self.logger.info(self.vapi.cli("show http static server cache"))
        self.logger.info(self.vapi.cli("clear http static cache"))
        self.logger.info(self.vapi.cli("show http static server sessions"))

        # Now turn the server off again
        self.vapi.cli("http static server disable")
        process = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                self.ns_name,
                "curl",
                f"10.10.1.2/{self.temp2.name[5:]}",
            ],
            capture_output=True,
        )
        self.assertNotIn(b"Hello world2", process.stdout)

    def _client(self, port, path="/version.json", secure=False, pending=False):
        script = """
import http.client, json, socket, ssl, sys
port, path, secure, pending = json.loads(sys.argv[1])
connection = (http.client.HTTPSConnection(
    "10.10.1.2", port, timeout=5, context=ssl._create_unverified_context())
    if secure else http.client.HTTPConnection("10.10.1.2", port, timeout=5))
if pending:
    connection.connect()
    connection.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    connection.request("GET", path)
    response = connection.getresponse()
    print(json.dumps({"status": response.status}), flush=True)
else:
    def request():
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            body = response.read()
            print(json.dumps({"status": response.status,
                              "body": body.decode(),
                              "cache": response.getheader("Cache-Control")}), flush=True)
        except (ConnectionResetError, BrokenPipeError,
                http.client.IncompleteRead, http.client.RemoteDisconnected) as error:
            print(json.dumps({"closed": type(error).__name__}), flush=True)
    request()
for command in sys.stdin:
    if command.strip() == "close":
        break
    if pending:
        try:
            remaining = response.length
            while remaining:
                data = response.read(min(65536, remaining))
                if not data:
                    raise http.client.IncompleteRead(b"", remaining)
                remaining -= len(data)
            print(json.dumps({"drained": True}), flush=True)
        except (ConnectionResetError, BrokenPipeError,
                http.client.IncompleteRead, http.client.RemoteDisconnected) as error:
            print(json.dumps({"closed": type(error).__name__}), flush=True)
    else:
        request()
connection.close()
"""
        client = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                self.ns_name,
                sys.executable,
                "-u",
                "-c",
                script,
                json.dumps([port, path, secure, pending]),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(self._stop_client, client)
        return client

    @staticmethod
    def _stop_client(client):
        if client.poll() is None:
            client.terminate()
        try:
            client.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            client.kill()
            client.communicate(timeout=10)

    def _response(self, client, command=None):
        if command:
            client.stdin.write(command + "\n")
            client.stdin.flush()
        ready, _, _ = select.select([client.stdout], [], [], 15)
        self.assertTrue(ready, "persistent client timed out")
        line = client.stdout.readline()
        self.assertTrue(line, f"persistent client exited: {client.poll()}")
        return json.loads(line)

    def _refused(self, port):
        script = """
import errno, socket, sys
try:
    connection = socket.create_connection(("10.10.1.2", int(sys.argv[1])), timeout=3)
except OSError as error:
    if error.errno != errno.ECONNREFUSED:
        raise
    print("ECONNREFUSED")
else:
    connection.close()
    raise RuntimeError("listener still accepts TCP connections")
"""
        process = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                self.ns_name,
                sys.executable,
                "-c",
                script,
                str(port),
            ],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stdout.strip(), b"ECONNREFUSED")

    def _assert_closed(self, response):
        self.assertIn(
            response.get("closed"),
            (
                "ConnectionResetError",
                "BrokenPipeError",
                "IncompleteRead",
                "RemoteDisconnected",
            ),
            response,
        )

    def _empty_default(self):
        reply = self.vapi.http_static_get()
        self.assertEqual(reply.www_root, "")
        self.assertEqual(reply.uri, "")
        for field in (
            "fifo_size",
            "cache_size_limit",
            "max_age",
            "keepalive_timeout",
            "max_body_size",
            "rx_buff_thresh",
        ):
            self.assertEqual(getattr(reply, field), 0, field)

    def _wait_released(self):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            sessions = self.vapi.cli("show http static server sessions")
            listeners = self.vapi.cli("show http static server listeners")
            if "path " not in sessions and "listener " not in listeners:
                return
            time.sleep(0.05)
        self.fail(f"HSS ownership retained: {sessions}\n{listeners}")

    def _listener_states(self):
        output = self.vapi.cli("show http static server listeners")
        states = {
            int(index): int(retiring)
            for index, retiring in re.findall(
                r"^listener (\d+), .* retiring ([01])$", output, re.MULTILINE
            )
        }
        self.assertEqual(len(states), output.count("listener "), output)
        return states, output

    def _hss_apps(self):
        output = self.vapi.cli("show app")
        apps = set(
            re.findall(r"^\s*(\d+)\s+(http_static_server_\d+)", output, re.MULTILINE)
        )
        self.assertEqual(len(apps), output.count("http_static_server_"), output)
        return apps, output

    def _wait_listener_gone(self, index):
        deadline = time.monotonic() + 10
        while True:
            states, output = self._listener_states()
            if index not in states or time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        self.assertNotIn(index, states, output)

    def _wait_destroyed(self, old_app):
        deadline = time.monotonic() + 10
        while True:
            apps, app_output = self._hss_apps()
            states, listener_output = self._listener_states()
            session_output = self.vapi.cli("show http static server sessions")
            cleared = old_app not in apps and len(apps) == 1
            cleared = cleared and list(states.values()) == [0]
            cleared = cleared and "path " not in session_output
            if cleared or time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        self.assertNotIn(old_app, apps, app_output)
        self.assertEqual(len(apps), 1, app_output)
        self.assertEqual(list(states.values()), [0], listener_output)
        self.assertNotIn("path ", session_output, session_output)

    def test_http_static_listener_delete_reuse(self):
        """Accepted sessions retain their listener through delete and readd."""
        self.vapi.cli("http static server")
        self.addCleanup(self.vapi.cli, "http static server disable")
        uri = "http://10.10.1.2:8080"
        self.vapi.cli(f"http static listener add uri {uri} url-handlers")
        client = self._client(8080)
        first = self._response(client)
        self.assertEqual(first["status"], 200)
        states, output = self._listener_states()
        self.assertEqual(list(states.values()), [0], output)
        old_index = next(iter(states))
        self.vapi.cli(f"http static listener del uri {uri}")
        states, output = self._listener_states()
        self.assertEqual(states, {old_index: 1}, output)
        self._refused(8080)
        self.assertEqual(self._response(client, "next")["body"], first["body"])
        self.vapi.cli(f"http static listener add uri {uri} www-root /tmp")
        states, output = self._listener_states()
        self.assertEqual(states.get(old_index), 1, output)
        active_indices = [index for index, retiring in states.items() if not retiring]
        self.assertEqual(len(active_indices), 1, output)
        self.assertNotEqual(active_indices[0], old_index, output)
        self.assertEqual(len(states), 2, output)
        self.assertEqual(self._response(client, "next")["body"], first["body"])
        replacement = self._client(8080)
        self.assertEqual(self._response(replacement)["status"], 404)
        self._stop_client(client)
        self._wait_listener_gone(old_index)
        self._stop_client(replacement)
        self.vapi.cli(f"http static listener del uri {uri}")
        self._wait_released()

    def test_http_static_cached_listener_retirement(self):
        """Persistent cached responses release the original cache ownership."""
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "file.txt"), "w") as output:
                output.write("original listener")
            self.vapi.cli("http static server")
            self.addCleanup(self.vapi.cli, "http static server disable")
            uri = "http://10.10.1.2:8081"
            self.vapi.cli(
                f"http static listener add uri {uri} www-root {root} max-age 123"
            )
            client = self._client(8081, "/file.txt")
            self.assertEqual(self._response(client)["body"], "original listener")
            states, output = self._listener_states()
            self.assertEqual(list(states.values()), [0], output)
            old_index = next(iter(states))
            with open(os.path.join(root, "file.txt"), "w") as output:
                output.write("replacement listener")
            self.vapi.cli(f"http static listener del uri {uri}")
            states, output = self._listener_states()
            self.assertEqual(states, {old_index: 1}, output)
            self.vapi.cli(
                f"http static listener add uri {uri} www-root {root} max-age 456"
            )
            old = self._response(client, "next")
            self.assertEqual(old["body"], "original listener")
            self.assertEqual(old["cache"], "max-age=123")
            replacement = self._client(8081, "/file.txt")
            new = self._response(replacement)
            self.assertEqual(new["body"], "replacement listener")
            self.assertEqual(new["cache"], "max-age=456")
            self._stop_client(client)
            self._stop_client(replacement)
            self.vapi.cli(f"http static listener del uri {uri}")
            self._wait_released()

    def test_http_static_destroy_ownership(self):
        """Disable cleans pending pointer responses before immediate re-enable."""
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "large.txt"), "wb") as output:
                output.write(b"x" * (8 << 20))
            self.addCleanup(self.vapi.cli, "http static server disable")
            for iteration in range(3):
                self.vapi.cli(
                    f"http static server uri http://10.10.1.2:8082 www-root {root}"
                )
                pending = self._client(8082, "/large.txt", pending=True)
                self.assertEqual(self._response(pending)["status"], 200)
                apps, output = self._hss_apps()
                self.assertEqual(len(apps), 1, output)
                old_app = next(iter(apps))
                self.vapi.cli("http static server disable")
                self.vapi.cli(
                    "http static server uri http://10.10.1.2:8082 url-handlers"
                )
                self._wait_destroyed(old_app)
                active = self._client(8082)
                self.assertEqual(self._response(active)["status"], 200)
                self._assert_closed(self._response(pending, "drain"))
                self._stop_client(pending)
                self._stop_client(active)
                self.vapi.cli("http static listener del uri http://10.10.1.2:8082")
                self._wait_released()
                self.vapi.cli("http static server disable")

    def test_http_static_default_get_states(self):
        """Get reports only the live default listener, including URL-only roots."""
        self._empty_default()
        self.vapi.cli("http static server")
        self.addCleanup(self.vapi.cli, "http static server disable")
        self._empty_default()
        for config in ("www-root /tmp", "url-handlers"):
            self.vapi.cli(
                f"http static listener add uri http://10.10.1.2:8083 {config}"
            )
            self._empty_default()
            self.vapi.cli("http static listener del uri http://10.10.1.2:8083")
        self.vapi.cli("http static server disable")
        self.vapi.cli("http static server uri tcp://10.10.1.2:8083 url-handlers")
        reply = self.vapi.http_static_get()
        self.assertEqual(reply.www_root, "")
        self.assertEqual(reply.uri, "http://10.10.1.2:8083")
        self.vapi.cli("http static listener del uri tcp://10.10.1.2:8083")
        self._empty_default()
        self.vapi.cli("http static server disable")
        self.vapi.cli(
            "http static server uri http://10.10.1.2:8083 www-root /tmp cache-size 2m"
        )
        self.vapi.cli("http static listener add uri http://10.10.1.2:8084 url-handlers")
        reply = self.vapi.http_static_get()
        self.assertEqual(reply.www_root, "/tmp")
        self.assertEqual(reply.cache_size_limit, 2 << 20)
        self.vapi.cli("http static listener del uri http://10.10.1.2:8083")
        self._empty_default()
        self.vapi.cli("http static listener del uri http://10.10.1.2:8084")
        self.vapi.cli("http static listener add uri http://10.10.1.2:8083 url-handlers")
        self._empty_default()
        self.vapi.cli("http static server disable")
        self.vapi.cli("http static server uri http://10.10.1.2:8083 www-root /tmp")
        self.assertEqual(self.vapi.http_static_get().www_root, "/tmp")

    def test_http_static_listener_uri_identity(self):
        """Same parsed URI deletes TCP/HTTP and secure listeners after readd."""
        self.vapi.cli("http static server")
        self.addCleanup(self.vapi.cli, "http static server disable")
        for protocol in ("tcp", "http", "tls", "https"):
            with self.subTest(protocol=protocol):
                if (
                    protocol in ("tls", "https")
                    and "tlsopenssl" in config.excluded_plugins
                ):
                    self.skipTest(
                        f"{protocol} identity: tlsopenssl explicitly excluded"
                    )
                uri = f"{protocol}://10.10.1.2:8085"
                for repeat in range(2):
                    self.vapi.cli(
                        f"http static listener add uri {uri} url-handlers http1-only"
                    )
                    client = self._client(8085, secure=protocol in ("tls", "https"))
                    self.assertEqual(self._response(client)["status"], 200)
                    self._stop_client(client)
                    reply = self.vapi.cli_return_response(
                        f"http static listener del uri {uri}"
                    )
                    self.assertEqual(reply.retval, 0, reply.reply)
                    self._refused(8085)

    def test_http_static_listener_ipv6_identity(self):
        """IPv6 identities survive parsing, normalization and repeated add/delete."""
        self.vapi.cli("http static server")
        self.addCleanup(self.vapi.cli, "http static server disable")
        for protocol in ("tcp", "http"):
            uri = f"{protocol}://[::]:8086"
            for repeat in range(2):
                self.vapi.cli(f"http static listener add uri {uri} url-handlers")
                self.assertIn(
                    "8086", self.vapi.cli("show http static server listeners")
                )
                reply = self.vapi.cli_return_response(
                    f"http static listener del uri {uri}"
                )
                self.assertEqual(reply.retval, 0, reply.reply)
                self._wait_released()
        self.vapi.cli("http static server disable")
        self.vapi.cli("http static server uri tcp://[::]:8086 url-handlers")
        self.assertEqual(self.vapi.http_static_get().uri, "http://[::]:8086")
        reply = self.vapi.cli_return_response(
            "http static listener del uri tcp://[::]:8086"
        )
        self.assertEqual(reply.retval, 0, reply.reply)
        self._empty_default()

    @unittest.skipIf("quic" in config.excluded_plugins, "QUIC plugin is excluded")
    def test_http_static_listener_http3_identity(self):
        """The original QUIC URI deletes the actual HTTP3 lower listener."""
        self.vapi.cli("http static server")
        self.addCleanup(self.vapi.cli, "http static server disable")
        uri = "quic://10.10.1.2:8087"
        command = "show session listeners quic verbose 2"
        original = self.vapi.cli(command).count("[Q]")
        for repeat in range(2):
            self.vapi.cli(f"http static listener add uri {uri} url-handlers http3")
            listeners = self.vapi.cli(command)
            self.assertEqual(listeners.count("[Q]"), original + 1, listeners)
            self.assertIn("h3", listeners)
            reply = self.vapi.cli_return_response(
                f"http static listener del uri {uri} http3"
            )
            self.assertEqual(reply.retval, 0, reply.reply)
            self._wait_released()
            self.assertEqual(self.vapi.cli(command).count("[Q]"), original)


class TestHttpStaticCliWorker(TestHttpStaticCli):
    """Exercise HSS listener ownership with a worker thread."""

    vpp_worker_count = 1


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
