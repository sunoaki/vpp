#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import os
import re
import socket
import subprocess
import unittest
from pathlib import Path

from config import config
from test_linux_cp import TestLinuxCPNetNSBase
from vpp_ip_route import find_route
from vpp_qemu_utils import add_namespace_route, del_namespace_route


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
@unittest.skipIf("linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests")
class TestLinuxCPNetlinkSocketOwnership(TestLinuxCPNetNSBase):
    """Pair creation while netlink recovery owns the notification socket."""

    extra_vpp_plugin_config = TestLinuxCPNetNSBase.extra_vpp_plugin_config + [
        "plugin",
        "linux_cp_unittest_plugin.so",
        "{",
        "enable",
        "}",
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_loopback_interfaces(2)
        cls.vapi.cli(f"lcp create loop0 host-if hloop0 netns {cls.ns_name}")
        cls.lo_interfaces[0].admin_up()
        cls.lo_interfaces[1].admin_up()

    def _netlink_stats(self):
        fields = {}
        for line in self.vapi.cli("show lcp netlink").splitlines():
            key, separator, value = line.partition(":")
            if separator:
                fields[key.strip()] = value.strip()
        return fields

    def _socket_ownership(self):
        process = Path(f"/proc/{self.vpp.pid}")
        sockets = {}
        epoll = []
        for descriptor in (process / "fd").iterdir():
            try:
                target = os.readlink(descriptor)
            except FileNotFoundError:
                continue
            match = re.fullmatch(r"socket:\[(\d+)\]", target)
            if match:
                sockets[int(match[1])] = int(descriptor.name)
            elif target == "anon_inode:[eventpoll]":
                info = (process / "fdinfo" / descriptor.name).read_text()
                epoll.extend(
                    int(match.group(1))
                    for match in re.finditer(r"^tfd:\s+(\d+)\s", info, re.MULTILINE)
                )

        table = subprocess.run(
            ["ip", "netns", "exec", self.ns_name, "cat", "/proc/net/netlink"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        netlink = {}
        for line in table.splitlines()[1:]:
            columns = line.split()
            inode = int(columns[-1])
            if int(columns[1]) == socket.NETLINK_ROUTE and inode in sockets:
                netlink[sockets[inode]] = (inode, int(columns[3], 16))
        snapshot = {"netlink": netlink, "epoll": epoll}
        self.logger.info("Netlink socket ownership: %s", snapshot)
        return snapshot

    def _check_single_notification_socket(self, stats, snapshot):
        descriptor = int(stats["Socket"])
        self.assertGreaterEqual(descriptor, 0, stats)
        self.assertEqual(set(snapshot["netlink"]), {descriptor}, snapshot)
        self.assertNotEqual(snapshot["netlink"][descriptor][1], 0, snapshot)
        self.assertEqual(snapshot["epoll"].count(descriptor), 1, snapshot)
        return snapshot["netlink"][descriptor][0]

    def _check_route_updates(self):
        prefix = "192.168.61.0/24"

        def present():
            return find_route(self, "192.168.61.0", 24)

        self.assertFalse(present(), prefix)
        try:
            add_namespace_route(self.ns_name, prefix, route_type="blackhole")
            self.poll_for("route notification reaches VPP", present, True)
        finally:
            del_namespace_route(self.ns_name, prefix, check=False)
            self.poll_for("route withdrawal reaches VPP", present, False)

    def test_pair_add_during_netlink_recovery(self):
        """Real pair creation cannot open a socket owned by paused recovery"""
        before = self._netlink_stats()
        self.assertEqual(before["State"], "notification", before)
        baseline = self._socket_ownership()
        old_inode = self._check_single_notification_socket(before, baseline)
        attempts = int(before["Synchronization attempts"])
        completed = int(before["Synchronization completed"])
        pair_added = False
        try:
            self.vapi.cli("test lcp netlink-sync-pause on")
            output = self.vapi.cli("test lcp netlink-error")
            self.assertIn("netlink-error: callback", output)

            def paused():
                stats = self._netlink_stats()
                return (
                    stats["State"] == "synchronizing"
                    and stats["Socket"] == "-1"
                    and int(stats["Synchronization attempts"]) > attempts
                )

            self.poll_for(
                "recovery closed notification socket", paused, True, timeout=20
            )
            paused_before = self._netlink_stats()
            self.assertEqual(self._socket_ownership()["netlink"], {})
            self.vapi.cli(f"lcp create loop1 host-if hloop1 netns {self.ns_name}")
            pair_added = True
            pairs = list(self.vapi.vpp.details_iter(self.vapi.lcp_itf_pair_get))
            self.assertIn(
                self.lo_interfaces[1].sw_if_index,
                [pair.phy_sw_if_index for pair in pairs],
            )
            paused_after = self._netlink_stats()
            self.logger.info(
                "Pair created during recovery: before=%s after=%s",
                paused_before,
                paused_after,
            )
            self.assertEqual(paused_after["State"], "synchronizing", paused_after)
            self.assertEqual(paused_after["Socket"], "-1", paused_after)
            self.assertEqual(
                paused_after["Synchronization attempts"],
                paused_before["Synchronization attempts"],
            )
            self.assertEqual(
                int(paused_after["Synchronization completed"]), completed, paused_after
            )
            self.assertEqual(self._socket_ownership()["netlink"], {})
        finally:
            try:
                self.vapi.cli("test lcp netlink-sync-pause off")
            finally:
                if pair_added:
                    self.addCleanup(self.vapi.cli, "lcp delete loop1")

        def recovered():
            stats = self._netlink_stats()
            return (
                stats["State"] == "notification"
                and int(stats["Synchronization completed"]) > completed
            )

        self.poll_for("netlink recovery completed", recovered, True, timeout=20)
        after = self._netlink_stats()
        current = self._socket_ownership()
        new_inode = self._check_single_notification_socket(after, current)
        self.assertNotEqual(old_inode, new_inode, current)
        self._check_route_updates()


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
@unittest.skipIf("linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests")
class TestLinuxCPNetlinkDumpCompletion(TestLinuxCPNetNSBase):
    """Kernel dump status reaches the real receiver and recovery process."""

    extra_vpp_plugin_config = TestLinuxCPNetlinkSocketOwnership.extra_vpp_plugin_config

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_loopback_interfaces(1)
        cls.vapi.cli(f"lcp create loop0 host-if hloop0 netns {cls.ns_name}")
        cls.lo_interfaces[0].admin_up()

    def _stats(self):
        fields = {}
        for line in self.vapi.cli("show lcp netlink").splitlines():
            key, separator, value = line.partition(":")
            if separator:
                fields[key.strip()] = value.strip()
        return fields

    def _check_case(self, sock_type, scenario, expect_failure):
        before = self._stats()
        self.assertEqual(before["State"], "notification", before)
        completed = int(before["Synchronization completed"])
        failed = int(before["Synchronization failed"])
        try:
            self.vapi.cli(f"test lcp netlink-dump {sock_type} {scenario}")
            self.vapi.cli("test lcp netlink-error")

            def finished():
                stats = self._stats()
                if expect_failure:
                    return (
                        int(stats["Synchronization failed"]) > failed
                        and stats["State"] == "synchronizing"
                        and stats["Socket"] == "-1"
                    )
                return (
                    int(stats["Synchronization completed"]) > completed
                    and stats["State"] == "notification"
                )

            self.poll_for("injected dump attempt finished", finished, True, timeout=20)
            stats = self._stats()
            self.logger.info(
                "Dump type=%s scenario=%s before=%s after=%s",
                sock_type,
                scenario,
                before,
                stats,
            )
            self.assertEqual(stats["Test dump injected"], "1", stats)
            if expect_failure:
                self.assertLess(int(stats["Test dump result"]), 0, stats)
                self.assertEqual(
                    int(stats["Synchronization failed"]), failed + 1, stats
                )
                self.assertEqual(
                    int(stats["Synchronization completed"]), completed, stats
                )
                self.assertEqual(stats["Test dump sync ends"], "0", stats)
            else:
                self.assertGreater(int(stats["Test dump result"]), 0, stats)
                self.assertEqual(int(stats["Synchronization failed"]), failed, stats)
                self.assertEqual(int(stats["Synchronization completed"]), completed + 1)
                self.assertEqual(stats["Test dump sync ends"], "4", stats)
        finally:
            self.vapi.cli("test lcp netlink-sync-pause off")

        if expect_failure:

            def recovered():
                stats = self._stats()
                return (
                    stats["State"] == "notification"
                    and int(stats["Synchronization completed"]) == completed + 1
                )

            self.poll_for("clean retry completed", recovered, True, timeout=20)
            stats = self._stats()
            self.assertEqual(int(stats["Synchronization failed"]), failed + 1, stats)
            self.assertEqual(stats["Test dump sync ends"], "4", stats)

    def test_dump_completion_errors(self):
        """Interrupted and failed dumps never finish synchronization"""
        self._check_case(0, 1, True)
        for sock_type in range(4):
            for scenario in range(2, 6):
                with self.subTest(sock_type=sock_type, scenario=scenario):
                    self._check_case(sock_type, scenario, True)

    def test_dump_completion_success(self):
        """Zero dump status accepts optional extended ACK data"""
        for sock_type in range(4):
            for scenario in (6, 7):
                with self.subTest(sock_type=sock_type, scenario=scenario):
                    self._check_case(sock_type, scenario, False)
