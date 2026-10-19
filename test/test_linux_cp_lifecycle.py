#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import os
import subprocess
import unittest

from config import config
from framework import VppTestCase
from asfframework import VppTestRunner
from test_linux_cp import TestLinuxCPNetNSBase
from vpp_papi import VppEnum
from vpp_qemu_utils import (
    create_namespace,
    delete_all_namespaces,
    interface_exists,
)


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
@unittest.skipIf("linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests")
class TestLinuxCPLifecycle(VppTestCase):
    """Linux CP API pair and namespace lifecycle"""

    extra_vpp_plugin_config = [
        "plugin linux_cp_plugin.so { enable }",
        "plugin linux_nl_plugin.so { disable }",
    ]

    def setUp(self):
        super().setUp()
        self.ns_history = os.path.join(self.tempdir, "lifecycle_namespaces.txt")
        self.addCleanup(delete_all_namespaces, self.ns_history)
        self.ns_name = create_namespace(self.ns_history)
        self.other_ns = create_namespace(self.ns_history)
        self.addCleanup(self.vapi.lcp_default_ns_set, netns="")
        self.addCleanup(self._delete_pairs)
        self.vapi.lcp_default_ns_set(netns=self.ns_name)

    def _pairs(self):
        return {
            pair.phy_sw_if_index: pair
            for pair in self.vapi.vpp.details_iter(self.vapi.lcp_itf_pair_get)
        }

    def _delete_pair(self, sw_if_index):
        return self.vapi.lcp_itf_pair_add_del_v3(is_add=False, sw_if_index=sw_if_index)

    def _delete_pairs(self):
        for sw_if_index in reversed(list(self._pairs())):
            self._delete_pair(sw_if_index)

    def _add_pair(self, sw_if_index, name, host_type=0, netns="", version=3):
        method = (
            self.vapi.lcp_itf_pair_add_del
            if version == 1
            else getattr(self.vapi, f"lcp_itf_pair_add_del_v{version}")
        )
        return method(
            is_add=True,
            sw_if_index=sw_if_index,
            host_if_name=name,
            host_if_type=host_type,
            netns=netns,
        )

    def _fd_count(self):
        return len(os.listdir(f"/proc/{self.vpp.pid}/fd"))

    def _namespace_fd_count(self, namespace):
        target = os.stat(f"/var/run/netns/{namespace}")
        count = 0
        for fd in os.listdir(f"/proc/{self.vpp.pid}/fd"):
            try:
                opened = os.stat(f"/proc/{self.vpp.pid}/fd/{fd}")
            except FileNotFoundError:
                continue
            count += (opened.st_dev, opened.st_ino) == (target.st_dev, target.st_ino)
        return count

    def _ip(self, *args):
        subprocess.run(
            ["ip", "-n", self.ns_name, *args],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_default_namespace_resources(self):
        """Repeated namespace replacement and clear preserve fd ownership"""
        self.vapi.lcp_default_ns_set(netns="")
        baseline = {
            ns: self._namespace_fd_count(ns) for ns in (self.ns_name, self.other_ns)
        }
        for _ in range(16):
            for ns in (self.ns_name, self.ns_name, self.other_ns):
                self.vapi.lcp_default_ns_set(netns=ns)
                self.assertEqual(self.vapi.lcp_default_ns_get().netns, ns)
                for candidate in baseline:
                    self.assertEqual(
                        self._namespace_fd_count(candidate),
                        baseline[candidate] + int(candidate == ns),
                    )
            self.vapi.lcp_default_ns_set(netns="")
            self.vapi.lcp_default_ns_set(netns="")
            self.assertEqual(self.vapi.lcp_default_ns_get().netns, "")
            for ns in baseline:
                self.assertEqual(self._namespace_fd_count(ns), baseline[ns])

    def test_default_namespace_failure(self):
        """Failed namespace open retains the configured namespace and fd"""
        missing = f"lcp-missing-{self.vpp.pid}"
        self.assertFalse(os.path.exists(f"/var/run/netns/{missing}"))
        before = self._namespace_fd_count(self.ns_name)
        for _ in range(16):
            with self.vapi.assert_negative_api_retval():
                self.vapi.lcp_default_ns_set(netns=missing)
            self.assertEqual(self.vapi.lcp_default_ns_get().netns, self.ns_name)
            self.assertEqual(self._namespace_fd_count(self.ns_name), before)
        self.create_pg_interfaces(range(1))
        self._add_pair(self.pg0.sw_if_index, "hnskeep")
        self.assertTrue(interface_exists(self.ns_name, "hnskeep"))

    def test_pair_replace_resend(self):
        """All public add API versions retain matching TAP and TUN pairs"""
        self.create_pg_interfaces(range(3))
        keep, omit, new = [pg.sw_if_index for pg in self.pg_interfaces]
        for version in (1, 2, 3):
            for host_type in (0, 1):
                with self.subTest(version=version, host_type=host_type):
                    self._add_pair(keep, "hkeep", host_type)
                    self._add_pair(omit, "homit", host_type)
                    original = self._pairs()[keep]
                    with self.vapi.assert_known_api_retval([-81]):
                        self._add_pair(keep, "hkeep", host_type, version=version)
                    self.vapi.lcp_itf_pair_replace_begin()
                    for name, kind, ns in (
                        ("hrenamed", host_type, ""),
                        ("hkeep", 1 - host_type, ""),
                        ("hkeep", host_type, self.other_ns),
                    ):
                        with self.vapi.assert_known_api_retval([-81]):
                            self._add_pair(keep, name, kind, ns, version)
                    reply = self._add_pair(
                        keep, "hkeep", host_type, self.ns_name, version
                    )
                    if version >= 2:
                        self.assertEqual(
                            reply.host_sw_if_index, original.host_sw_if_index
                        )
                    if version == 3:
                        self.assertEqual(reply.vif_index, original.vif_index)
                    with self.vapi.assert_known_api_retval([-81]):
                        self._add_pair(keep, "hkeep", host_type, version=version)
                    self._add_pair(new, "hnew", host_type)
                    self.vapi.lcp_itf_pair_replace_end()
                    pairs = self._pairs()
                    self.assertEqual(set(pairs), {keep, new})
                    for field in (
                        "host_sw_if_index",
                        "vif_index",
                        "host_if_name",
                        "host_if_type",
                        "netns",
                    ):
                        self.assertEqual(
                            getattr(pairs[keep], field), getattr(original, field)
                        )
                    self.assertTrue(interface_exists(self.ns_name, "hkeep"))
                    self.assertTrue(interface_exists(self.ns_name, "hnew"))
                    self.assertFalse(interface_exists(self.ns_name, "homit"))
                    self.vapi.lcp_itf_pair_replace_begin()
                    self._add_pair(keep, "hkeep", host_type, version=version)
                    self._add_pair(new, "hnew", host_type, version=version)
                    self.vapi.lcp_itf_pair_replace_end()
                    self.assertEqual(set(self._pairs()), {keep, new})
                    self.vapi.lcp_itf_pair_replace_begin()
                    self.vapi.lcp_itf_pair_replace_end()
                    self.assertEqual(self._pairs(), {})

    def test_pair_flags_pool_reuse(self):
        """New pairs never inherit stale flags from a deleted pool slot"""
        self.create_pg_interfaces(range(2))
        old, new = [pg.sw_if_index for pg in self.pg_interfaces]
        for host_type in (0, 1):
            self._add_pair(old, "hold", host_type)
            self.vapi.lcp_itf_pair_replace_begin()
            self._delete_pair(old)
            self._add_pair(new, "hnew", host_type)
            self.vapi.lcp_itf_pair_replace_end()
            self.assertEqual(set(self._pairs()), {new})
            self.assertTrue(interface_exists(self.ns_name, "hnew"))
            self.vapi.lcp_itf_pair_replace_begin()
            self.vapi.lcp_itf_pair_replace_end()
            self._add_pair(old, "hold", host_type)
            self.vapi.lcp_itf_pair_replace_end()
            self.assertEqual(set(self._pairs()), {old})
            self._delete_pair(old)

    def test_vlan_resources(self):
        """VLAN success and kernel rejection cycles release socket fds"""
        self.create_pg_interfaces(range(1))
        parent = self.pg0.sw_if_index
        self._add_pair(parent, "hvlan")
        flags = VppEnum.vl_api_sub_if_flags_t
        for dot1ad in (False, True):
            sub_flags = (
                flags.SUB_IF_API_FLAG_ONE_TAG | flags.SUB_IF_API_FLAG_EXACT_MATCH
            )
            if dot1ad:
                sub_flags |= flags.SUB_IF_API_FLAG_DOT1AD
            sub = self.vapi.create_subif(
                sw_if_index=parent,
                sub_id=100,
                outer_vlan_id=100,
                sub_if_flags=sub_flags,
            ).sw_if_index
            try:
                baseline = self._fd_count()
                self._ip(
                    "link",
                    "add",
                    "link",
                    "hvlan",
                    "name",
                    "hblock",
                    "type",
                    "vlan",
                    "protocol",
                    "802.1ad" if dot1ad else "802.1Q",
                    "id",
                    "100",
                )
                for _ in range(16):
                    with self.vapi.assert_negative_api_retval():
                        self._add_pair(sub, "hvlan100")
                    self.assertNotIn(sub, self._pairs())
                    self.assertFalse(interface_exists(self.ns_name, "hvlan100"))
                    self.assertEqual(self._fd_count(), baseline)
                self._ip("link", "del", "hblock")
                for missing_link in (False, True):
                    for _ in range(16):
                        reply = self._add_pair(sub, "hvlan100")
                        pair = self._pairs()[sub]
                        self.assertEqual(reply.host_sw_if_index, pair.host_sw_if_index)
                        self.assertEqual(reply.vif_index, pair.vif_index)
                        self.assertTrue(interface_exists(self.ns_name, "hvlan100"))
                        if missing_link:
                            self._ip("link", "del", "hvlan100")
                        self._delete_pair(sub)
                        self.assertNotIn(sub, self._pairs())
                        self.assertFalse(interface_exists(self.ns_name, "hvlan100"))
                        self.assertEqual(self._fd_count(), baseline)
            finally:
                if sub in self._pairs():
                    self._delete_pair(sub)
                self.vapi.delete_subif(sw_if_index=sub)


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
@unittest.skipIf("linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests")
class TestLinuxCPNamespaceOwnership(TestLinuxCPNetNSBase):
    """Linux CP namespace-scoped interface index ownership"""

    def test_equal_ifindex_namespace_delete(self):
        """Deleting another namespace's pair preserves Linux address updates"""
        self.create_pg_interfaces(range(2))
        other_ns = create_namespace(self.ns_history_name)
        self.vapi.cli("lcp lcp-auto-subint off")
        parents = []
        subinterfaces = []
        paired_subinterfaces = []
        try:
            for pg, ns, host in zip(
                self.pg_interfaces,
                (self.ns_name, other_ns),
                ("howner", "hother"),
            ):
                self.vapi.lcp_itf_pair_add_del_v3(
                    is_add=True,
                    sw_if_index=pg.sw_if_index,
                    host_if_name=host,
                    netns=ns,
                )
                parents.append(pg.sw_if_index)
                sub = self.vapi.create_vlan_subif(
                    sw_if_index=pg.sw_if_index, vlan_id=100
                ).sw_if_index
                subinterfaces.append(sub)
                subprocess.run(
                    [
                        "ip",
                        "-n",
                        ns,
                        "link",
                        "add",
                        "link",
                        host,
                        "name",
                        "hshared",
                        "index",
                        "5000",
                        "type",
                        "vlan",
                        "id",
                        "100",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                reply = self.vapi.lcp_itf_pair_add_del_v3(
                    is_add=True,
                    sw_if_index=sub,
                    host_if_name="hshared",
                    netns=ns,
                )
                paired_subinterfaces.append(sub)
                self.assertEqual(reply.vif_index, 5000)
            owner, other = subinterfaces
            pairs = {
                pair.phy_sw_if_index: pair
                for pair in self.vapi.vpp.details_iter(self.vapi.lcp_itf_pair_get)
            }
            self.assertEqual(pairs[owner].vif_index, pairs[other].vif_index)
            self.assertNotEqual(
                pairs[owner].host_sw_if_index, pairs[other].host_sw_if_index
            )
            for prefix in ("198.18.10.1/24", "198.18.11.1/24"):
                subprocess.run(
                    [
                        "ip",
                        "-n",
                        self.ns_name,
                        "address",
                        "add",
                        prefix,
                        "dev",
                        "hshared",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.poll_for(
                    f"owner receives {prefix}",
                    lambda: prefix
                    in {
                        str(address.prefix)
                        for address in self.vapi.ip_address_dump(
                            sw_if_index=owner, is_ipv6=False
                        )
                    },
                    True,
                )
                if prefix == "198.18.10.1/24":
                    self.vapi.lcp_itf_pair_add_del_v3(is_add=False, sw_if_index=other)
                    paired_subinterfaces.remove(other)
                    self.assertTrue(interface_exists(self.ns_name, "hshared"))
                    self.assertFalse(interface_exists(other_ns, "hshared"))
            remaining = {
                pair.phy_sw_if_index
                for pair in self.vapi.vpp.details_iter(self.vapi.lcp_itf_pair_get)
            }
            self.assertIn(owner, remaining)
            self.assertNotIn(other, remaining)
        finally:
            for sub in reversed(paired_subinterfaces):
                self.vapi.lcp_itf_pair_add_del_v3(is_add=False, sw_if_index=sub)
            for sub in reversed(subinterfaces):
                self.vapi.delete_subif(sw_if_index=sub)
            for parent in reversed(parents):
                self.vapi.lcp_itf_pair_add_del_v3(is_add=False, sw_if_index=parent)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
