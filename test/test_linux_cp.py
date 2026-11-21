#!/usr/bin/env python3

import unittest
import os
import socket
import subprocess
from ipaddress import ip_address, ip_interface

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6, Raw
from scapy.layers.l2 import Ether, ARP, Dot3, LLC, GRE
from scapy.contrib.lacp import LACP
from scapy.contrib.lldp import (
    LLDPDUChassisID,
    LLDPDUPortID,
    LLDPDUTimeToLive,
    LLDPDUEndOfLLDPDU,
    LLDPDU,
)
from scapy.contrib.isis import ISIS_CommonHdr, ISIS_L1_LAN_Hello
from scapy.data import IP_PROTOS

from util import reassemble4
from host_interface import HostInterface
from vpp_object import VppObject
from framework import VppTestCase
from asfframework import (
    VppTestRunner,
    get_testcase_dirname,
)
from vpp_ipip_tun_interface import VppIpIpTunInterface
from vpp_papi_provider import CliFailedCommandError
from template_ipsec import (
    TemplateIpsec,
    IpsecTun4,
)
from template_ipsec import (
    TemplateIpsec,
    IpsecTun4,
)
from test_ipsec_tun_if_esp import TemplateIpsecItf4
from config import config
from vpp_ip_route import (
    FibPathType,
    VppIpRoute,
    VppIpTable,
    VppRoutePath,
    find_route,
)
from vpp_neighbor import VppNeighbor, find_nbr
from vpp_gre_interface import VppGreInterface
from vpp_qemu_utils import (
    add_namespace_route,
    add_namespace_multipath_route,
    del_namespace_route,
    add_namespace_address,
    del_namespace_address,
    add_namespace_neighbor,
    del_namespace_neighbor,
    NextHop,
    create_namespace,
    delete_all_namespaces,
    set_interface_up,
    set_interface_down,
    get_interface_addresses,
    get_interface_info,
    interface_exists,
    is_interface_up,
    get_interface_mtu,
)


class VppLcpPair(VppObject):
    def __init__(self, test, phy, host):
        self._test = test
        self.phy = phy
        self.host = host

    def add_vpp_config(self):
        self._test.vapi.cli("test lcp add phy %s host %s" % (self.phy, self.host))
        self._test.registry.register(self, self._test.logger)
        return self

    def remove_vpp_config(self):
        self._test.vapi.cli("test lcp del phy %s host %s" % (self.phy, self.host))

    def object_id(self):
        return "lcp:%d:%d" % (self.phy.sw_if_index, self.host.sw_if_index)

    def query_vpp_config(self):
        pairs = list(self._test.vapi.vpp.details_iter(self._test.vapi.lcp_itf_pair_get))

        for p in pairs:
            if (
                p.phy_sw_if_index == self.phy.sw_if_index
                and p.host_sw_if_index == self.host.sw_if_index
            ):
                return True
        return False


@unittest.skipIf("linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests")
class TestLinuxCP(VppTestCase):
    """Linux Control Plane"""

    extra_vpp_plugin_config = [
        "plugin",
        "linux_cp_plugin.so",
        "{",
        "enable",
        "}",
        "plugin",
        "linux_cp_unittest_plugin.so",
        "{",
        "enable",
        "}",
    ]

    @classmethod
    def setUpClass(cls):
        super(TestLinuxCP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestLinuxCP, cls).tearDownClass()

    def setUp(self):
        super(TestLinuxCP, self).setUp()

        # create 4 pg interfaces so we can create two pairs
        self.create_pg_interfaces(range(4))

        # create on ip4 and one ip6 pg tun
        self.pg_interfaces += self.create_pg_ip4_interfaces(range(4, 5))
        self.pg_interfaces += self.create_pg_ip6_interfaces(range(5, 6))

        for i in self.pg_interfaces:
            i.admin_up()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.admin_down()
        super(TestLinuxCP, self).tearDown()

    def test_linux_cp_tap(self):
        """Linux CP TAP"""

        #
        # Setup
        #

        arp_opts = {"who-has": 1, "is-at": 2}

        # create two pairs, wihch a bunch of hots on the phys
        hosts = [self.pg0, self.pg1]
        phys = [self.pg2, self.pg3]
        N_HOSTS = 4

        for phy in phys:
            phy.config_ip4()
            phy.generate_remote_hosts(4)
            phy.configure_ipv4_neighbors()

        pair1 = VppLcpPair(self, phys[0], hosts[0]).add_vpp_config()
        pair2 = VppLcpPair(self, phys[1], hosts[1]).add_vpp_config()

        self.logger.info(self.vapi.cli("sh lcp adj verbose"))
        self.logger.info(self.vapi.cli("sh lcp"))

        #
        # Traffic Tests
        #

        # hosts to phys
        for phy, host in zip(phys, hosts):
            for j in range(N_HOSTS):
                p = (
                    Ether(src=phy.local_mac, dst=host.local_mac)
                    / IP(src=phy.local_ip4, dst=phy.remote_hosts[j].ip4)
                    / UDP(sport=1234, dport=1234)
                    / Raw()
                )

                rxs = self.send_and_expect(host, [p], phy)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

                # ARPs x-connect to phy
                p = Ether(dst="ff:ff:ff:ff:ff:ff", src=phy.remote_hosts[j].mac) / ARP(
                    op="who-has",
                    hwdst=phy.remote_hosts[j].mac,
                    hwsrc=phy.local_mac,
                    psrc=phy.local_ip4,
                    pdst=phy.remote_hosts[j].ip4,
                )

                rxs = self.send_and_expect(host, [p], phy)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

        # phy to host
        for phy, host in zip(phys, hosts):
            for j in range(N_HOSTS):
                p = (
                    Ether(dst=phy.local_mac, src=phy.remote_hosts[j].mac)
                    / IP(dst=phy.local_ip4, src=phy.remote_hosts[j].ip4)
                    / UDP(sport=1234, dport=1234)
                    / Raw()
                )

                rxs = self.send_and_expect(phy, [p], host)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

                # ARPs rx'd on the phy are sent to the host
                p = Ether(dst="ff:ff:ff:ff:ff:ff", src=phy.remote_hosts[j].mac) / ARP(
                    op="is-at",
                    hwsrc=phy.remote_hosts[j].mac,
                    hwdst=phy.local_mac,
                    pdst=phy.local_ip4,
                    psrc=phy.remote_hosts[j].ip4,
                )

                rxs = self.send_and_expect(phy, [p], host)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

        # cleanup
        for phy in phys:
            phy.unconfig_ip4()

    def test_linux_cp_sync_unnumbered(self):
        """Linux CP Sync Unnumbered"""

        # default should be enabled
        reply = self.vapi.lcp_sync_unnumbered_get()
        self.assertTrue(reply.is_enable)

        # disable it
        self.vapi.lcp_sync_unnumbered_set(is_enable=False)

        # verify it is now disabled
        reply = self.vapi.lcp_sync_unnumbered_get()
        self.assertFalse(reply.is_enable)

        # re-enable for clean state
        self.vapi.lcp_sync_unnumbered_set(is_enable=True)

    def test_linux_cp_tun(self):
        """Linux CP TUN"""

        #
        # Setup
        #
        N_PKTS = 31

        # create two pairs, wihch a bunch of hots on the phys
        hosts = [self.pg4, self.pg5]
        phy = self.pg2

        phy.config_ip4()
        phy.config_ip6()
        phy.resolve_arp()
        phy.resolve_ndp()

        tun4 = VppIpIpTunInterface(
            self, phy, phy.local_ip4, phy.remote_ip4
        ).add_vpp_config()
        tun6 = VppIpIpTunInterface(
            self, phy, phy.local_ip6, phy.remote_ip6
        ).add_vpp_config()
        tuns = [tun4, tun6]

        tun4.admin_up()
        tun4.config_ip4()
        tun6.admin_up()
        tun6.config_ip6()

        pair1 = VppLcpPair(self, tuns[0], hosts[0]).add_vpp_config()
        pair2 = VppLcpPair(self, tuns[1], hosts[1]).add_vpp_config()

        self.logger.info(self.vapi.cli("sh lcp adj verbose"))
        self.logger.info(self.vapi.cli("sh lcp"))
        self.logger.info(self.vapi.cli("sh ip punt redirect"))

        #
        # Traffic Tests
        #

        # host to phy for v4
        p = IP(src=tun4.local_ip4, dst="2.2.2.2") / UDP(sport=1234, dport=1234) / Raw()

        rxs = self.send_and_expect(self.pg4, p * N_PKTS, phy)

        # verify inner packet is unchanged and has the tunnel encap
        for rx in rxs:
            self.assertEqual(rx[Ether].dst, phy.remote_mac)
            self.assertEqual(rx[IP].dst, phy.remote_ip4)
            self.assertEqual(rx[IP].src, phy.local_ip4)
            inner = IP(bytes(rx[IP].payload))
            self.assertEqual(inner.src, tun4.local_ip4)
            self.assertEqual(inner.dst, "2.2.2.2")

        # host to phy for v6
        p = IPv6(src=tun6.local_ip6, dst="2::2") / UDP(sport=1234, dport=1234) / Raw()

        rxs = self.send_and_expect(self.pg5, p * N_PKTS, phy)

        # verify inner packet is unchanged and has the tunnel encap
        for rx in rxs:
            self.assertEqual(rx[IPv6].dst, phy.remote_ip6)
            self.assertEqual(rx[IPv6].src, phy.local_ip6)
            inner = IPv6(bytes(rx[IPv6].payload))
            self.assertEqual(inner.src, tun6.local_ip6)
            self.assertEqual(inner.dst, "2::2")

        # phy to host v4
        p = (
            Ether(dst=phy.local_mac, src=phy.remote_mac)
            / IP(dst=phy.local_ip4, src=phy.remote_ip4)
            / IP(dst=tun4.local_ip4, src=tun4.remote_ip4)
            / UDP(sport=1234, dport=1234)
            / Raw()
        )

        rxs = self.send_and_expect(phy, p * N_PKTS, self.pg4)
        for rx in rxs:
            rx = IP(bytes(rx))
            self.assertEqual(rx[IP].dst, tun4.local_ip4)
            self.assertEqual(rx[IP].src, tun4.remote_ip4)

        # phy to host v6
        p = (
            Ether(dst=phy.local_mac, src=phy.remote_mac)
            / IPv6(dst=phy.local_ip6, src=phy.remote_ip6)
            / IPv6(dst=tun6.local_ip6, src=tun6.remote_ip6)
            / UDP(sport=1234, dport=1234)
            / Raw()
        )

        rxs = self.send_and_expect(phy, p * N_PKTS, self.pg5)
        for rx in rxs:
            rx = IPv6(bytes(rx))
            self.assertEqual(rx[IPv6].dst, tun6.local_ip6)
            self.assertEqual(rx[IPv6].src, tun6.remote_ip6)

        # cleanup
        phy.unconfig_ip4()
        phy.unconfig_ip6()

        tun4.unconfig_ip4()
        tun6.unconfig_ip6()


@unittest.skipIf("linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests")
class TestLinuxCPIpsec(TemplateIpsec, TemplateIpsecItf4, IpsecTun4):
    """IPsec Interface IPv4"""

    extra_vpp_plugin_config = [
        "plugin",
        "linux_cp_plugin.so",
        "{",
        "enable",
        "}",
        "plugin",
        "linux_cp_unittest_plugin.so",
        "{",
        "enable",
        "}",
    ]

    def setUp(self):
        super(TestLinuxCPIpsec, self).setUp()

        self.tun_if = self.pg0
        self.pg_interfaces += self.create_pg_ip4_interfaces(range(3, 4))
        self.pg_interfaces += self.create_pg_ip6_interfaces(range(4, 5))

    def tearDown(self):
        super(TestLinuxCPIpsec, self).tearDown()

    def verify_encrypted(self, p, sa, rxs):
        decrypt_pkts = []
        for rx in rxs:
            if p.nat_header:
                self.assertEqual(rx[UDP].dport, 4500)
            self.assert_packet_checksums_valid(rx)
            self.assertEqual(len(rx) - len(Ether()), rx[IP].len)
            try:
                rx_ip = rx[IP]
                decrypt_pkt = p.vpp_tun_sa.decrypt(rx_ip)
                if not decrypt_pkt.haslayer(IP):
                    decrypt_pkt = IP(decrypt_pkt[Raw].load)
                if rx_ip.proto == socket.IPPROTO_ESP:
                    self.verify_esp_padding(sa, rx_ip[ESP].data, decrypt_pkt)
                decrypt_pkts.append(decrypt_pkt)
                self.assert_equal(decrypt_pkt.src, p.tun_if.local_ip4)
                self.assert_equal(decrypt_pkt.dst, p.tun_if.remote_ip4)
            except:
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", decrypt_pkt))
                except:
                    pass
                raise
        pkts = reassemble4(decrypt_pkts)
        for pkt in pkts:
            self.assert_packet_checksums_valid(pkt)

    def verify_decrypted(self, p, rxs):
        for rx in rxs:
            rx = IP(bytes(rx))
            self.assert_equal(rx[IP].src, p.tun_if.remote_ip4)
            self.assert_equal(rx[IP].dst, p.tun_if.local_ip4)
            self.assert_packet_checksums_valid(rx)

    def gen_encrypt_pkts(self, p, sa, sw_intf, src, dst, count=1, payload_size=54):
        return [
            Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac)
            / sa.encrypt(
                IP(src=src, dst=dst)
                / UDP(sport=1111, dport=2222)
                / Raw(b"X" * payload_size)
            )
            for i in range(count)
        ]

    def test_linux_cp_ipsec4_tun(self):
        """Linux CP Ipsec TUN"""

        #
        # Setup
        #
        N_PKTS = 31

        # the pg that paris with the tunnel
        self.host = self.pg3

        # tunnel and protection setup
        p = self.ipv4_params

        self.config_network(p)
        self.config_sa_tun(p, self.pg0.local_ip4, self.pg0.remote_ip4)
        self.config_protect(p)

        pair = VppLcpPair(self, p.tun_if, self.host).add_vpp_config()

        self.logger.info(self.vapi.cli("sh int addr"))
        self.logger.info(self.vapi.cli("sh lcp"))
        self.logger.info(self.vapi.cli("sh ip punt redirect"))

        #
        # Traffic Tests
        #

        # host to phy for v4
        pkt = (
            IP(src=p.tun_if.local_ip4, dst=p.tun_if.remote_ip4)
            / UDP(sport=1234, dport=1234)
            / Raw()
        )

        rxs = self.send_and_expect(self.host, pkt * N_PKTS, self.tun_if)
        self.verify_encrypted(p, p.vpp_tun_sa, rxs)

        # phy to host for v4
        pkts = self.gen_encrypt_pkts(
            p,
            p.scapy_tun_sa,
            self.tun_if,
            src=p.tun_if.remote_ip4,
            dst=p.tun_if.local_ip4,
            count=N_PKTS,
        )
        rxs = self.send_and_expect(self.tun_if, pkts, self.host)
        self.verify_decrypted(p, rxs)

        # cleanup
        pair.remove_vpp_config()
        self.unconfig_protect(p)
        self.unconfig_sa(p)
        self.unconfig_network(p)


@unittest.skipIf("linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests")
class TestLinuxCPEthertype(VppTestCase):
    """Linux CP Ethertype"""

    extra_vpp_plugin_config = [
        "plugin",
        "linux_cp_plugin.so",
        "{",
        "enable",
        "}",
        "plugin",
        "linux_cp_unittest_plugin.so",
        "{",
        "enable",
        "}",
        "plugin",
        "lldp_plugin.so",
        "{",
        "disable",
        "}",
    ]

    LACP_ETHERTYPE = 0x8809
    LLDP_ETHERTYPE = 0x88CC

    @classmethod
    def setUpClass(cls):
        super(TestLinuxCPEthertype, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestLinuxCPEthertype, cls).tearDownClass()

    def setUp(self):
        super(TestLinuxCPEthertype, self).setUp()
        self.create_pg_interfaces(range(2))
        for i in self.pg_interfaces:
            i.admin_up()

        self.host = self.pg0
        self.phy = self.pg1

        self.pair = VppLcpPair(self, self.phy, self.host).add_vpp_config()
        self.logger.info(self.vapi.cli("sh lcp"))

    def tearDown(self):
        self.pair.remove_vpp_config()

        for i in self.pg_interfaces:
            i.admin_down()
        super(TestLinuxCPEthertype, self).tearDown()

    def send_packet(self, sender, receiver, ethertype, dst, data, expect_copy=True):
        packet = Ether(src=sender.remote_mac, dst=dst, type=ethertype) / data
        if expect_copy:
            rxs = self.send_and_expect(sender, [packet], receiver)
            for rx in rxs:
                self.assertEqual(packet.show2(True), rx.show2(True))
        else:
            self.send_and_assert_no_replies(sender, [packet])

    def send_lacp_packet(self, sender, receiver, expect_copy=True):
        data = LACP(
            actor_system="00:00:00:00:00:01", partner_system="00:00:00:00:00:02"
        )
        self.send_packet(
            sender,
            receiver,
            self.LACP_ETHERTYPE,
            "01:80:c2:00:00:02",
            data,
            expect_copy,
        )

    def send_lldp_packet(self, sender, receiver, expect_copy=True):
        data = (
            LLDPDUChassisID(subtype=4, id="01:02:03:04:05:06")
            / LLDPDUPortID(subtype=3, id="07:08:09:0a:0b:0c")
            / LLDPDUTimeToLive(ttl=120)
            / LLDPDUEndOfLLDPDU()
        )
        self.send_packet(
            sender,
            receiver,
            self.LLDP_ETHERTYPE,
            "01:80:c2:00:00:0e",
            data,
            expect_copy,
        )

    def check_ethertype_enabled(self, ethertype, enabled=True):
        reply = self.vapi.lcp_ethertype_get()
        output = self.vapi.cli("show lcp ethertype")

        if enabled:
            self.assertIn(ethertype, reply.ethertypes)
            self.assertIn(hex(ethertype), output)
        else:
            self.assertNotIn(ethertype, reply.ethertypes)
            self.assertNotIn(hex(ethertype), output)

    def test_linux_cp_lacp(self):
        """Linux CP LACP Test"""
        self.check_ethertype_enabled(self.LACP_ETHERTYPE, enabled=False)
        self.send_lacp_packet(self.phy, self.host, expect_copy=False)
        self.send_lacp_packet(self.host, self.phy, expect_copy=False)

        self.vapi.cli("lcp ethertype enable " + str(self.LACP_ETHERTYPE))

        self.check_ethertype_enabled(self.LACP_ETHERTYPE, enabled=True)
        self.send_lacp_packet(self.phy, self.host, expect_copy=True)
        self.send_lacp_packet(self.host, self.phy, expect_copy=True)

    def test_linux_cp_lldp(self):
        """Linux CP LLDP Test"""
        self.check_ethertype_enabled(self.LLDP_ETHERTYPE, enabled=False)
        self.send_lldp_packet(self.phy, self.host, expect_copy=False)
        self.send_lldp_packet(self.host, self.phy, expect_copy=False)

        self.vapi.cli("lcp ethertype enable " + str(self.LLDP_ETHERTYPE))

        self.check_ethertype_enabled(self.LLDP_ETHERTYPE, enabled=True)
        self.send_lldp_packet(self.phy, self.host, expect_copy=True)
        self.send_lldp_packet(self.host, self.phy, expect_copy=True)


CLIB_U32_MAX = 4294967295


class TestLinuxCPNetNSBase(VppTestCase):
    """Base class for LCP tests that use real Linux namespaces."""

    extra_vpp_plugin_config = [
        "plugin",
        "linux_cp_plugin.so",
        "{",
        "enable",
        "}",
        "plugin",
        "linux_nl_plugin.so",
        "{",
        "enable",
        "}",
    ]

    @classmethod
    def setUpNetNS(cls):
        # The namespace must be set up before VPP starts
        cls.ns_history_name = (
            f"{config.tmp_dir}/{get_testcase_dirname(cls.__name__)}/history_ns.txt"
        )
        delete_all_namespaces(cls.ns_history_name)

        cls.ns_name = create_namespace(cls.ns_history_name)
        cls.vpp_cmdline.extend(
            [
                "linux-cp",
                "{",
                "default",
                "netns",
                cls.ns_name,
                "lcp-sync",
                "}",
            ]
        )

    @classmethod
    def attach_vpp(cls):
        cls.setUpNetNS()
        super().attach_vpp()

    @classmethod
    def run_vpp(cls):
        cls.setUpNetNS()
        super().run_vpp()

    @classmethod
    def tearDownClass(cls):
        delete_all_namespaces(cls.ns_history_name)
        super().tearDownClass()

    def poll_for(self, description, fn, expected, timeout=2.0, interval=0.1):
        """Poll fn() until it returns expected, or fail after timeout."""
        iterations = int(timeout / interval)
        actual = None
        for i in range(iterations):
            actual = fn()
            if actual == expected:
                return
            self.sleep(interval)
        self.assertEqual(actual, expected, description)

    def route_lookup(self, prefix):
        return self.vapi.api(
            self.vapi.papi.ip_route_lookup,
            {
                "table_id": 0,
                "exact": False,
                "prefix": prefix,
            },
        )

    def get_paths(self, prefix):
        result = []
        route = self.route_lookup(prefix).route
        for path in route.paths:
            d = dict(type=path.type)
            if path.sw_if_index != CLIB_U32_MAX:
                d["sw_if_index"] = path.sw_if_index
            if str(path.nh.address.ip4) != "0.0.0.0":
                d["ip4"] = str(path.nh.address.ip4)
            result.append(d)
        return result

    def verify_paths(self, prefix, *expected_paths):
        for i in range(0, 20):
            paths = self.get_paths(prefix)
            if paths == list(expected_paths):
                break
            self.sleep(0.1)
        else:
            self.assertEqual(paths, expected_paths)


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
@unittest.skipIf(
    "linux-cp" in config.excluded_plugins or "linux-nl" in config.excluded_plugins,
    "Exclude linux-cp route tests",
)
class TestLinuxCPMalformedRoutes(TestLinuxCPNetNSBase):
    """Malformed libnl routes preserve the FIB and release table references."""

    extra_vpp_plugin_config = [
        "plugin linux_cp_plugin.so { enable }",
        "plugin linux_nl_plugin.so { enable }",
        "plugin linux_cp_unittest_plugin.so { enable }",
    ]

    def setUp(self):
        super().setUp()
        self.create_pg_interfaces(range(2))
        self.phy, self.host = self.pg_interfaces
        self.phy.admin_up()
        self.host.admin_up()
        self.pair = VppLcpPair(self, self.phy, self.host).add_vpp_config()

    def test_malformed_routes(self):
        """Rejected destination, nexthop and source attributes leave no FIB changes."""
        table_id = 65000
        for is_ip6 in (False, True):
            family = "ip6" if is_ip6 else "ip4"
            for operation in ("add", "replace", "del"):
                faults = ["destination", "gateway-first", "gateway-last"]
                if is_ip6 and operation != "del":
                    faults.append("source")
                for fault in faults:
                    table_id += 1
                    with self.subTest(family=family, operation=operation, fault=fault):
                        table = VppIpTable(
                            self, table_id, is_ip6=is_ip6, create_mfib=False
                        ).add_vpp_config()
                        command = (
                            f"test lcp route phy {self.phy.sw_if_index} "
                            f"table {table_id} {family}"
                        )
                        self.assertFalse(
                            any(
                                r.table.table_id == table_id
                                and r.table.is_ip6 == is_ip6
                                for r in self.vapi.ip_mtable_dump()
                            ),
                            "unicast-only fixture created an MFIB",
                        )
                        try:
                            self.vapi.cli(f"{command} add valid")
                            before = [r.route for r in table.dump()]
                            default = next(r for r in before if r.prefix.prefixlen == 0)
                            self.assertEqual(default.n_paths, 2)
                            self.vapi.cli(f"{command} {operation} {fault}")
                            self.assertEqual(before, [r.route for r in table.dump()])
                        finally:
                            try:
                                self.vapi.cli(f"{command} del valid")
                                self.assertFalse(
                                    any(
                                        r.table.table_id == table_id
                                        and r.table.is_ip6 == is_ip6
                                        for r in self.vapi.ip_mtable_dump()
                                    ),
                                    "rejected route retained an LCP table reference",
                                )
                            finally:
                                # Release one extra reference when testing the unfixed add.
                                self.vapi.cli(f"{command} del valid")


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
@unittest.skipIf(
    "linux-cp" in config.excluded_plugins or "linux-nl" in config.excluded_plugins,
    "Exclude linux-cp route tests",
)
class TestLinuxCPCrossFibNexthop(TestLinuxCPNetNSBase):
    """A route whose nexthop lives in another FIB table is reported, not dropped."""

    extra_vpp_plugin_config = TestLinuxCPNetNSBase.extra_vpp_plugin_config + [
        "plugin",
        "linux_cp_unittest_plugin.so",
        "{",
        "enable",
        "}",
    ]

    dev_table = 65200
    route_table = 65201

    def setUp(self):
        super().setUp()
        self.create_pg_interfaces(range(2))
        self.phy, self.host = self.pg_interfaces
        self.phy.admin_up()
        self.host.admin_up()
        self.pair = VppLcpPair(self, self.phy, self.host).add_vpp_config()
        for table_id in (self.dev_table, self.route_table):
            VppIpTable(self, table_id, create_mfib=False).add_vpp_config()
        # The nexthop device lives in a table of its own; the route below is
        # installed into another one.
        self.vapi.cli(f"set interface ip table {self.phy.name} {self.dev_table}")

    def tearDown(self):
        self.vapi.cli(f"set interface ip table {self.phy.name} 0")
        super().tearDown()

    def _cross_fib_count(self):
        output = self.vapi.cli("test lcp cross-fib")
        self.assertIn("cross-fib:", output)
        return int(output.strip().split("cross-fib:")[-1])

    def _vif_index(self):
        return next(
            entry
            for entry in self.vapi.vpp.details_iter(self.vapi.lcp_itf_pair_get)
            if entry.phy_sw_if_index == self.phy.sw_if_index
        ).vif_index

    def test_cross_fib_nexthop_reported_and_installed(self):
        """The mismatch is reported once and the route stays in the target table."""
        # A concrete prefix, not 0.0.0.0/0: every table carries that one as a
        # default drop entry, so it would be present either way.
        prefix = "198.18.90.0/24"
        base = f"ip4 table {self.route_table}"
        route = f"{prefix} proto 4 vif {self._vif_index()} via 192.0.2.1"
        before = self._cross_fib_count()
        try:
            self.vapi.cli(f"test lcp router {base} add {route}")
            self.assertEqual(
                self._cross_fib_count(),
                before + 1,
                "cross FIB nexthop diagnostic did not fire exactly once",
            )
            logging = self.vapi.cli("show logging")
            self.assertIn(
                f"route {self.route_table}:{prefix} nexthop sw_if_index "
                f"{self.phy.sw_if_index} is in fib",
                logging,
            )
            # Repeated netlink replays of the same route are deduplicated.
            self.vapi.cli(f"test lcp router {base} add {route}")
            self.vapi.cli(f"test lcp router {base} replace {route}")
            self.assertEqual(self._cross_fib_count(), before + 1)
            # The path is still installed in the route's table, reachable
            # through the nexthop device that lives in the other table.
            self.assertTrue(
                find_route(
                    self,
                    "198.18.90.0",
                    24,
                    table_id=self.route_table,
                    sw_if_index=self.phy.sw_if_index,
                ),
                "cross FIB nexthop route was not installed",
            )
        finally:
            self.vapi.cli(f"test lcp router {base} del {route}")

    def test_mpls_paths_are_not_checked(self):
        """MPLS paths use their own FIB index mapping and are left out of the check.

        The IPv4 route in the same table, over the same device, does qualify for
        the check, so the unchanged counter is due to the MPLS skip and not to a
        path that would have been ignored anyway.
        """
        vif = self._vif_index()
        label = 18802
        base = f"mpls table {self.route_table}"
        route = f"{label} proto 4 vif {vif} via 192.0.2.1"
        ip4 = f"198.18.91.0/24 proto 4 vif {vif} via 192.0.2.1"
        before = self._cross_fib_count()
        try:
            self.vapi.cli(f"test lcp router {base} add {route}")
            self.assertEqual(
                self._cross_fib_count(),
                before,
                "MPLS path was checked against the unicast FIB table",
            )
            labels = [
                entry.mr_route.mr_label
                for entry in self.vapi.mpls_route_dump(self.route_table)
            ]
            self.assertIn(label, labels, "MPLS route was not installed")
            self.vapi.cli(f"test lcp router ip4 table {self.route_table} add {ip4}")
            self.assertEqual(
                self._cross_fib_count(),
                before + 1,
                "IPv4 path over the same device did not qualify for the check",
            )
            self.vapi.cli(f"test lcp router ip4 table {self.route_table} del {ip4}")
        finally:
            self.vapi.cli(f"test lcp router {base} del {route}")


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
@unittest.skipIf(
    "linux-cp" in config.excluded_plugins or "linux-nl" in config.excluded_plugins,
    "Exclude linux-cp route tests",
)
class TestLinuxCPMulticastRoutes(TestLinuxCPNetNSBase):
    """Multicast routes are removed from the MFIB and resynchronized like unicast ones."""

    extra_vpp_plugin_config = TestLinuxCPNetNSBase.extra_vpp_plugin_config + [
        "plugin",
        "linux_cp_unittest_plugin.so",
        "{",
        "enable",
        "}",
    ]

    table_id = 65202
    group = "239.1.1.1"
    source = "192.0.2.1"
    other_group = "239.1.1.2"
    # A group the table itself holds, installed under MFIB_SOURCE_SPECIAL when
    # the table is created and never replayed by the plugin.
    special_group = "224.0.0.1"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_loopback_interfaces(1)
        cls.vapi.cli(f"lcp create loop0 host-if hloop0 netns {cls.ns_name}")
        cls.lo_interfaces[0].admin_up()

    def setUp(self):
        super().setUp()
        VppIpTable(self, self.table_id, create_mfib=False).add_vpp_config()
        self.pair = next(
            entry
            for entry in self.vapi.vpp.details_iter(self.vapi.lcp_itf_pair_get)
            if entry.phy_sw_if_index == self.lo_interfaces[0].sw_if_index
        )

    # Actions that act on every table and name no route.
    _ROUTER_TABLE_WIDE_ACTIONS = ("begin", "end")

    def _base(self, table_id=None):
        """The table a command names: the family, then the table id."""
        return f"ip4 table {table_id or self.table_id}"

    def _router(self, action, route=None, table_id=None):
        """Run one router command; the table comes before the action it acts on.

        begin and end act on every table and name no route, so they are the
        only actions that may leave one out; a route left out of any other
        action is a mistake in the test, not a command for the plugin. The
        record probe names its table after its own verb and does not come
        through here.
        """
        if route is None:
            if action not in self._ROUTER_TABLE_WIDE_ACTIONS:
                raise TypeError(f"test lcp router {action} needs a route")
            return self.vapi.cli(f"test lcp router {action}")
        return self.vapi.cli(f"test lcp router {self._base(table_id)} {action} {route}")

    def _mroute(self, group, source=None, table_id=None):
        return self.vapi.cli(
            f"test lcp mroute table {table_id or self.table_id} {group} "
            + (f"source {source}" if source else "wildcard")
        )

    def _entry(self, group, source=None, table_id=None):
        """Return (present, {source id: (stale, paths)}) for one MFIB entry.

        The fixture prints the id of the plugin's source on the entry line, so
        the test names that source without a constant for its numeric value.
        """
        lines = self._mroute(group, source, table_id).splitlines()
        fields = dict(field.split(":", 1) for field in lines[0].split())
        sources = {}
        for line in lines[1:]:
            source_fields = dict(field.split(":", 1) for field in line.split())
            sources[int(source_fields["source"])] = (
                source_fields["flags"] == "stale",
                int(source_fields["paths"]),
            )
        return fields["entry"] == "present", sources

    def _plugin_low(self, group, source=None, table_id=None):
        """Id of the source the plugin installs multicast routes under."""
        fields = dict(
            field.split(":", 1)
            for field in self._mroute(group, source, table_id).splitlines()[0].split()
        )
        return int(fields["plugin-low"])

    def _router_record(self, table_id=None):
        """The plugin's record of a table: absent, or the indices it names.

        The plugin reads a record by its table, so this probe names the table
        after its own verb, as the parser dispatches it before any family.
        """
        output = self.vapi.cli(f"test lcp router record {self._base(table_id)}")
        fields = dict(field.split(":", 1) for field in output.split())
        if fields["router-record"] == "absent":
            return {"state": "absent"}
        return {
            "state": "present",
            "fib": int(fields["fib"]),
            "table-fib": int(fields["table-fib"]),
            "mfib": int(fields["mfib"]),
            "table-mfib": int(fields["table-mfib"]),
        }

    def _router_state(self, table_id=None):
        """The plugin's state line for one table, absent or present.

        Unlike the record probe, state is read after the table it names.
        """
        return self.vapi.cli(f"test lcp router {self._base(table_id)} state")

    def _table_state(self, table_id=None):
        output = self._router_state(table_id)
        self.assertNotIn("absent", output, output)
        state = dict(
            field.split(":", 1)
            for line in output.splitlines()
            for field in line.split()
        )
        return {
            "refs": int(state["refs"]),
            "mcast-routes": int(state["mcast-routes"]),
        }

    def _route(self, group, source=None, vif=True):
        """The route a router action acts on, without the table it lives in.

        _router names the table before the action, so the route carries only
        what the action itself takes.
        """
        route = f"{group}/32 proto 4 multicast source {source or '0.0.0.0'}"
        return route + (f" vif {self.pair.vif_index}" if vif else "")

    def test_multicast_zero_source_route_is_a_wildcard_entry(self):
        """A route that names an all-zero source is the (*,G) entry

        Netlink can carry a source attribute with an all-zero address, which
        names no source at all: the MFIB key folds nothing into its low half
        for such a source, so the route is the same entry a wildcard add
        installs. It is therefore keyed at the group's own length. Keying it at
        the (S,G) length would file it in a bucket the (S,G) lookup misses
        because its key differs, and that the group fallback of the table
        lookup never reaches, so nothing could find it.
        """
        route = self._route(self.group, vif=True)
        try:
            self._router("add", route)
            present, sources = self._entry(self.group)
            self.assertTrue(
                present,
                "a route with a zero source was not found as the (*,G) entry",
            )
            plugin_low = self._plugin_low(self.group)
            self.assertIn(plugin_low, sources)
            self.assertTrue(
                sources[plugin_low][1] > 0,
                "a route with a zero source lost its paths",
            )
            # The entry is the group's, so the (S,G) query does not reach it:
            # exact match reads the host-length bucket, which this key never
            # filled. This is the shape that made the bug invisible, and it is
            # why the route must live in the group's bucket.
            self.assertEqual(
                self._entry(self.group, "0.0.0.0"),
                (False, {}),
                "the zero-source route was filed under the (S,G) key",
            )
            self.assertEqual(self._table_state(), {"refs": 1, "mcast-routes": 1})
        finally:
            self._router("del", route)

    def test_multicast_route_delete(self):
        """A deleted (S,G) leaves the MFIB, and a repeated delete changes nothing"""
        route = self._route(self.group, self.source)
        self.assertEqual(self._entry(self.group, self.source), (False, {}))
        try:
            self._router("add", route)
            present, sources = self._entry(self.group, self.source)
            self.assertTrue(present, "multicast route was not installed")
            plugin_low = self._plugin_low(self.group, self.source)
            self.assertIn(plugin_low, sources)
            self.assertTrue(sources[plugin_low][1] > 0)
            self.assertEqual(self._table_state(), {"refs": 1, "mcast-routes": 1})
            self._router("del", route)
            self.assertEqual(
                self._entry(self.group, self.source),
                (False, {}),
                "deleted multicast route is still in the MFIB",
            )
            # The table held nothing else, so the reference the route held was
            # the last one and the table went with it. Releasing it twice
            # would have freed a table that was gone already.
            self.assertNotIn("refs:", self._router_state())
            # The kernel repeats deletes; a second one must not fault or
            # change the table.
            self._router("del", route)
            self.assertEqual(self._entry(self.group, self.source), (False, {}))
        finally:
            self._router("del", route)

    def test_multicast_sync_drops_routes_the_kernel_no_longer_has(self):
        """A route absent from a synchronization is removed and its reference freed"""
        route = self._route(self.group, self.source)
        stale = self._route(self.other_group, self.source)
        try:
            self._router("add", route)
            self._router("add", stale)
            self.assertEqual(self._table_state()["mcast-routes"], 2)
            self._router("begin")
            self._router("add", route)
            self._router("end")
            self.assertEqual(
                self._entry(self.other_group, self.source),
                (False, {}),
                "multicast route the kernel no longer has survived the synchronization",
            )
            self.assertTrue(
                self._entry(self.group, self.source)[0],
                "multicast route the kernel replayed was dropped",
            )
            self.assertEqual(
                self._table_state()["mcast-routes"],
                1,
                "reference accounting does not follow the routes left",
            )
        finally:
            self._router("del", route)
            self._router("del", stale)

    def test_multicast_mark_delete_replay(self):
        """A route the kernel deletes and re-adds within one synchronization stays"""
        route = self._route(self.group, self.source)
        try:
            self._router("begin")
            self._router("add", route)
            self._router("del", route)
            self._router("add", route)
            self._router("end")
            present, sources = self._entry(self.group, self.source)
            self.assertTrue(
                present, "multicast route replayed after its delete was dropped"
            )
            plugin_low = self._plugin_low(self.group, self.source)
            self.assertIn(plugin_low, sources)
            self.assertTrue(
                sources[plugin_low][1] > 0,
                "multicast route replayed after its delete lost its paths",
            )
            # The delete gave the route's reference back and the replay took
            # it again. The fixture calls the plugin's route handler itself, so
            # nothing can drop the replay on the way.
            self.assertEqual(self._table_state(), {"refs": 1, "mcast-routes": 1})
        finally:
            self._router("del", route)

    def test_multicast_empty_replay_drops_the_route(self):
        """A replace that names no nexthop takes the route and its reference away"""
        route = self._route(self.group, self.source)
        empty = self._route(self.group, self.source, vif=False)
        try:
            self._router("add", route)
            self.assertEqual(self._table_state(), {"refs": 1, "mcast-routes": 1})
            self._router("replace", empty)
            self.assertEqual(
                self._entry(self.group, self.source),
                (False, {}),
                "multicast route replaced with no nexthop is still in the MFIB",
            )
            # The route's reference went with it, as it does on a delete: the
            # table held nothing else and is gone.
            self.assertNotIn("refs:", self._router_state())
            # No record is left for the next synchronization to trip over.
            self._router("begin")
            self._router("end")
            self.assertNotIn("refs:", self._router_state())

            # Nor does a second replace act on what is no longer there: it
            # reaches the plugin with no record to find.
            self._router("replace", empty)
            self.assertEqual(self._entry(self.group, self.source), (False, {}))
            self.assertNotIn("refs:", self._router_state())
        finally:
            self._router("del", route)

    def test_multicast_empty_add_drops_nothing(self):
        """An add with no nexthop installs nothing and takes nothing away

        The kernel sends such a route for one it dropped itself, so it reaches
        the plugin with no record behind it. Only a replace may act on one.
        """
        route = self._route(self.group, self.source)
        empty = self._route(self.group, self.source, vif=False)
        try:
            self._router("add", empty)
            self.assertEqual(self._entry(self.group, self.source), (False, {}))
            self.assertNotIn("refs:", self._router_state())

            # Nor does it take away a route the plugin holds: the add names no
            # nexthop, so it is not the replace that drops the nexthop list.
            self._router("add", route)
            self._router("add", empty)
            self.assertTrue(
                self._entry(self.group, self.source)[0],
                "add with no nexthop took a held multicast route away",
            )
            self.assertEqual(self._table_state(), {"refs": 1, "mcast-routes": 1})
        finally:
            self._router("del", route)

    def test_multicast_empty_add_keeps_the_table_special_route(self):
        """An add with no nexthop leaves the route the table holds for itself

        The table installs (*,224.0.0.1) and (*,224.0.0.2) under
        MFIB_SOURCE_SPECIAL and never replays them, so a delete aimed at that
        prefix would take a route away for good.
        """
        route = self._route(self.group, self.source)
        empty = self._route(self.special_group, vif=False)
        try:
            # The plugin creates the table and its special routes together; a
            # command for a table that does not exist yet is dropped before it
            # can touch anything.
            self._router("add", route)
            present, sources = self._entry(self.special_group)
            self.assertTrue(present, "the table has no special multicast route")
            self.assertNotIn(self._plugin_low(self.special_group), sources)
            before = sources

            self._router("add", empty)
            self._router("replace", empty)

            present, sources = self._entry(self.special_group)
            self.assertTrue(present, "the table lost its special multicast route")
            self.assertEqual(sources, before)
        finally:
            self._router("del", route)

    def test_multicast_table_delete_and_recreate(self):
        """A table the API deletes gives up the plugin's record of it

        The api delete unlocks the FIB the plugin locked and frees the MFIB the
        plugin's record names, so the record has to go with them: a record kept
        past that point makes the plugin index a table that is gone. The
        plugin's own lock is what tells the two apart, since the delete clears
        it and nothing else does.
        """
        # A table of its own, deleted and re-created here.
        table_id = self.table_id - 1
        route = self._route(self.group, self.source)
        table = VppIpTable(self, table_id, create_mfib=False).add_vpp_config()
        self.addCleanup(VppIpTable(self, table_id, create_mfib=False).remove_vpp_config)
        try:
            self._router("add", route, table_id)
            self.assertTrue(
                self._entry(self.group, self.source, table_id)[0],
                "multicast route was not installed",
            )
            self.assertEqual(
                self._table_state(table_id), {"refs": 1, "mcast-routes": 1}
            )
            before = self._router_record(table_id)
            self.assertEqual(before["state"], "present")
            self.assertEqual(before["fib"], before["table-fib"])
            self.assertEqual(before["mfib"], before["table-mfib"])

            table.remove_vpp_config()
            self.assertEqual(
                self._router_record(table_id),
                {"state": "absent"},
                "the plugin kept a record of the deleted table",
            )
            # The table is gone for the fixture too, and asking does not fault.
            self.assertIn("absent", self._router_state(table_id))

            VppIpTable(self, table_id, create_mfib=False).add_vpp_config()
            self._router("add", route, table_id)
            after = self._router_record(table_id)
            self.assertEqual(after["state"], "present")
            self.assertEqual(after["fib"], after["table-fib"])
            self.assertEqual(after["mfib"], after["table-mfib"])
            self.assertEqual(
                self._table_state(table_id), {"refs": 1, "mcast-routes": 1}
            )
            self.assertTrue(
                self._entry(self.group, self.source, table_id)[0],
                "multicast route was not installed in the re-created table",
            )
        finally:
            self._router("del", route, table_id)

    def test_multicast_sync_is_idempotent(self):
        """Replaying the same routes does not leak a table reference each time"""
        route = self._route(self.group, self.source)
        try:
            self._router("begin")
            self._router("add", route)
            self._router("end")
            baseline = self._table_state()
            for _ in range(3):
                self._router("begin")
                self._router("add", route)
                self._router("end")
            self.assertEqual(self._table_state(), baseline)
        finally:
            self._router("del", route)


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
class TestLinuxCPRoutes(TestLinuxCPNetNSBase):
    """Linux CP Routes"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_loopback_interfaces(2)

        cls.vapi.cli(f"lcp create loop0 host-if hloop0 netns {cls.ns_name}")
        cls.vapi.cli(f"lcp create loop1 host-if hloop1 netns {cls.ns_name}")

        cls.vapi.cli("set int ip address loop0 10.10.1.2/24")
        cls.vapi.cli("set int ip address loop1 10.20.1.2/24")

        for lo in cls.lo_interfaces:
            lo.admin_up()

    def test_linux_cp_route(self):
        """Linux CP Route"""
        add_namespace_route(self.ns_name, "default", dev="hloop0", gw_ip="10.10.1.1")
        add_namespace_route(
            self.ns_name, "192.168.100.0/24", dev="hloop1", gw_ip="10.20.1.1"
        )

        self.verify_paths(
            "192.168.1.1/32",
            dict(
                type=FibPathType.FIB_PATH_TYPE_NORMAL,
                sw_if_index=self.lo_interfaces[0].sw_if_index,
                ip4="10.10.1.1",
            ),
        )
        self.verify_paths(
            "192.168.100.1/32",
            dict(
                type=FibPathType.FIB_PATH_TYPE_NORMAL,
                sw_if_index=self.lo_interfaces[1].sw_if_index,
                ip4="10.20.1.1",
            ),
        )

        set_interface_down(self.ns_name, "hloop0")

        self.verify_paths("192.168.1.1/32", dict(type=FibPathType.FIB_PATH_TYPE_DROP))
        self.verify_paths(
            "192.168.100.1/32",
            dict(
                type=FibPathType.FIB_PATH_TYPE_NORMAL,
                sw_if_index=self.lo_interfaces[1].sw_if_index,
                ip4="10.20.1.1",
            ),
        )

        set_interface_down(self.ns_name, "hloop1")

        self.verify_paths("192.168.1.1/32", dict(type=FibPathType.FIB_PATH_TYPE_DROP))
        self.verify_paths("192.168.100.1/32", dict(type=FibPathType.FIB_PATH_TYPE_DROP))

        set_interface_up(self.ns_name, "hloop0")
        set_interface_up(self.ns_name, "hloop1")

    def test_linux_cp_multipath_route(self):
        """Linux CP Multipath Route"""
        add_namespace_multipath_route(
            self.ns_name,
            "default",
            NextHop(gw_ip="10.10.1.1", dev="hloop0"),
            NextHop(gw_ip="10.20.1.1", dev="hloop1"),
        )
        self.verify_paths(
            "192.168.1.1/32",
            dict(
                type=FibPathType.FIB_PATH_TYPE_NORMAL,
                sw_if_index=self.lo_interfaces[0].sw_if_index,
                ip4="10.10.1.1",
            ),
            dict(
                type=FibPathType.FIB_PATH_TYPE_NORMAL,
                sw_if_index=self.lo_interfaces[1].sw_if_index,
                ip4="10.20.1.1",
            ),
        )
        set_interface_down(self.ns_name, "hloop0")
        self.verify_paths(
            "192.168.1.1/32",
            dict(
                type=FibPathType.FIB_PATH_TYPE_NORMAL,
                sw_if_index=self.lo_interfaces[1].sw_if_index,
                ip4="10.20.1.1",
            ),
        )
        set_interface_down(self.ns_name, "hloop1")
        self.verify_paths("192.168.1.1/32", dict(type=FibPathType.FIB_PATH_TYPE_DROP))
        set_interface_up(self.ns_name, "hloop0")
        set_interface_up(self.ns_name, "hloop1")


ISIS_PROTO = 0x83


@unittest.skipIf("linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests")
class TestLinuxCPOSI(VppTestCase):
    """Linux CP OSI registration and passthrough"""

    extra_vpp_plugin_config = [
        "plugin linux_cp_plugin.so { enable }",
        "plugin linux_cp_unittest_plugin.so { enable }",
    ]

    @classmethod
    def setUpClass(cls):
        super(TestLinuxCPOSI, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestLinuxCPOSI, cls).tearDownClass()

    def tearDown(self):
        self.pair.remove_vpp_config()

        for i in self.pg_interfaces:
            i.admin_down()
        super(TestLinuxCPOSI, self).tearDown()

    def setUp(self):
        super(TestLinuxCPOSI, self).setUp()
        self.create_pg_interfaces(range(2))
        for i in self.pg_interfaces:
            i.admin_up()

        self.host = self.pg0
        self.phy = self.pg1

        self.pair = VppLcpPair(self, self.phy, self.host).add_vpp_config()
        self.logger.info(self.vapi.cli("sh lcp"))

    def num_osi_protos_enabled(self):
        reply = self.vapi.lcp_osi_proto_get()
        return reply.count

    def osi_proto_is_enabled(self, proto, expected=True):
        reply = self.vapi.lcp_osi_proto_get()
        self.assertEqual(expected, (proto in reply.osi_protos))
        return reply.count

    def test_linux_cp_osi_registration(self):
        """Linux CP OSI proto registration"""

        VNET_API_ERROR_INVALID_REGISTRATION = -31
        CLNP_PROTO = 0x81
        BAD_OSI_PROTO = 0xFF

        # verify that CLNP is not registered
        count_before = self.osi_proto_is_enabled(CLNP_PROTO, expected=False)

        # register CLNP, verify that it was enabled
        self.vapi.lcp_osi_proto_enable(osi_proto=CLNP_PROTO)
        count_after = self.osi_proto_is_enabled(CLNP_PROTO, expected=True)
        self.assertEqual(count_after, count_before + 1)
        count_before = count_after

        # register an unknown proto, verify that its not enabled
        with self.vapi.assert_negative_api_retval():
            reply = self.vapi.lcp_osi_proto_enable(osi_proto=BAD_OSI_PROTO)
        self.assertEqual(reply.retval, VNET_API_ERROR_INVALID_REGISTRATION)
        count_after = self.osi_proto_is_enabled(BAD_OSI_PROTO, expected=False)
        self.assertEqual(count_before, count_after)

    def send_isis_packets(self, sender, receiver, expect_copy=True):
        # Two cases:
        # - Original ethernet framing (size instead of ethertype)
        # - Ethernet II framing (ethertype containing LLC-Encap ethertype)
        ISIS_ALL_L1 = "01:80:c2:00:00:14"
        LLC_ETHERTYPE = 0x8870
        no_encap = (
            Dot3(src=sender.remote_mac, dst=ISIS_ALL_L1)
            / LLC()
            / ISIS_CommonHdr()
            / ISIS_L1_LAN_Hello(circuittype="L1")
        )
        encap = (
            Ether(src=sender.remote_mac, dst=ISIS_ALL_L1, type=LLC_ETHERTYPE)
            / LLC()
            / ISIS_CommonHdr()
            / ISIS_L1_LAN_Hello(circuittype="L1")
        )
        packets = [no_encap, encap]

        if expect_copy:
            rxs = self.send_and_expect(sender, packets, receiver)
            for rx in rxs:
                if Ether in rx:
                    self.assertEqual(encap.show2(True), rx.show2(True))
                else:
                    self.assertEqual(no_encap.show2(True), rx.show2(True))
        else:
            self.send_and_assert_no_replies(sender, packets)

    def test_linux_cp_osi_passthrough(self):
        """Linux CP OSI proto passthrough"""

        # IS-IS should not be registered yet
        count_before = self.osi_proto_is_enabled(ISIS_PROTO, expected=False)

        # send IS-IS packets in both directions, they should not be forwarded
        self.send_isis_packets(self.phy, self.host, expect_copy=False)
        self.send_isis_packets(self.host, self.phy, expect_copy=False)

        # register IS-IS, verify success
        reply = self.vapi.lcp_osi_proto_enable(osi_proto=ISIS_PROTO)
        count_after = self.osi_proto_is_enabled(ISIS_PROTO, expected=True)
        self.assertEqual(count_after, count_before + 1)

        # re-send IS-IS packets, they should be forwarded now
        self.send_isis_packets(self.phy, self.host, expect_copy=True)
        self.send_isis_packets(self.host, self.phy, expect_copy=True)


@unittest.skipIf("linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests")
class TestLinuxCPOSINotLoaded(VppTestCase):
    """Linux CP OSI registration without osi_plugin"""

    extra_vpp_plugin_config = [
        "plugin linux_cp_plugin.so { enable }",
        "plugin osi_plugin.so { disable }",
    ]

    VNET_API_ERROR_FEATURE_DISABLED = -30

    @classmethod
    def setUpClass(cls):
        super(TestLinuxCPOSINotLoaded, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestLinuxCPOSINotLoaded, cls).tearDownClass()

    def setUp(self):
        super(TestLinuxCPOSINotLoaded, self).setUp()

    def tearDown(self):
        super(TestLinuxCPOSINotLoaded, self).tearDown()

    def test_linux_cp_osi_not_loaded(self):
        """Linux CP OSI proto registration without osi_plugin"""

        with self.vapi.assert_negative_api_retval():
            reply = self.vapi.lcp_osi_proto_enable(osi_proto=ISIS_PROTO)

        self.assertEqual(reply.retval, self.VNET_API_ERROR_FEATURE_DISABLED)


def _prefix_tuple(prefix):
    """Split a prefix string like "10.10.1.2/24" into ("10.10.1.2", 24)."""
    iface = ip_interface(prefix)
    return (str(iface.ip), iface.network.prefixlen)


def _cleanup_failure(failure, logger, description, fn):
    """Run a cleanup step without hiding the failure being propagated."""
    try:
        fn()
    except Exception as exc:
        if failure is None:
            raise
        logger.error("%s cleanup failed: %s", description, exc)


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
class TestLinuxCPSync(TestLinuxCPNetNSBase):
    """Linux CP VPP-to-Linux State Sync"""

    VNET_API_ERROR_ADDRESS_NOT_FOUND_FOR_INTERFACE = -60

    # Addresses assigned to loop0 in the IPv4/IPv6 address sync tests.
    loop0_prefixes_v4 = ["10.10.1.2/24", "10.10.2.2/24"]
    loop0_prefixes_v6 = ["2001:db8:1::2/64", "2001:db8:2::2/64"]
    # State applied to loop0 in the lcp-sync toggle test.
    loop0_toggle_prefix_v4 = "10.30.1.2/24"
    loop0_toggle_mtu = 3000

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_loopback_interfaces(2)
        cls.vapi.cli(f"lcp create loop0 host-if hloop0 netns {cls.ns_name}")
        cls.vapi.cli(f"lcp create loop1 host-if hloop1 netns {cls.ns_name}")

    def _get_ipv6_global_addresses(self, ifname):
        """Get non-link-local IPv6 addresses."""
        addrs = get_interface_addresses(self.ns_name, ifname, family="inet6")
        return sorted(
            [(addr, plen) for addr, plen in addrs if not addr.startswith("fe80:")]
        )

    def _add_addr(self, sw_if_index, prefix):
        self.vapi.sw_interface_add_del_address(sw_if_index=sw_if_index, prefix=prefix)

    def _del_addr(self, sw_if_index, prefix):
        self.vapi.sw_interface_add_del_address(
            sw_if_index=sw_if_index, prefix=prefix, is_add=0
        )

    def _vpp_has_ipv4_address(self, sw_if_index, prefix):
        """Return whether VPP reports an IPv4 address on an interface."""
        return any(
            str(address.prefix) == prefix
            for address in self.vapi.ip_address_dump(sw_if_index, is_ipv6=False)
        )

    def test_lcp_sync_admin_state(self):
        """VPP admin state changes sync to Linux"""
        # Loopbacks default to admin-down, so the host side should already
        # be down without waiting.
        self.assertFalse(is_interface_up(self.ns_name, "hloop0"))
        self.assertFalse(is_interface_up(self.ns_name, "hloop1"))

        # Bring loop0 up in VPP, verify Linux side
        self.lo_interfaces[0].admin_up()
        self.poll_for(
            "hloop0 up after VPP admin_up",
            lambda: is_interface_up(self.ns_name, "hloop0"),
            True,
        )
        self.assertFalse(is_interface_up(self.ns_name, "hloop1"))

        # Bring loop0 down in VPP, verify Linux side
        self.lo_interfaces[0].admin_down()
        self.poll_for(
            "hloop0 down after VPP admin_down",
            lambda: is_interface_up(self.ns_name, "hloop0"),
            False,
        )

        # Bring both up
        for lo in self.lo_interfaces:
            lo.admin_up()
        self.poll_for(
            "hloop0 up", lambda: is_interface_up(self.ns_name, "hloop0"), True
        )
        self.poll_for(
            "hloop1 up", lambda: is_interface_up(self.ns_name, "hloop1"), True
        )

        # Bring both down (cleanup)
        for lo in self.lo_interfaces:
            lo.admin_down()
        self.poll_for(
            "hloop0 down", lambda: is_interface_up(self.ns_name, "hloop0"), False
        )
        self.poll_for(
            "hloop1 down", lambda: is_interface_up(self.ns_name, "hloop1"), False
        )

    def test_lcp_sync_mtu(self):
        """VPP MTU changes sync to Linux"""
        loop0 = self.lo_interfaces[0]
        loop0.admin_up()
        self.poll_for(
            "hloop0 up", lambda: is_interface_up(self.ns_name, "hloop0"), True
        )

        for mtu in (4000, 1500, 9000):
            loop0.set_l3_mtu(mtu)
            self.poll_for(
                f"hloop0 mtu {mtu}",
                lambda: get_interface_mtu(self.ns_name, "hloop0"),
                mtu,
            )

        # Cleanup
        loop0.admin_down()

    def test_lcp_sync_ipv4_addr(self):
        """VPP IPv4 address changes sync to Linux"""
        loop0 = self.lo_interfaces[0]
        prefix_a, prefix_b = self.loop0_prefixes_v4
        tuple_a = _prefix_tuple(prefix_a)
        tuple_b = _prefix_tuple(prefix_b)

        loop0.admin_up()
        self.poll_for(
            "hloop0 up", lambda: is_interface_up(self.ns_name, "hloop0"), True
        )

        # Initially no IPv4 addresses
        self.poll_for(
            "hloop0 no initial ipv4",
            lambda: get_interface_addresses(self.ns_name, "hloop0", family="inet"),
            [],
        )

        # Add first IPv4 address
        self._add_addr(loop0.sw_if_index, prefix_a)
        self.poll_for(
            f"hloop0 has {prefix_a}",
            lambda: sorted(
                get_interface_addresses(self.ns_name, "hloop0", family="inet")
            ),
            [tuple_a],
        )

        # Add second IPv4 address
        self._add_addr(loop0.sw_if_index, prefix_b)
        self.poll_for(
            "hloop0 has both ipv4",
            lambda: sorted(
                get_interface_addresses(self.ns_name, "hloop0", family="inet")
            ),
            sorted([tuple_a, tuple_b]),
        )

        # Delete first address
        self._del_addr(loop0.sw_if_index, prefix_a)
        self.poll_for(
            f"hloop0 only {prefix_b}",
            lambda: sorted(
                get_interface_addresses(self.ns_name, "hloop0", family="inet")
            ),
            [tuple_b],
        )

        # Delete second address
        self._del_addr(loop0.sw_if_index, prefix_b)
        self.poll_for(
            "hloop0 no ipv4",
            lambda: get_interface_addresses(self.ns_name, "hloop0", family="inet"),
            [],
        )

        # Cleanup
        loop0.admin_down()

    def test_lcp_sync_ipv4_addr_delete_already_absent(self):
        """Deleting a VPP address after Linux removed it keeps state converged"""
        loop0 = self.lo_interfaces[0]
        prefix = "10.40.1.2/24"
        prefix_tuple = _prefix_tuple(prefix)

        try:
            loop0.admin_up()
            self.poll_for(
                "hloop0 up", lambda: is_interface_up(self.ns_name, "hloop0"), True
            )

            self._add_addr(loop0.sw_if_index, prefix)
            self.poll_for(
                f"hloop0 has {prefix}",
                lambda: prefix_tuple
                in get_interface_addresses(self.ns_name, "hloop0", family="inet"),
                True,
            )

            del_namespace_address(self.ns_name, "hloop0", prefix)
            self.poll_for(
                f"hloop0 no longer has {prefix}",
                lambda: prefix_tuple
                not in get_interface_addresses(self.ns_name, "hloop0", family="inet"),
                True,
            )
            # The Linux->VPP sync may already have removed the address.
            with self.vapi.assert_known_api_retval(
                [0, self.VNET_API_ERROR_ADDRESS_NOT_FOUND_FOR_INTERFACE]
            ):
                self._del_addr(loop0.sw_if_index, prefix)
            self.poll_for(
                f"VPP no longer has {prefix}",
                lambda: not self._vpp_has_ipv4_address(loop0.sw_if_index, prefix),
                True,
            )
            self.assertNotIn(
                prefix_tuple,
                get_interface_addresses(self.ns_name, "hloop0", family="inet"),
            )
        finally:
            if self._vpp_has_ipv4_address(loop0.sw_if_index, prefix):
                self._del_addr(loop0.sw_if_index, prefix)
            loop0.admin_down()

    def test_lcp_sync_ipv4_addr_external_delete_preserves_other_state(self):
        """Removing one Linux address does not sweep another valid VPP address"""
        loop0 = self.lo_interfaces[0]
        prefixes = ("10.40.3.2/24", "10.40.4.2/24")
        prefix_tuples = tuple(_prefix_tuple(prefix) for prefix in prefixes)

        try:
            loop0.admin_up()
            self.poll_for(
                "hloop0 up", lambda: is_interface_up(self.ns_name, "hloop0"), True
            )
            for prefix in prefixes:
                self._add_addr(loop0.sw_if_index, prefix)
            self.poll_for(
                "hloop0 has both ipv4 addresses",
                lambda: sorted(
                    get_interface_addresses(self.ns_name, "hloop0", family="inet")
                ),
                sorted(prefix_tuples),
            )

            del_namespace_address(self.ns_name, "hloop0", prefixes[0])
            self.poll_for(
                f"VPP removed {prefixes[0]}",
                lambda: not self._vpp_has_ipv4_address(loop0.sw_if_index, prefixes[0]),
                True,
            )

            self.assertTrue(self._vpp_has_ipv4_address(loop0.sw_if_index, prefixes[1]))
            self.assertEqual(
                sorted(get_interface_addresses(self.ns_name, "hloop0", family="inet")),
                [prefix_tuples[1]],
            )
        finally:
            for prefix in prefixes:
                if self._vpp_has_ipv4_address(loop0.sw_if_index, prefix):
                    self._del_addr(loop0.sw_if_index, prefix)
            loop0.admin_down()

    def test_lcp_sync_ipv6_addr(self):
        """VPP IPv6 address changes sync to Linux"""
        loop0 = self.lo_interfaces[0]
        prefix_a, prefix_b = self.loop0_prefixes_v6
        tuple_a = _prefix_tuple(prefix_a)
        tuple_b = _prefix_tuple(prefix_b)

        loop0.admin_up()
        self.poll_for(
            "hloop0 up", lambda: is_interface_up(self.ns_name, "hloop0"), True
        )

        # Initially no global IPv6 addresses (link-local may exist)
        self.poll_for(
            "hloop0 no initial global ipv6",
            lambda: self._get_ipv6_global_addresses("hloop0"),
            [],
        )

        # Add first IPv6 address
        self._add_addr(loop0.sw_if_index, prefix_a)
        self.poll_for(
            f"hloop0 has {prefix_a}",
            lambda: self._get_ipv6_global_addresses("hloop0"),
            [tuple_a],
        )

        # Add second IPv6 address
        self._add_addr(loop0.sw_if_index, prefix_b)
        self.poll_for(
            "hloop0 has both ipv6",
            lambda: self._get_ipv6_global_addresses("hloop0"),
            sorted([tuple_a, tuple_b]),
        )

        # Delete first address
        self._del_addr(loop0.sw_if_index, prefix_a)
        self.poll_for(
            f"hloop0 only {prefix_b}",
            lambda: self._get_ipv6_global_addresses("hloop0"),
            [tuple_b],
        )

        # Delete second address
        self._del_addr(loop0.sw_if_index, prefix_b)
        self.poll_for(
            "hloop0 no global ipv6",
            lambda: self._get_ipv6_global_addresses("hloop0"),
            [],
        )

        # Cleanup
        loop0.admin_down()

    def test_lcp_sync_toggle(self):
        """Disabling and re-enabling lcp-sync triggers full state push"""
        loop0 = self.lo_interfaces[0]
        prefix = self.loop0_toggle_prefix_v4
        prefix_tuple = _prefix_tuple(prefix)
        mtu = self.loop0_toggle_mtu

        # Disable sync
        self.vapi.cli("lcp lcp-sync off")
        try:
            # Make changes while sync is off
            loop0.admin_up()
            loop0.set_l3_mtu(mtu)
            self._add_addr(loop0.sw_if_index, prefix)

            # Give time for any spurious sync
            self.sleep(0.5)

            # Verify Linux side did NOT get the changes
            self.assertFalse(is_interface_up(self.ns_name, "hloop0"))
            self.assertNotEqual(get_interface_mtu(self.ns_name, "hloop0"), mtu)
            ipv4_addrs = get_interface_addresses(self.ns_name, "hloop0", family="inet")
            self.assertNotIn(prefix_tuple, ipv4_addrs)

            # Re-enable sync (triggers lcp_itf_pair_sync_state_all)
            self.vapi.cli("lcp lcp-sync on")

            # Now poll for the state to appear
            self.poll_for(
                "hloop0 up after re-sync",
                lambda: is_interface_up(self.ns_name, "hloop0"),
                True,
            )
            self.poll_for(
                f"hloop0 mtu {mtu} after re-sync",
                lambda: get_interface_mtu(self.ns_name, "hloop0"),
                mtu,
            )
            self.poll_for(
                f"hloop0 has {prefix} after re-sync",
                lambda: get_interface_addresses(self.ns_name, "hloop0", family="inet"),
                [prefix_tuple],
            )

            # Cleanup VPP state
            self._del_addr(loop0.sw_if_index, prefix)
            loop0.admin_down()
        finally:
            self.vapi.cli("lcp lcp-sync on")


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
class TestLinuxCPLinuxToVPP(TestLinuxCPNetNSBase):
    """Linux CP Linux-to-VPP Sync"""

    # Initial IPv4 assignments so routes/neighbors can be added on the Linux side.
    loop0_prefix_v4 = "10.10.1.2/24"
    loop1_prefix_v4 = "10.20.1.2/24"
    # IPv6 address needed on loop0 for the NDP neighbor test.
    loop0_prefix_v6 = "2001:db8:10::2/64"
    # Neighbors added from the Linux side to verify they sync to VPP.
    loop0_neighbor_v4 = "10.10.1.100"
    loop0_neighbor_v4_mac = "02:01:02:03:04:05"
    loop0_neighbor_v6 = "2001:db8:10::100"
    loop0_neighbor_v6_mac = "02:01:02:03:04:06"
    # Addresses added on the Linux side to verify they sync to VPP.
    loop0_linux_added_v4 = "10.10.5.1/24"
    loop0_linux_added_v6 = "2001:db8:20::1/64"
    # Special route types synced from Linux to VPP.
    route_blackhole = "192.168.50.0/24"
    route_unreachable = "192.168.51.0/24"
    route_prohibit = "192.168.52.0/24"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_loopback_interfaces(2)
        cls.vapi.cli(f"lcp create loop0 host-if hloop0 netns {cls.ns_name}")
        cls.vapi.cli(f"lcp create loop1 host-if hloop1 netns {cls.ns_name}")

        # Configure IPs and bring up so routes/neighbors can be added
        cls.vapi.sw_interface_add_del_address(
            sw_if_index=cls.lo_interfaces[0].sw_if_index, prefix=cls.loop0_prefix_v4
        )
        cls.vapi.sw_interface_add_del_address(
            sw_if_index=cls.lo_interfaces[1].sw_if_index, prefix=cls.loop1_prefix_v4
        )
        for lo in cls.lo_interfaces:
            lo.admin_up()

    def _route_exists(self, prefix):
        """Check if an exact route exists in VPP FIB."""
        try:
            self.vapi.api(
                self.vapi.papi.ip_route_lookup,
                {"table_id": 0, "exact": True, "prefix": prefix},
            )
            return True
        except Exception:
            return False

    def test_linux_to_vpp_route_blackhole(self):
        """Linux blackhole route syncs to VPP as DROP"""
        add_namespace_route(self.ns_name, self.route_blackhole, route_type="blackhole")

        lookup_addr = str(ip_interface(self.route_blackhole).network[1]) + "/32"
        self.verify_paths(lookup_addr, dict(type=FibPathType.FIB_PATH_TYPE_DROP))

        # Verify delete is also synced
        del_namespace_route(self.ns_name, self.route_blackhole)
        self.poll_for(
            "blackhole route removed from VPP",
            lambda: self._route_exists(self.route_blackhole),
            False,
        )

    def test_linux_to_vpp_route_unreachable(self):
        """Linux unreachable route syncs to VPP as ICMP_UNREACH"""
        add_namespace_route(
            self.ns_name, self.route_unreachable, route_type="unreachable"
        )

        lookup_addr = str(ip_interface(self.route_unreachable).network[1]) + "/32"
        self.verify_paths(
            lookup_addr, dict(type=FibPathType.FIB_PATH_TYPE_ICMP_UNREACH)
        )

        # Verify delete is also synced
        del_namespace_route(self.ns_name, self.route_unreachable)
        self.poll_for(
            "unreachable route removed from VPP",
            lambda: self._route_exists(self.route_unreachable),
            False,
        )

    def test_linux_to_vpp_route_prohibit(self):
        """Linux prohibit route syncs to VPP as ICMP_PROHIBIT"""
        add_namespace_route(self.ns_name, self.route_prohibit, route_type="prohibit")

        lookup_addr = str(ip_interface(self.route_prohibit).network[1]) + "/32"
        self.verify_paths(
            lookup_addr, dict(type=FibPathType.FIB_PATH_TYPE_ICMP_PROHIBIT)
        )

        # Verify delete is also synced
        del_namespace_route(self.ns_name, self.route_prohibit)
        self.poll_for(
            "prohibit route removed from VPP",
            lambda: self._route_exists(self.route_prohibit),
            False,
        )

    def _find_neighbor(self, sw_if_index, nbr_addr, mac=None):
        """Find a neighbor entry in VPP regardless of static/dynamic flag."""
        ip_addr = ip_address(nbr_addr)
        nbrs = self.vapi.ip_neighbor_dump(sw_if_index=sw_if_index, af=ip_addr.vapi_af)
        for n in nbrs:
            if (
                sw_if_index == n.neighbor.sw_if_index
                and ip_addr == n.neighbor.ip_address
            ):
                if mac is None or mac == str(n.neighbor.mac_address):
                    return True
        return False

    def test_linux_to_vpp_neighbor_ipv4(self):
        """Linux ARP neighbor entries sync to VPP"""
        lo0_idx = self.lo_interfaces[0].sw_if_index
        nbr = self.loop0_neighbor_v4

        # Add static ARP entry in namespace
        add_namespace_neighbor(self.ns_name, "hloop0", nbr, self.loop0_neighbor_v4_mac)

        self.poll_for(
            f"neighbor {nbr} in VPP",
            lambda: self._find_neighbor(lo0_idx, nbr, mac=self.loop0_neighbor_v4_mac),
            True,
        )

        # Delete the neighbor
        del_namespace_neighbor(self.ns_name, "hloop0", nbr)

        self.poll_for(
            f"neighbor {nbr} removed from VPP",
            lambda: self._find_neighbor(lo0_idx, nbr),
            False,
        )

    def test_linux_to_vpp_neighbor_ipv6(self):
        """Linux NDP neighbor entries sync to VPP"""
        loop0 = self.lo_interfaces[0]
        nbr = self.loop0_neighbor_v6

        # Need an IPv6 address on the interface for NDP
        self.vapi.sw_interface_add_del_address(
            sw_if_index=loop0.sw_if_index, prefix=self.loop0_prefix_v6
        )

        add_namespace_neighbor(self.ns_name, "hloop0", nbr, self.loop0_neighbor_v6_mac)

        self.poll_for(
            f"neighbor {nbr} in VPP",
            lambda: self._find_neighbor(
                loop0.sw_if_index, nbr, mac=self.loop0_neighbor_v6_mac
            ),
            True,
        )

        del_namespace_neighbor(self.ns_name, "hloop0", nbr)

        self.poll_for(
            f"neighbor {nbr} removed from VPP",
            lambda: self._find_neighbor(loop0.sw_if_index, nbr),
            False,
        )

        # Cleanup
        self.vapi.sw_interface_add_del_address(
            sw_if_index=loop0.sw_if_index, prefix=self.loop0_prefix_v6, is_add=0
        )

    def test_linux_to_vpp_ipv4_addr(self):
        """Linux IPv4 address changes sync to VPP"""
        lo0_idx = self.lo_interfaces[0].sw_if_index
        prefix = self.loop0_linux_added_v4

        # Add an address from the Linux side
        add_namespace_address(self.ns_name, "hloop0", prefix)

        self.poll_for(
            f"{prefix} on loop0 in VPP",
            lambda: any(
                str(a.prefix) == prefix
                for a in self.vapi.ip_address_dump(lo0_idx, is_ipv6=False)
            ),
            True,
        )

        # Delete the address from Linux side
        del_namespace_address(self.ns_name, "hloop0", prefix)

        self.poll_for(
            f"{prefix} removed from loop0 in VPP",
            lambda: any(
                str(a.prefix) == prefix
                for a in self.vapi.ip_address_dump(lo0_idx, is_ipv6=False)
            ),
            False,
        )

    def test_linux_to_vpp_ipv6_addr(self):
        """Linux IPv6 address changes sync to VPP"""
        lo0_idx = self.lo_interfaces[0].sw_if_index
        prefix = self.loop0_linux_added_v6

        # Add an IPv6 address from the Linux side
        add_namespace_address(self.ns_name, "hloop0", prefix)

        self.poll_for(
            f"{prefix} on loop0 in VPP",
            lambda: any(
                str(a.prefix) == prefix
                for a in self.vapi.ip_address_dump(lo0_idx, is_ipv6=True)
            ),
            True,
        )

        # Delete the address from Linux side
        del_namespace_address(self.ns_name, "hloop0", prefix)

        self.poll_for(
            f"{prefix} removed from loop0 in VPP",
            lambda: any(
                str(a.prefix) == prefix
                for a in self.vapi.ip_address_dump(lo0_idx, is_ipv6=True)
            ),
            False,
        )


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
@unittest.skipIf(
    "linux-cp" in config.excluded_plugins or "linux-nl" in config.excluded_plugins,
    "Exclude linux-cp route tests",
)
class TestLinuxCPOnlinkRoute(TestLinuxCPNetNSBase):
    """A route whose gateway the kernel marks onlink is installed into the FIB."""

    # The gateway belongs to no prefix connected on hloop0: hloop0 holds
    # 10.10.1.2/24, and this route names 10.10.9.1 beyond its edge.
    prefix = "199.18.0.0/26"
    gateway = "10.10.9.1"
    loop0_address = "10.10.1.2/24"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_loopback_interfaces(1)
        cls.loop0 = cls.lo_interfaces[0]
        cls.vapi.cli(f"lcp create loop0 host-if hloop0 netns {cls.ns_name}")
        cls.vapi.sw_interface_add_del_address(
            sw_if_index=cls.loop0.sw_if_index, prefix=cls.loop0_address
        )
        cls.loop0.admin_up()

    def _namespace_route(self, *extra):
        """Run ip route against the namespace, returning the completed process."""
        return subprocess.run(
            ["ip", "netns", "exec", self.ns_name, "ip", "route", *extra],
            capture_output=True,
            text=True,
            check=False,
        )

    def _exact_entry_flags(self, prefix):
        """Return the source flags of the exact FIB entry, or None.

        The CLI lookup is longest-prefix, so the flags of a covering entry
        would be reported for a prefix that has no entry of its own. The
        header line names the entry actually found, and only a header equal to
        the requested prefix is accepted.
        """
        output = self.vapi.cli(f"show ip fib table 0 {prefix} detail")
        found = False
        for line in output.splitlines():
            fields = line.split()
            if not fields:
                continue
            if not line[0].isspace():
                found = fields[0] == prefix
                continue
            if not found:
                continue
            for field in fields:
                if field.startswith("entry-flags:"):
                    return field.split(":", 1)[1]
        return None

    def _gateway_attached(self, gateway=None):
        gateway = self.gateway if gateway is None else gateway
        return "attached," in (self._exact_entry_flags(f"{gateway}/32") or "")

    def _route_paths(self):
        """Return the paths of the exact prefix, as the API reports them."""
        for entry in self.vapi.ip_route_dump(0, False):
            if str(entry.route.prefix) == self.prefix:
                return entry.route.paths
        return None

    def test_onlink_gateway_route(self):
        """An onlink route's gateway gets the attached prefix it needs to resolve"""
        # The kernel refuses this gateway without the flag, which establishes
        # that it is outside every prefix connected on hloop0.
        outside = self._namespace_route(
            "add", self.prefix, "via", self.gateway, "dev", "hloop0"
        )
        self.assertNotEqual(
            outside.returncode,
            0,
            f"the kernel accepted {self.gateway} without onlink: the test needs "
            "a gateway outside every connected prefix",
        )
        self.assertIsNone(
            self._exact_entry_flags(f"{self.gateway}/32"),
            "the gateway already has a FIB entry: the test cannot tell the fix "
            "from the state before it",
        )

        onlink = self._namespace_route(
            "add", self.prefix, "via", self.gateway, "dev", "hloop0", "onlink"
        )
        self.assertEqual(onlink.returncode, 0, onlink.stderr)
        try:
            # The route reaches the FIB with the gateway as its nexthop.
            self.poll_for(
                f"{self.prefix} in VPP",
                lambda: self._route_paths() is not None,
                True,
            )
            paths = self._route_paths()
            self.assertEqual(len(paths), 1)
            self.assertEqual(paths[0].sw_if_index, self.loop0.sw_if_index)
            self.assertEqual(str(paths[0].nh.address.ip4), self.gateway)

            # The gateway's host prefix is installed as an attached entry.
            # This is the shape arp_reply() requires before it accepts a reply
            # from an address no connected prefix covers; without it the
            # gateway is never learned and the route carries no usable
            # neighbour. Nothing else in VPP installs this entry: the kernel
            # route is not a host route, so it would not exist before the fix.
            self.poll_for(
                f"{self.gateway}/32 attached in VPP",
                self._gateway_attached,
                True,
            )
        finally:
            self._namespace_route("del", self.prefix)
            self.poll_for(
                f"{self.prefix} removed from VPP",
                lambda: self._route_paths() is None,
                True,
            )
            # The attached host prefix goes with the last route naming it, so
            # a deleted route leaves nothing behind.
            self.poll_for(
                f"{self.gateway}/32 gone from VPP",
                lambda: self._exact_entry_flags(f"{self.gateway}/32"),
                None,
            )

    def test_offnet_gateway_without_onlink(self):
        """A route without the flag installs no attached host entry of its own"""
        gateway = "10.10.1.1"
        prefix = "199.19.0.0/26"

        added = self._namespace_route("add", prefix, "via", gateway, "dev", "hloop0")
        self.assertEqual(added.returncode, 0, added.stderr)
        try:
            self.poll_for(
                f"{prefix} in VPP",
                lambda: any(
                    str(entry.route.prefix) == prefix
                    for entry in self.vapi.ip_route_dump(0, False)
                ),
                True,
            )
            # The gateway sits inside 10.10.1.2/24, so the kernel route needs
            # no attached prefix of ours, and none is installed: the plugin's
            # onlink source owns no entry with the gateway's exact prefix. The
            # CLI lookup is longest-prefix, so the detail of the gateway's
            # prefix reaches the connected entry that covers it; asking for
            # the exact entry is what tells the two apart.
            self.assertIsNone(
                self._exact_entry_flags(f"{gateway}/32"),
                "a route without RTNH_F_ONLINK must not install an attached "
                "host prefix",
            )
        finally:
            self._namespace_route("del", prefix)

    def test_onlink_partial_delete_keeps_surviving_gateway(self):
        """Deleting one nexthop of an onlink route leaves the other resolvable"""
        second = "10.10.9.2"

        added = self._namespace_route(
            "add",
            self.prefix,
            "via",
            self.gateway,
            "dev",
            "hloop0",
            "onlink",
            "metric",
            "10",
        )
        self.assertEqual(added.returncode, 0, added.stderr)
        added = self._namespace_route(
            "add", self.prefix, "via", second, "dev", "hloop0", "onlink", "metric", "20"
        )
        self.assertEqual(added.returncode, 0, added.stderr)
        try:
            # Two nexthops, and an attached host prefix for each gateway.
            self.poll_for(
                f"{self.prefix} with two paths in VPP",
                lambda: len(self._route_paths() or []) == 2,
                True,
            )
            for gateway in (self.gateway, second):
                self.poll_for(
                    f"{gateway}/32 attached in VPP",
                    lambda gateway=gateway: "attached,"
                    in (self._exact_entry_flags(f"{gateway}/32") or ""),
                    True,
                )

            # The kernel deletes one nexthop. The route stays, so the gateway
            # of the path that goes must give its attached host prefix up and
            # the one of the path that stays must keep its own.
            removed = self._namespace_route("del", self.prefix, "via", self.gateway)
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.poll_for(
                "the surviving path is the only one in VPP",
                lambda: [str(path.nh.address.ip4) for path in self._route_paths() or []]
                == [second],
                True,
            )
            self.poll_for(
                f"{self.gateway}/32 gone from VPP",
                lambda: self._exact_entry_flags(f"{self.gateway}/32"),
                None,
            )
            self.assertEqual(
                self._gateway_attached(second),
                True,
                "the surviving path's gateway lost the attached host prefix "
                "that makes it resolvable",
            )
        finally:
            self._namespace_route("del", self.prefix)

    def test_blackhole_delete_keeps_unicast_gateway(self):
        """Deleting a blackhole route leaves the unicast route of the prefix alone"""
        # The kernel keys routes by prefix, so the two coexist and the delete
        # of the blackhole route carries no nexthop at all. The unicast route
        # and its gateway must be untouched by it.
        added = self._namespace_route(
            "add",
            self.prefix,
            "via",
            self.gateway,
            "dev",
            "hloop0",
            "onlink",
            "metric",
            "10",
        )
        self.assertEqual(added.returncode, 0, added.stderr)
        added = self._namespace_route("add", "blackhole", self.prefix, "metric", "20")
        self.assertEqual(added.returncode, 0, added.stderr)
        try:
            self.poll_for(
                f"{self.prefix} in VPP",
                lambda: self._route_paths() is not None,
                True,
            )
            self.poll_for(
                f"{self.gateway}/32 attached in VPP",
                self._gateway_attached,
                True,
            )

            removed = self._namespace_route(
                "del", "blackhole", self.prefix, "metric", "20"
            )
            self.assertEqual(removed.returncode, 0, removed.stderr)
            # The kernel keeps the unicast route, and so must the plugin keep
            # its gateway's attached prefix.
            self.poll_for(
                "the unicast route is still the only path in VPP",
                lambda: [str(path.nh.address.ip4) for path in self._route_paths() or []]
                == [self.gateway],
                True,
            )
            self.assertEqual(
                self._gateway_attached(),
                True,
                "deleting the blackhole route tore down the attached host "
                "prefix of the unicast route that survived it",
            )
        finally:
            self._namespace_route("del", "blackhole", self.prefix, "metric", "20")
            self._namespace_route("del", self.prefix)


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
class TestLinuxCPPairManagement(TestLinuxCPNetNSBase):
    """Linux CP Interface Pair Management"""

    def _get_lcp_pairs(self):
        """Get all LCP pairs as a list of dicts."""
        return list(self.vapi.vpp.details_iter(self.vapi.lcp_itf_pair_get))

    def _find_lcp_pair(self, phy_sw_if_index):
        """Find an LCP pair by phy sw_if_index."""
        for p in self._get_lcp_pairs():
            if p.phy_sw_if_index == phy_sw_if_index:
                return p
        return None

    def _gre_linux_route_source_present(self, prefix):
        output = self.vapi.cli(f"show ip fib table 0 {prefix} detail")
        in_prefix = False
        for line in output.splitlines():
            fields = line.split()
            if not fields:
                continue
            if not line[0].isspace():
                in_prefix = fields[0] == prefix
            elif (
                in_prefix
                and fields[0] == "lcp-rt"
                and len(fields) > 1
                and fields[1].startswith("refs:")
            ):
                return True
        return False

    def _exact_route_paths(self, prefix):
        is_ipv6 = ip_interface(prefix).version == 6
        routes = [
            entry.route
            for entry in self.vapi.ip_route_dump(0, is_ipv6)
            if str(entry.route.prefix) == prefix
        ]
        self.assertLessEqual(len(routes), 1)
        if not routes:
            return None
        return sorted(
            (
                path.type,
                path.sw_if_index,
                str(path.nh.address.ip6 if is_ipv6 else path.nh.address.ip4),
            )
            for path in routes[0].paths
        )

    def _verify_exact_route_paths(self, prefix, *expected):
        self.poll_for(
            f"exact paths for {prefix}",
            lambda: self._exact_route_paths(prefix),
            sorted(expected),
        )

    def _test_pair_route_cleanup(self, protocol, is_ipv6):
        self.create_loopback_interfaces(3)
        pair_a, pair_b, api_interface = self.lo_interfaces
        prefix = "2001:db8:100::/64" if is_ipv6 else "198.18.100.0/24"
        gateways = (
            ("2001:db8:10::1", "2001:db8:20::1", "2001:db8:30::1")
            if is_ipv6
            else ("10.10.1.1", "10.20.1.1", "10.30.1.1")
        )
        addresses = (
            ("2001:db8:10::2/64", "2001:db8:20::2/64", "2001:db8:30::2/64")
            if is_ipv6
            else ("10.10.1.2/24", "10.20.1.2/24", "10.30.1.2/24")
        )
        active_pairs = []
        api_route = None
        try:
            for interface, host in ((pair_a, "hclean0"), (pair_b, "hclean1")):
                self.vapi.cli(
                    f"lcp create {interface.name} host-if {host} netns {self.ns_name}"
                )
                active_pairs.append(interface)
            for interface, address in zip(self.lo_interfaces, addresses):
                self.vapi.sw_interface_add_del_address(
                    sw_if_index=interface.sw_if_index, prefix=address
                )
                interface.admin_up()
            for host, address in zip(("hclean0", "hclean1"), addresses):
                self.poll_for(
                    f"{host} has {address}",
                    lambda: _prefix_tuple(address)
                    in get_interface_addresses(
                        self.ns_name, host, family="inet6" if is_ipv6 else "inet"
                    ),
                    True,
                )

            network = ip_interface(prefix).network
            api_route = VppIpRoute(
                self,
                str(network.network_address),
                network.prefixlen,
                [VppRoutePath(gateways[2], api_interface.sw_if_index)],
            ).add_vpp_config()
            paths = [
                (FibPathType.FIB_PATH_TYPE_NORMAL, interface.sw_if_index, gateway)
                for interface, gateway in zip(self.lo_interfaces, gateways)
            ]
            self._verify_exact_route_paths(prefix, paths[2])
            subprocess.run(
                [
                    "ip",
                    "-n",
                    self.ns_name,
                    "-6" if is_ipv6 else "-4",
                    "route",
                    "add",
                    prefix,
                    "proto",
                    str(protocol),
                    *NextHop(gw_ip=gateways[0], dev="hclean0").args(),
                    *NextHop(gw_ip=gateways[1], dev="hclean1").args(),
                ],
                capture_output=True,
                check=True,
            )
            self._verify_exact_route_paths(prefix, paths[0], paths[1])

            self.vapi.cli(f"lcp delete {pair_a.name}")
            active_pairs.remove(pair_a)
            self.assertIsNone(self._find_lcp_pair(pair_a.sw_if_index))
            self.assertIsNotNone(self._find_lcp_pair(pair_b.sw_if_index))
            self._verify_exact_route_paths(prefix, paths[1])

            self.vapi.cli(f"lcp delete {pair_b.name}")
            active_pairs.remove(pair_b)
            self.assertIsNone(self._find_lcp_pair(pair_b.sw_if_index))
            self._verify_exact_route_paths(prefix, paths[2])
            for interface, address in zip(self.lo_interfaces, addresses):
                self.assertEqual(
                    [
                        str(entry.prefix)
                        for entry in self.vapi.ip_address_dump(
                            interface.sw_if_index, is_ipv6=is_ipv6
                        )
                    ],
                    [address],
                )
            api_route.remove_vpp_config()
            api_route = None
            self.poll_for(
                f"{prefix} absent after API removal",
                lambda: self._exact_route_paths(prefix),
                None,
            )
        finally:
            for interface in active_pairs:
                self.vapi.cli(f"lcp delete {interface.name}")
            if api_route is not None:
                api_route.remove_vpp_config()
            for interface in self.lo_interfaces:
                interface.admin_down()
                interface.remove_vpp_config()

    @unittest.skipIf(
        "linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests"
    )
    def test_pair_delete_static_routes_ipv4(self):
        """Pair deletion preserves IPv4 static multipath and API ownership"""
        self._test_pair_route_cleanup(4, False)

    @unittest.skipIf(
        "linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests"
    )
    def test_pair_delete_dynamic_routes_ipv4(self):
        """Pair deletion preserves IPv4 dynamic multipath and API ownership"""
        self._test_pair_route_cleanup(186, False)

    @unittest.skipIf(
        "linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests"
    )
    def test_pair_delete_static_routes_ipv6(self):
        """Pair deletion preserves IPv6 static multipath and API ownership"""
        self._test_pair_route_cleanup(4, True)

    @unittest.skipIf(
        "linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests"
    )
    def test_pair_delete_dynamic_routes_ipv6(self):
        """Pair deletion preserves IPv6 dynamic multipath and API ownership"""
        self._test_pair_route_cleanup(186, True)

    def test_pair_create_delete_tun(self):
        """Create and delete TUN LCP pair on loopback"""
        self.create_loopback_interfaces(1)
        lo = self.lo_interfaces[0]

        # Create LCP pair in TUN mode
        self.vapi.cli(f"lcp create {lo.name} host-if htun0 netns {self.ns_name} tun")

        # Verify pair exists in API with correct type
        pair = self._find_lcp_pair(lo.sw_if_index)
        self.assertIsNotNone(pair, "LCP pair should exist")
        self.assertEqual(pair.host_if_name, "htun0")
        self.assertEqual(pair.host_if_type, 1, "host_if_type should be TUN (1)")

        # Verify host interface exists in namespace
        self.assertTrue(
            interface_exists(self.ns_name, "htun0"),
            "htun0 should exist in namespace",
        )

        # Delete the pair
        self.vapi.cli(f"lcp delete {lo.name}")

        # Verify pair is gone
        self.assertIsNone(
            self._find_lcp_pair(lo.sw_if_index),
            "LCP pair should be gone after delete",
        )

        # Verify host interface is gone
        self.poll_for(
            "htun0 gone from namespace",
            lambda: interface_exists(self.ns_name, "htun0"),
            False,
        )

    @unittest.skipIf(
        "linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests"
    )
    @unittest.skipIf("gre" in config.excluded_plugins, "Exclude GRE plugin tests")
    def test_gre_lcp_ipv4_survives_pair_churn(self):
        self.create_pg_interfaces(range(1))
        underlay = self.pg_interfaces[0]
        gre_if = VppGreInterface(self, underlay.local_ip4, underlay.remote_ip4)
        sender = None
        capture_active = False
        gre_created = False
        route_created = False
        pair_created = False
        linux_route_present = False
        ready_file = os.path.join(self.tempdir, "gre_lcp_sender_ready")
        go_file = os.path.join(self.tempdir, "gre_lcp_sender_go")
        inner_dst = "198.18.0.1"

        try:
            underlay.admin_up()
            underlay.config_ip4()
            underlay.resolve_arp()

            gre_if.add_vpp_config()
            gre_created = True
            gre_if.admin_up()
            self.vapi.cli(
                f"lcp create {gre_if.name} host-if hgre0 netns {self.ns_name} tun"
            )
            pair_created = True
            self.poll_for(
                "GRE LCP pair exists",
                lambda: self._find_lcp_pair(gre_if.sw_if_index) is not None,
                True,
            )
            pair = self._find_lcp_pair(gre_if.sw_if_index)
            self.assertIsNotNone(pair)
            self.assertEqual(pair.host_if_type, 1, "GRE LCP pair should use TUN")

            gre_if.config_ip4()
            route = VppIpRoute(
                self,
                inner_dst,
                32,
                [VppRoutePath("0.0.0.0", gre_if.sw_if_index)],
            )
            route.add_vpp_config()
            route_created = True
            expected_path = dict(
                type=FibPathType.FIB_PATH_TYPE_NORMAL,
                sw_if_index=gre_if.sw_if_index,
                ip4=inner_dst,
            )
            self.verify_paths(f"{inner_dst}/32", expected_path)
            expected_address = [_prefix_tuple(gre_if.local_ip4_prefix)]
            self.poll_for(
                "hgre0 has GRE IPv4 address",
                lambda: get_interface_addresses(self.ns_name, "hgre0", family="inet"),
                expected_address,
            )
            add_namespace_route(self.ns_name, f"{inner_dst}/32", dev="hgre0")
            linux_route_present = True
            self.poll_for(
                "GRE Linux route source present",
                lambda: self._gre_linux_route_source_present(f"{inner_dst}/32"),
                True,
            )
            self.verify_paths(f"{inner_dst}/32", expected_path)
            self._verify_exact_route_paths(
                f"{inner_dst}/32",
                (FibPathType.FIB_PATH_TYPE_NORMAL, gre_if.sw_if_index, inner_dst),
            )

            sender_script = """
import os
import sys
import time
from scapy.error import Scapy_Exception
from scapy.all import IP, Raw, UDP, send

iface, source, destination, ready, go = sys.argv[1:]
def send_packet(sequence, tolerate_errors=False):
    try:
        send(IP(src=source, dst=destination) / UDP(sport=1234, dport=1234) / Raw(str(sequence).encode()), iface=iface, verbose=0)
    except (OSError, Scapy_Exception, ValueError):
        if not tolerate_errors:
            raise

for sequence in range(20):
    send_packet(sequence)
open(ready, "w").close()
while not os.path.exists(go):
    send_packet(20, tolerate_errors=True)
    time.sleep(0.01)
for sequence in range(100, 130):
    send_packet(sequence)
    time.sleep(0.01)
"""
            underlay.enable_capture()
            capture_active = True
            sender = subprocess.Popen(
                [
                    "ip",
                    "netns",
                    "exec",
                    self.ns_name,
                    "python3",
                    "-c",
                    sender_script,
                    "hgre0",
                    gre_if.local_ip4,
                    inner_dst,
                    ready_file,
                    go_file,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            def _sender_ready():
                self.assertIsNone(
                    sender.poll(), "inner IPv4 sender exited before churn"
                )
                return os.path.exists(ready_file)

            self.poll_for(
                "inner IPv4 sender is active",
                _sender_ready,
                True,
                timeout=10,
            )
            self.assertIsNone(self.vpp.poll(), "VPP must be alive before churn")

            gre_if.admin_down()
            self.poll_for(
                "hgre0 down after GRE admin_down",
                lambda: is_interface_up(self.ns_name, "hgre0"),
                False,
            )
            gre_if.admin_up()
            self.poll_for(
                "hgre0 up after GRE admin_up",
                lambda: is_interface_up(self.ns_name, "hgre0"),
                True,
            )

            self.vapi.cli(f"lcp delete {gre_if.name}")
            pair_created = False
            self.poll_for(
                "GRE LCP pair removed",
                lambda: self._find_lcp_pair(gre_if.sw_if_index) is not None,
                False,
            )
            self.poll_for(
                "hgre0 removed after pair delete",
                lambda: interface_exists(self.ns_name, "hgre0"),
                False,
            )
            self.poll_for(
                "GRE Linux route source removed after pair delete",
                lambda: self._gre_linux_route_source_present(f"{inner_dst}/32"),
                False,
            )
            self._verify_exact_route_paths(
                f"{inner_dst}/32",
                (FibPathType.FIB_PATH_TYPE_NORMAL, gre_if.sw_if_index, inner_dst),
            )
            self.assertEqual(
                [
                    str(address.prefix)
                    for address in self.vapi.ip_address_dump(
                        gre_if.sw_if_index, is_ipv6=False
                    )
                ],
                [gre_if.local_ip4_prefix],
            )
            del_namespace_route(self.ns_name, f"{inner_dst}/32", check=False)
            linux_route_present = False
            self.assertIsNone(self.vpp.poll(), "VPP must be alive after pair delete")

            self.vapi.cli(
                f"lcp create {gre_if.name} host-if hgre0 netns {self.ns_name} tun"
            )
            pair_created = True
            self.poll_for(
                "GRE LCP pair recreated",
                lambda: self._find_lcp_pair(gre_if.sw_if_index) is not None,
                True,
            )
            self.poll_for(
                "hgre0 recreated",
                lambda: interface_exists(self.ns_name, "hgre0"),
                True,
            )
            self.assertEqual(
                [
                    str(address.prefix)
                    for address in self.vapi.ip_address_dump(
                        gre_if.sw_if_index, is_ipv6=False
                    )
                ],
                [gre_if.local_ip4_prefix],
            )
            self.verify_paths(f"{inner_dst}/32", expected_path)
            self.vapi.cli("lcp lcp-sync on")
            self.poll_for(
                "hgre0 has GRE IPv4 address after recreation",
                lambda: get_interface_addresses(self.ns_name, "hgre0", family="inet"),
                expected_address,
            )
            add_namespace_route(self.ns_name, f"{inner_dst}/32", dev="hgre0")
            linux_route_present = True
            self.verify_paths(f"{inner_dst}/32", expected_path)
            self.assertTrue(gre_if.query_vpp_config())
            self.assertIn(gre_if.name, self.vapi.cli("show adj"))
            self.assertIsNone(
                self.vpp.poll(), "VPP must be alive after pair recreation"
            )

            with open(go_file, "w"):
                pass
            sender.wait(timeout=10)
            self.assertEqual(sender.returncode, 0, "inner IPv4 sender failed")

            def _capture_inner_sequences():
                captured = underlay._get_capture()
                if captured is None:
                    return []
                sequences = []
                for packet in captured:
                    if packet.haslayer(GRE):
                        inner = IP(bytes(packet[GRE].payload))
                        if inner.dst == inner_dst and inner.haslayer(Raw):
                            sequences.append(int(bytes(inner[Raw].load)))
                return sequences

            self.poll_for(
                "capture has pre- and post-churn inner packets",
                lambda: any(sequence < 20 for sequence in _capture_inner_sequences())
                and any(sequence >= 100 for sequence in _capture_inner_sequences()),
                True,
                timeout=10,
            )
            underlay.disable_capture()
            capture_active = False
            inner_sequences = _capture_inner_sequences()
            self.assertTrue(any(sequence < 20 for sequence in inner_sequences))
            self.assertTrue(any(sequence >= 100 for sequence in inner_sequences))

            self.vapi.cli(f"lcp delete {gre_if.name}")
            pair_created = False
            self._verify_exact_route_paths(
                f"{inner_dst}/32",
                (FibPathType.FIB_PATH_TYPE_NORMAL, gre_if.sw_if_index, inner_dst),
            )
            route.remove_vpp_config()
            route_created = False
            self.poll_for(
                "GRE route absent after API removal",
                lambda: find_route(self, inner_dst, 32),
                False,
            )
        finally:
            if sender is not None and sender.poll() is None:
                sender.terminate()
                sender.wait(timeout=5)
            if capture_active:
                underlay.disable_capture()
            if pair_created:
                self.vapi.cli(f"lcp delete {gre_if.name}")
            if linux_route_present:
                del_namespace_route(self.ns_name, f"{inner_dst}/32", check=False)
            if route_created:
                route.remove_vpp_config()
            if gre_created:
                gre_if.remove_vpp_config()
            underlay.unconfig_ip4()
            underlay.admin_down()

    def test_pair_create_delete_tap(self):
        """Create and delete TAP LCP pair on pg interface"""
        self.create_pg_interfaces(range(1))
        pg = self.pg_interfaces[0]

        # Create LCP pair (TAP mode, default for ethernet)
        self.vapi.cli(f"lcp create {pg.name} host-if htap0 netns {self.ns_name}")

        # Verify pair exists in API with correct type
        pair = self._find_lcp_pair(pg.sw_if_index)
        self.assertIsNotNone(pair, "LCP pair should exist")
        self.assertEqual(pair.host_if_name, "htap0")
        self.assertEqual(pair.host_if_type, 0, "host_if_type should be TAP (0)")

        # Verify host interface exists in namespace
        self.assertTrue(
            interface_exists(self.ns_name, "htap0"),
            "htap0 should exist in namespace",
        )

        # Delete the pair
        self.vapi.cli(f"lcp delete {pg.name}")

        # Verify pair is gone
        self.assertIsNone(
            self._find_lcp_pair(pg.sw_if_index),
            "LCP pair should be gone after delete",
        )

        # Verify host interface is gone
        self.poll_for(
            "htap0 gone from namespace",
            lambda: interface_exists(self.ns_name, "htap0"),
            False,
        )

    def test_host_tap_delete_removes_pair(self):
        """Deleting a pair's host tap removes the pair"""
        self.create_pg_interfaces(range(1))
        pg = self.pg_interfaces[0]

        self.vapi.cli(f"lcp create {pg.name} host-if hdel0 netns {self.ns_name}")
        pair = self._find_lcp_pair(pg.sw_if_index)
        self.assertIsNotNone(pair, "LCP pair should exist")
        self.assertTrue(
            interface_exists(self.ns_name, "hdel0"),
            "hdel0 should exist in namespace",
        )

        # Delete the host tap on its own, without going through the pair
        self.vapi.tap_delete_v2(sw_if_index=pair.host_sw_if_index)

        self.assertIsNone(
            self._find_lcp_pair(pg.sw_if_index),
            "LCP pair must be gone with its host tap",
        )

        # The pair record went away with its host tap, so this delete has
        # nothing to act on: it must report the missing pair and leave the
        # freed host index alone, not crash vpp like the unchecked path did.
        # lcp_itf_pair_delete returns VNET_API_ERROR_INVALID_SW_IF_INDEX (-2)
        # when lcp_itf_pair_find_by_phy finds no pair.
        with self.assertRaises(CliFailedCommandError) as cm:
            self.vapi.cli(f"lcp delete {pg.name}")
        self.assertIn("deletion failed (-2)", str(cm.exception))
        self.assertIsNone(
            self._find_lcp_pair(pg.sw_if_index),
            "LCP pair must stay gone after the failed delete",
        )

    def test_tap_phy_and_host_delete_removes_both_pairs(self):
        """Deleting a tap that is both a host and a phy removes both pairs"""
        self.create_pg_interfaces(range(1))
        pg = self.pg_interfaces[0]

        self.vapi.cli(f"lcp create {pg.name} host-if hdual0 netns {self.ns_name}")
        first = self._find_lcp_pair(pg.sw_if_index)
        self.assertIsNotNone(first, "first pair should exist")
        self.assertTrue(interface_exists(self.ns_name, "hdual0"))

        # The host tap of the first pair becomes the phy of a second one
        shared = first.host_sw_if_index
        self.vapi.cli(f"lcp create {shared} host-if hdual1 netns {self.ns_name}")
        second = self._find_lcp_pair(shared)
        self.assertIsNotNone(second, "second pair should exist")
        self.assertEqual(second.phy_sw_if_index, shared)

        self.vapi.tap_delete_v2(sw_if_index=shared)

        self.assertIsNone(
            self._find_lcp_pair(pg.sw_if_index),
            "pair hosted on the deleted tap must be gone",
        )
        self.assertIsNone(
            self._find_lcp_pair(shared),
            "pair using the deleted tap as phy must be gone",
        )

    def test_pair_vlan_subinterface(self):
        """Create LCP pairs for VLAN sub-interfaces"""
        self.create_pg_interfaces(range(1))
        pg = self.pg_interfaces[0]

        # Create parent LCP pair
        self.vapi.cli(f"lcp create {pg.name} host-if hpg0 netns {self.ns_name}")
        self.assertTrue(interface_exists(self.ns_name, "hpg0"))

        # Create VLAN sub-interface via API (sets exact-match)
        r = self.vapi.create_vlan_subif(pg.sw_if_index, 100)
        sub_sw_if_index = r.sw_if_index

        # Create LCP pair for the sub-interface
        self.vapi.cli(f"lcp create pg0.100 host-if hpg0.100 netns {self.ns_name}")

        # Verify sub-interface pair exists
        pair = self._find_lcp_pair(sub_sw_if_index)
        self.assertIsNotNone(pair, "sub-interface LCP pair should exist")

        # Verify VLAN host interface exists in namespace
        self.poll_for(
            "hpg0.100 exists in namespace",
            lambda: interface_exists(self.ns_name, "hpg0.100"),
            True,
        )

        # Delete sub-interface pair
        self.vapi.cli("lcp delete pg0.100")
        self.assertIsNone(self._find_lcp_pair(sub_sw_if_index))
        self.poll_for(
            "hpg0.100 gone from namespace",
            lambda: interface_exists(self.ns_name, "hpg0.100"),
            False,
        )

        # Clean up
        self.vapi.delete_subif(sub_sw_if_index)
        self.vapi.cli(f"lcp delete {pg.name}")

    def test_parent_pair_delete_removes_subinterface_pair(self):
        """Deleting a parent pair removes the pair of its VLAN sub-interface"""
        self.create_pg_interfaces(range(1))
        pg = self.pg_interfaces[0]

        self.vapi.cli(f"lcp create {pg.name} host-if hpar0 netns {self.ns_name}")
        self.assertTrue(interface_exists(self.ns_name, "hpar0"))

        r = self.vapi.create_vlan_subif(pg.sw_if_index, 100)
        sub_sw_if_index = r.sw_if_index

        self.vapi.cli(f"lcp create pg0.100 host-if hpar0.100 netns {self.ns_name}")
        self.assertIsNotNone(
            self._find_lcp_pair(sub_sw_if_index), "sub-interface pair should exist"
        )

        # Deleting the parent pair deletes its tap, and with it the host
        # sub-interface of the VLAN pair
        self.vapi.cli(f"lcp delete {pg.name}")

        self.assertIsNone(
            self._find_lcp_pair(pg.sw_if_index), "parent pair should be gone"
        )
        self.assertIsNone(
            self._find_lcp_pair(sub_sw_if_index),
            "sub-interface pair must be gone with its host sub-interface",
        )

        self.vapi.delete_subif(sub_sw_if_index)

    def test_pair_auto_subinterface(self):
        """lcp-auto-subint creates pairs automatically for new sub-interfaces"""
        self.create_pg_interfaces(range(1))
        pg = self.pg_interfaces[0]

        # Enable auto sub-interface creation
        self.vapi.cli("lcp lcp-auto-subint on")
        try:
            # Create parent LCP pair
            self.vapi.cli(f"lcp create {pg.name} host-if hauto0 netns {self.ns_name}")
            self.assertTrue(interface_exists(self.ns_name, "hauto0"))

            # Create VLAN sub-interface — LCP pair should be auto-created
            r = self.vapi.create_vlan_subif(pg.sw_if_index, 200)
            sub_sw_if_index = r.sw_if_index

            # Poll for the auto-created LCP pair
            self.poll_for(
                "auto sub-interface LCP pair exists",
                lambda: self._find_lcp_pair(sub_sw_if_index) is not None,
                True,
            )

            # Verify the auto-created host interface name is hauto0.200
            pair = self._find_lcp_pair(sub_sw_if_index)
            self.assertIsNotNone(pair)
            self.assertEqual(
                pair.host_if_name,
                "hauto0.200",
                "auto-created host interface should be named hauto0.200",
            )

            # Verify the VLAN interface exists in namespace
            self.poll_for(
                "hauto0.200 exists in namespace",
                lambda: interface_exists(self.ns_name, "hauto0.200"),
                True,
            )

            # Delete the VPP sub-interface — auto pair should be cleaned up
            self.vapi.delete_subif(sub_sw_if_index)

            self.poll_for(
                "auto sub-interface LCP pair removed",
                lambda: self._find_lcp_pair(sub_sw_if_index) is not None,
                False,
            )

            # Verify the Linux VLAN interface is also removed
            self.poll_for(
                "hauto0.200 gone from namespace",
                lambda: interface_exists(self.ns_name, "hauto0.200"),
                False,
            )

            self.vapi.cli(f"lcp delete {pg.name}")
        finally:
            self.vapi.cli("lcp lcp-auto-subint off")


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
@unittest.skipIf("linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests")
class TestLinuxCPOSPFMcast(TestLinuxCPNetNSBase):
    """Linux CP OSPF multicast bi-directional traffic"""

    ospf_ip_proto = IP_PROTOS.ospf
    ospf_mcast_ip4 = "224.0.0.5"
    ospf_mcast_mac = "01:00:5e:00:00:05"
    ospf_host_ip4 = "172.16.1.10"
    ospf_router_ip4 = "172.16.1.1"

    extra_vpp_plugin_config = [
        "plugin linux_cp_plugin.so { enable }",
        "plugin linux_nl_plugin.so { enable }",
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(1))
        cls.phy = cls.pg_interfaces[0]
        cls.phy.admin_up()
        cls.vapi.lcp_itf_pair_add_del_v3(
            is_add=True,
            sw_if_index=cls.phy.sw_if_index,
            host_if_name="hospf",
            host_if_type=0,
            netns=cls.ns_name,
        )
        cls.logger.info("lcp:\n%s", cls.vapi.cli("show lcp"))
        cls.hospf_mac = get_interface_info(cls.ns_name, "hospf")["address"]
        add_namespace_address(cls.ns_name, "hospf", cls.ospf_host_ip4 + "/24")
        set_interface_up(cls.ns_name, "hospf")
        for _ in range(20):
            if any(
                str(a.prefix) == cls.ospf_host_ip4 + "/24"
                for a in cls.vapi.ip_address_dump(cls.phy.sw_if_index, is_ipv6=False)
            ):
                break
            cls.sleep(0.1)
        cls.host_if = HostInterface(cls, cls.ns_name, "hospf")

    def tearDown(self):
        self.host_if.disable_capture()
        super().tearDown()

    def _is_non_ospf_pkt(self, p):
        return not (p.haslayer(IP) and p[IP].proto == self.ospf_ip_proto)

    def _mcast_ospf_pkt(self, src_mac, src_ip):
        return (
            Ether(src=src_mac, dst=self.ospf_mcast_mac)
            / IP(src=src_ip, dst=self.ospf_mcast_ip4, proto=self.ospf_ip_proto, ttl=64)
            / Raw(b"\x02" + b"\x00" * 23)
        )

    def test_ospf_mcast_host_to_phy(self):
        """OSPF multicast host-to-phy"""
        self.logger.info("MFIB:\n%s", self.vapi.cli("show ip mfib"))

        pkt = self._mcast_ospf_pkt(self.hospf_mac, self.ospf_host_ip4)

        self.host_if.add_stream([pkt])
        self.phy.enable_capture()
        self.host_if.start()

        captured = self.phy.get_capture(
            expected_count=1,
            timeout=2,
            filter_out_fn=self._is_non_ospf_pkt,
        )
        rx = captured[0]
        self.assertEqual(rx[Ether].dst, self.ospf_mcast_mac)
        self.assertEqual(rx[IP].dst, self.ospf_mcast_ip4)
        self.assertEqual(rx[IP].proto, self.ospf_ip_proto)

    def test_ospf_mcast_phy_to_host(self):
        """OSPF multicast phy-to-host"""
        self.logger.info("MFIB:\n%s", self.vapi.cli("show ip mfib"))

        pkt = self._mcast_ospf_pkt(self.phy.remote_mac, self.ospf_router_ip4)

        self.host_if.enable_capture()
        self.phy.add_stream([pkt])
        self.pg_start(trace=False)

        captured = self.host_if.get_capture(
            expected_count=1,
            timeout=5,
            filter_out_fn=self._is_non_ospf_pkt,
        )
        rx = captured[0]
        self.assertEqual(rx[Ether].dst, self.ospf_mcast_mac)
        self.assertEqual(rx[IP].dst, self.ospf_mcast_ip4)
        self.assertEqual(rx[IP].proto, self.ospf_ip_proto)


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
@unittest.skipIf("linux-cp" in config.excluded_plugins, "Exclude linux-cp plugin tests")
class TestLinuxCPNetlinkRecovery(TestLinuxCPNetNSBase):
    """Linux CP netlink polling error recovery.

    The polling error callback registered by the linux_nl plugin for the
    netlink route socket is invoked directly by the test plugin CLI. That
    simulates the EPOLLERR event the file poller reports, it does not create a
    real socket error. Recovery, the counters reported by `show lcp netlink`
    and a subsequent real Linux update are then checked.
    """

    extra_vpp_plugin_config = TestLinuxCPNetNSBase.extra_vpp_plugin_config + [
        "plugin",
        "linux_cp_unittest_plugin.so",
        "{",
        "enable",
        "}",
    ]

    # State reported by `show lcp netlink` while notifications are processed.
    NETLINK_STATE_NORMAL = "notification"
    # Bounds the wait for a recovery cycle, which is delayed by the 2s retry
    # delay of the netlink process node.
    NETLINK_RECOVERY_TIMEOUT = 20.0
    # Route added on the Linux side to check that an update still reaches VPP
    # through the reopened notification socket.
    route_blackhole = "192.168.60.0/24"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_loopback_interfaces(1)
        cls.vapi.cli(f"lcp create loop0 host-if hloop0 netns {cls.ns_name}")
        cls.lo_interfaces[0].admin_up()

    def _netlink_stats(self):
        """Return `show lcp netlink` as a dict of normalized field to value."""
        stats = {}
        for line in self.vapi.cli("show lcp netlink").splitlines():
            key, separator, value = line.partition(":")
            if not separator:
                continue
            key = key.strip().lower().replace("-", " ").replace("_", " ")
            stats[key] = value.strip()
        return stats

    def _netlink_count(self, stats, name):
        value = stats.get(name)
        self.assertIsNotNone(
            value, f"'{name}' missing from 'show lcp netlink': {stats}"
        )
        self.assertRegex(value, r"^\d+$", f"'{name}' is not a count: {value!r}")
        return int(value)

    def _netlink_completed(self):
        return self._netlink_count(self._netlink_stats(), "synchronization completed")

    def _invoke_netlink_error_callback(self, *args):
        """Invoke the polling error callback registered for the route socket."""
        return self.vapi.cli(" ".join(["test lcp netlink-error", *args]))

    def _check_recovery(self, attempts_before, completed_before, description):
        """Wait for a recovery cycle and check the state it reports afterwards."""
        self.poll_for(
            f"{description}: synchronization did not complete",
            lambda: self._netlink_completed() > completed_before,
            True,
            timeout=self.NETLINK_RECOVERY_TIMEOUT,
            interval=0.25,
        )
        self.poll_for(
            f"{description}: state not back to notification processing",
            lambda: self._netlink_stats().get("state"),
            self.NETLINK_STATE_NORMAL,
            timeout=self.NETLINK_RECOVERY_TIMEOUT,
            interval=0.25,
        )
        stats = self._netlink_stats()
        self.assertGreater(
            self._netlink_count(stats, "synchronization attempts"),
            attempts_before,
            f"{description}: no synchronization attempt recorded: {stats}",
        )

    def _check_linux_update_reaches_vpp(self):
        """Add a blackhole route on the Linux side and look it up in the VPP FIB."""
        route = self.route_blackhole
        network = ip_interface(route).network
        lookup = str(network[1]) + "/32"

        def route_present():
            return find_route(self, str(network.network_address), network.prefixlen)

        self.assertFalse(
            route_present(), f"{route} already present before Linux update"
        )
        try:
            add_namespace_route(self.ns_name, route, route_type="blackhole")
            self.poll_for(f"{route} present in VPP FIB", route_present, True)
            self.verify_paths(lookup, dict(type=FibPathType.FIB_PATH_TYPE_DROP))
        finally:
            del_namespace_route(self.ns_name, route, check=False)
            self.poll_for(f"{route} removed from VPP FIB", route_present, False)

    def test_netlink_poll_error_recovery(self):
        """Netlink polling error callback triggers a recovery cycle"""
        stats = self._netlink_stats()
        attempts_before = self._netlink_count(stats, "synchronization attempts")
        completed_before = self._netlink_count(stats, "synchronization completed")
        self.assertEqual(stats.get("state"), self.NETLINK_STATE_NORMAL, stats)

        output = self._invoke_netlink_error_callback()
        self.assertIn("netlink-error: target fd", output)
        self.assertNotIn("(copy with invalid-fd)", output)
        self.assertIn("netlink-error: callback", output)

        self._check_recovery(attempts_before, completed_before, "polling error")
        self._check_linux_update_reaches_vpp()

    def test_netlink_poll_error_invalid_fd(self):
        """Netlink polling error callback handles a failed socket error query"""
        stats = self._netlink_stats()
        attempts_before = self._netlink_count(stats, "synchronization attempts")
        completed_before = self._netlink_count(stats, "synchronization completed")

        output = self._invoke_netlink_error_callback("invalid-fd")
        self.assertIn("netlink-error: target fd -1 (copy with invalid-fd)", output)
        self.assertIn("netlink-error: callback", output)

        self._check_recovery(attempts_before, completed_before, "invalid-fd")
        self._check_linux_update_reaches_vpp()

    def _netlink_attempts(self):
        return self._netlink_count(self._netlink_stats(), "synchronization attempts")

    def _set_link_down_flag(self, name, enable):
        self.vapi.cli(f"lcp param {name} {'on' if enable else 'off'}")
        self.addCleanup(self.vapi.cli, f"lcp param {name} off")

    def _kernel_neighbor_present(self, address):
        command = ["ip", "netns", "exec", self.ns_name, "ip", "neigh", "show", address]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return address in result.stdout

    def _add_unsynced_neighbor(self, address, mac, is_static=False):
        """Add a neighbour to VPP that the kernel never learns.

        The registry removes it at teardown after checking it is still there,
        so a test may let the sweep delete it without failing the cleanup.
        """
        sw_if_index = self.lo_interfaces[0].sw_if_index
        neighbor = VppNeighbor(self, sw_if_index, mac, address, is_static=is_static)
        neighbor.add_vpp_config()
        self.assertFalse(
            self._kernel_neighbor_present(address),
            f"{address} is already known to the kernel",
        )
        self.assertTrue(find_nbr(self, sw_if_index, address, is_static=is_static))
        return sw_if_index

    def _force_resync(self):
        """Run a synchronization cycle by reporting a netlink polling error."""
        attempts_before = self._netlink_attempts()
        self._invoke_netlink_error_callback()
        self.poll_for(
            "synchronization did not complete",
            lambda: self._netlink_attempts() > attempts_before,
            True,
            timeout=self.NETLINK_RECOVERY_TIMEOUT,
            interval=0.25,
        )

    def _run_neigh_steps(self, *steps):
        """Drive the neighbour synchronization steps of the plugin directly."""
        for step in steps:
            self.vapi.cli(f"test lcp router neigh {step}")

    def test_neigh_resync_keeps_unsynced_dynamic_neighbor(self):
        """A dynamic neighbour the kernel never dumped survives with the flag off"""
        sw_if_index = self._add_unsynced_neighbor("10.10.1.101", "02:01:02:03:04:07")
        self._set_link_down_flag("del-dynamic-on-link-down", False)

        # A real synchronization cycle, then the steps it runs driven
        # directly, because the dump and the mark race inside the netlink
        # process node. Marking every neighbour is what the begin step did
        # before the fix; the end step is the production sweep.
        self._force_resync()
        self._run_neigh_steps("mark", "end")

        self.assertTrue(
            find_nbr(self, sw_if_index, "10.10.1.101"),
            "dynamic neighbour absent from the dump was removed by the sweep",
        )

    def test_neigh_resync_sweeps_unsynced_neighbor_with_flag_on(self):
        """A dynamic neighbour the kernel never dumped is removed with the flag on"""
        sw_if_index = self._add_unsynced_neighbor("10.10.1.103", "02:01:02:03:04:09")
        self._set_link_down_flag("del-dynamic-on-link-down", True)

        self._run_neigh_steps("mark", "end")

        self.assertFalse(
            find_nbr(self, sw_if_index, "10.10.1.103"),
            "dynamic neighbour absent from the dump survived the sweep",
        )

    def _router(self, arguments):
        return self.vapi.cli(f"test lcp router {arguments}")

    def _router_refs(self, proto, table, expected):
        output = self._router(f"{proto} table {table} state")
        self.assertIn(f"refs:{expected} ", output)
        self.assertIn("invalid-source-refs:0", output)
        if proto == "ip4":
            self.assertIn("broadcast refs:1 local:1", output)

    def _router_absent(self, proto, table):
        self.assertEqual(
            self._router(f"{proto} table {table} state").strip(),
            f"absent fib:{CLIB_U32_MAX} mfib:{CLIB_U32_MAX}",
        )

    def _router_sources(self, proto, table, prefix, expected, forwarding=None):
        output = self._router(f"{proto} table {table} entry {prefix}")
        lines = output.splitlines()
        for source, refs in zip(("static", "dynamic", "permanent"), expected):
            self.assertIn(f"{source}:{int(refs != 0)} refs:{refs}", lines, output)
        if forwarding is not None:
            self.assertIn(f"forwarding:{forwarding}", lines, output)

    def _router_broadcast_priority(self, table, dynamic):
        base = f"ip4 table {table}"
        prefix = "255.255.255.255/32"
        self._router_sources("ip4", table, prefix, (0, 0, 1), "receive")
        self._router(f"{base} add {prefix} proto 186 drop")
        self._router_refs("ip4", table, 2)
        self._router_sources("ip4", table, prefix, (0, 1, 1), "receive")
        self._router(f"{base} add {prefix} proto 4 drop")
        self._router_refs("ip4", table, 3)
        self._router_sources("ip4", table, prefix, (1, 1, 1), "drop")
        self._router(f"{base} del {prefix} proto 4 drop")
        self._router_refs("ip4", table, 2)
        self._router_sources("ip4", table, prefix, (0, 1, 1), "receive")
        self._router(f"{base} del {prefix} proto 186 drop")
        self._router_refs("ip4", table, 1)
        self._router_sources("ip4", table, prefix, (0, 0, 1), "receive")
        for protocol in (4, 186):
            self._router(f"{base} add {prefix} proto {protocol} drop")
            self._router("begin")
            self._router(f"{base} add {dynamic}")
            self._router("end")
            self._router_refs("ip4", table, 1)
            self._router_sources("ip4", table, prefix, (0, 0, 1), "receive")

    def test_router_source_ownership(self):
        """Repeated updates and stale sweeps release each IP source owner"""
        for proto, prefix, table in (
            ("ip4", "198.18.88.0/24", 1088),
            ("ip6", "2001:db8:88::/64", 1089),
        ):
            base = f"{proto} table {table}"
            route = f"{prefix} proto 4 drop"
            dynamic = f"{prefix} proto 186 drop"
            self._router_absent(proto, table)
            try:
                self._router(f"{base} add {route}")
                self._router_refs(proto, table, 1)
                self._router_sources(proto, table, prefix, (1, 0, 0))
                self._router(f"{base} del {prefix} proto 186 drop")
                self._router_refs(proto, table, 1)
                self._router_sources(proto, table, prefix, (1, 0, 0))
                for _ in range(3):
                    self._router(f"{base} replace {route}")
                    self._router(f"{base} add {route}")
                    self._router_refs(proto, table, 1)
                    self._router_sources(proto, table, prefix, (1, 0, 0))
                self._router(f"{base} add {dynamic}")
                self._router_refs(proto, table, 2)
                self._router_sources(proto, table, prefix, (1, 1, 0))
                for _ in range(2):
                    self._router("begin")
                    self._router(f"{base} add {route}")
                    self._router(f"{base} add {dynamic}")
                    self._router("end")
                    self._router_refs(proto, table, 2)
                    self._router_sources(proto, table, prefix, (1, 1, 0))
                self._router("begin")
                self._router(f"{base} add {dynamic}")
                self._router("end")
                self._router_refs(proto, table, 1)
                self._router_sources(proto, table, prefix, (0, 1, 0))
                if proto == "ip4":
                    self._router_broadcast_priority(table, dynamic)
                self._router("begin")
                self._router("end")
                self._router_absent(proto, table)
                self._router(f"{base} add {route}")
                self._router_refs(proto, table, 1)
                self._router_sources(proto, table, prefix, (1, 0, 0))
                self._router(f"{base} del {route}")
                self._router_absent(proto, table)
            finally:
                if proto == "ip4":
                    for protocol in (4, 186):
                        self._router(
                            f"{base} del 255.255.255.255/32 proto {protocol} drop"
                        )
                self._router(f"{base} del {route}")
                self._router(f"{base} del {dynamic}")

    def test_router_partial_delete_ownership(self):
        """Partial IPv4 deletes preserve source and independent API ownership"""
        pair = next(
            entry
            for entry in self.vapi.vpp.details_iter(self.vapi.lcp_itf_pair_get)
            if entry.phy_sw_if_index == self.lo_interfaces[0].sw_if_index
        )
        table = 1090
        prefix = "198.18.90.0/24"
        base = f"ip4 table {table}"
        route = f"{prefix} proto 4 vif {pair.vif_index} via 192.0.2.1"
        other = f"{prefix} proto 4 vif {pair.vif_index} via 192.0.2.2"
        multipath = f"{route} vif {pair.vif_index} via 192.0.2.2"
        api_route = VppIpRoute(
            self,
            "198.18.90.0",
            24,
            [
                VppRoutePath(
                    "0.0.0.0", CLIB_U32_MAX, type=FibPathType.FIB_PATH_TYPE_DROP
                )
            ],
            table_id=table,
        )
        self.vapi.ip_table_add_del(is_add=True, table={"table_id": table})
        api_route.add_vpp_config()
        try:
            self._router(f"{base} add {multipath}")
            self._router_refs("ip4", table, 1)
            self._router(f"{base} del {route}")
            self._router_refs("ip4", table, 1)
            paths = next(
                entry.route.paths
                for entry in self.vapi.ip_route_dump(table, False)
                if str(entry.route.prefix) == prefix
            )
            self.assertEqual(len(paths), 1)
            self.assertEqual(str(paths[0].nh.address.ip4), "192.0.2.2")
            self._router(f"{base} del {route}")
            self._router_refs("ip4", table, 1)
            self._router(f"{base} del {other}")
            self.assertTrue(find_route(self, "198.18.90.0", 24, table_id=table))
            self.assertIn("absent", self._router(f"{base} state"))
            self._router(f"{base} add {route}")
            self._router(f"{base} del {prefix} proto 186 vif {pair.vif_index}")
            self._router_refs("ip4", table, 1)
            self._router(f"{base} del {route}")
            self.assertIn("absent", self._router(f"{base} state"))
            self.assertTrue(find_route(self, "198.18.90.0", 24, table_id=table))
        finally:
            self._router(f"{base} del {route}")
            api_route.remove_vpp_config()
            self.vapi.ip_table_add_del(is_add=False, table={"table_id": table})
        self._router_absent("ip4", table)

    def test_router_mpls_ownership(self):
        """MPLS EOS and non-EOS retain and release separate source owners"""
        pair = next(iter(self.vapi.vpp.details_iter(self.vapi.lcp_itf_pair_get)))
        base = "mpls table 1091"
        route = f"18801 proto 4 vif {pair.vif_index} via 192.0.2.1"
        dynamic = f"18801 proto 186 vif {pair.vif_index} via 192.0.2.1"
        self._router_absent("mpls", 1091)
        try:
            self._router(f"{base} add {route}")
            self._router_refs("mpls", 1091, 2)
            for eos in (0, 1):
                self._router_sources("mpls", 1091, f"18801 eos {eos}", (1, 0, 0))
            entries = [
                entry.mr_route
                for entry in self.vapi.mpls_route_dump(1091)
                if entry.mr_route.mr_label == 18801
            ]
            self.assertEqual(sorted(entry.mr_eos for entry in entries), [0, 1])
            for entry in entries:
                self.assertEqual(entry.mr_n_paths, 1)
                self.assertEqual(str(entry.mr_paths[0].nh.address.ip4), "192.0.2.1")
                if entry.mr_eos:
                    self.assertEqual(entry.mr_eos_proto, 0)
            for _ in range(3):
                self._router(f"{base} replace {route}")
                self._router(f"{base} add {route}")
                self._router_refs("mpls", 1091, 2)
                for eos in (0, 1):
                    self._router_sources("mpls", 1091, f"18801 eos {eos}", (1, 0, 0))
            self._router(f"{base} add {dynamic}")
            self._router_refs("mpls", 1091, 4)
            for eos in (0, 1):
                self._router_sources("mpls", 1091, f"18801 eos {eos}", (1, 1, 0))
            self._router("begin")
            self._router(f"{base} add {dynamic}")
            self._router("end")
            self._router_refs("mpls", 1091, 2)
            for eos in (0, 1):
                self._router_sources("mpls", 1091, f"18801 eos {eos}", (0, 1, 0))
            self._router(f"{base} del {dynamic}")
            self._router_absent("mpls", 1091)
            self._router(f"{base} add {route}")
            self._router("begin")
            self._router("end")
            self._router_absent("mpls", 1091)
        finally:
            self._router(f"{base} del {route}")
            self._router(f"{base} del {dynamic}")

    def _router_linux_path(self, proto, table, prefix, gateway, protocol):
        def paths():
            return [
                (
                    path.sw_if_index,
                    path.type,
                    path.preference,
                    str(path.nh.address.ip6 if proto == "ip6" else path.nh.address.ip4),
                )
                for entry in self.vapi.ip_route_dump(table, proto == "ip6")
                if str(entry.route.prefix) == prefix
                for path in entry.route.paths
            ]

        self.poll_for(
            f"{prefix} via {gateway} preference 100 in VPP",
            paths,
            [
                (
                    self.lo_interfaces[0].sw_if_index,
                    FibPathType.FIB_PATH_TYPE_NORMAL,
                    100,
                    gateway,
                )
            ],
        )
        self._router_refs(proto, table, 1)
        self._router_sources(
            proto, table, prefix, (1, 0, 0) if protocol == 4 else (0, 1, 0)
        )

    def test_router_linux_replace_replay(self):
        """Changing Linux gateways and recovery replay retain one source owner"""
        set_interface_up(self.ns_name, "hloop0")
        for family, proto, prefix, table, address, gateways in (
            (
                "-4",
                "ip4",
                "198.18.92.0/24",
                1092,
                "192.0.2.254/24",
                ("192.0.2.1", "192.0.2.2", "192.0.2.3"),
            ),
            (
                "-6",
                "ip6",
                "2001:db8:93::/64",
                1093,
                "2001:db8:ffff::fe/64",
                ("2001:db8:ffff::1", "2001:db8:ffff::2", "2001:db8:ffff::3"),
            ),
        ):
            add_namespace_address(self.ns_name, "hloop0", address)
            try:
                for protocol in (4, 186):
                    command = ["ip", "-n", self.ns_name, family, "route"]
                    try:
                        for gateway in gateways:
                            subprocess.run(
                                command
                                + [
                                    "replace",
                                    prefix,
                                    "via",
                                    gateway,
                                    "dev",
                                    "hloop0",
                                    "onlink",
                                    "table",
                                    str(table),
                                    "proto",
                                    str(protocol),
                                    "metric",
                                    "100",
                                ],
                                check=True,
                                capture_output=True,
                            )
                            self._router_linux_path(
                                proto, table, prefix, gateway, protocol
                            )
                        for _ in range(2):
                            stats = self._netlink_stats()
                            self._invoke_netlink_error_callback()
                            self._check_recovery(
                                self._netlink_count(stats, "synchronization attempts"),
                                self._netlink_count(stats, "synchronization completed"),
                                "route replay ownership",
                            )
                            self._router_linux_path(
                                proto, table, prefix, gateways[-1], protocol
                            )
                    finally:
                        subprocess.run(
                            command + ["flush", "table", str(table)],
                            check=True,
                            capture_output=True,
                        )
                        self.poll_for(
                            "Linux route table released",
                            lambda: self._router(
                                f"{proto} table {table} state"
                            ).split()[0],
                            "absent",
                        )
                    self._router_absent(proto, table)
            finally:
                del_namespace_address(self.ns_name, "hloop0", address)

    def test_router_bound_table_sweep(self):
        """Sweep releases routes while pair binding preserves table lifetime"""
        interface = self.lo_interfaces[0]
        for is_ipv6, proto, prefix, table in (
            (False, "ip4", "198.18.94.0/24", 1094),
            (True, "ip6", "2001:db8:95::/64", 1095),
        ):
            self.vapi.ip_table_add_del(
                is_add=True, table={"table_id": table, "is_ip6": is_ipv6}
            )
            try:
                self.vapi.sw_interface_set_table(
                    sw_if_index=interface.sw_if_index, is_ipv6=is_ipv6, vrf_id=table
                )
                self._router_refs(proto, table, 1)
                base = f"{proto} table {table}"
                self._router(f"{base} add {prefix} proto 4 drop")
                self._router_refs(proto, table, 2)
                self._router("begin")
                self._router("end")
                self._router_refs(proto, table, 1)
                self._router(f"{base} del {prefix} proto 4 drop")
                self._router_refs(proto, table, 1)
            finally:
                self.vapi.sw_interface_set_table(
                    sw_if_index=interface.sw_if_index, is_ipv6=is_ipv6, vrf_id=0
                )
                self.vapi.ip_table_add_del(
                    is_add=False, table={"table_id": table, "is_ip6": is_ipv6}
                )
            self._router_absent(proto, table)

    def test_router_broadcast_recovery(self):
        """Permanent limited broadcast receive survives repeated real recovery"""
        self.create_pg_interfaces(range(1))
        phy = self.pg0
        prefix = phy.local_ip4_prefix
        phy.admin_up()

        def pair_address():
            vpp = any(
                str(address.prefix) == prefix
                for address in self.vapi.ip_address_dump(phy.sw_if_index, is_ipv6=False)
            )
            linux = _prefix_tuple(prefix) in get_interface_addresses(
                self.ns_name, "hbcast", "inet"
            )
            return vpp, linux

        host = None
        address_added = False
        failure = None
        try:
            self.vapi.cli(f"lcp create {phy.name} host-if hbcast netns {self.ns_name}")
            host = HostInterface(self, self.ns_name, "hbcast")
            # Linux owns the pair address, LCP mirrors it into VPP, and the
            # resync address sweep withdraws addresses Linux does not hold.
            add_namespace_address(self.ns_name, "hbcast", prefix)
            address_added = True
            set_interface_up(self.ns_name, "hbcast")
            self.poll_for(
                f"{prefix} on phy and hbcast",
                pair_address,
                (True, True),
                timeout=5,
            )
            packet = (
                Ether(src=phy.remote_mac, dst="ff:ff:ff:ff:ff:ff")
                / IP(src=phy.remote_ip4, dst="255.255.255.255")
                / UDP(sport=18888, dport=18888)
                / Raw(b"lcp broadcast ownership")
            )
            for cycle in range(4):
                self.assertIn(
                    "broadcast refs:1 local:1", self._router("ip4 table 0 state")
                )
                host.enable_capture()
                phy.add_stream([packet])
                self.pg_start(trace=False)
                captured = host.get_capture(
                    expected_count=1,
                    timeout=5,
                    filter_out_fn=lambda pkt: not (
                        pkt.haslayer(UDP) and pkt[UDP].dport == 18888
                    ),
                )
                self.assertEqual(captured[0][IP].dst, "255.255.255.255")
                host.disable_capture()
                if cycle == 3:
                    break
                stats = self._netlink_stats()
                self._invoke_netlink_error_callback()
                self._check_recovery(
                    self._netlink_count(stats, "synchronization attempts"),
                    self._netlink_count(stats, "synchronization completed"),
                    "broadcast receive ownership",
                )
                self.poll_for(
                    f"{prefix} on phy and hbcast after recovery",
                    pair_address,
                    (True, True),
                    timeout=5,
                )
        except BaseException as exc:
            failure = exc
            raise
        finally:
            if host is not None:
                _cleanup_failure(failure, self.logger, "capture", host.disable_capture)
            if address_added:
                _cleanup_failure(
                    failure,
                    self.logger,
                    "namespace address",
                    lambda: del_namespace_address(self.ns_name, "hbcast", prefix),
                )
            _cleanup_failure(
                failure,
                self.logger,
                "pair",
                lambda: self.vapi.cli(f"lcp delete {phy.name}"),
            )
            _cleanup_failure(failure, self.logger, "admin state", phy.admin_down)
