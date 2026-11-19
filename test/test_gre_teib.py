#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import unittest

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, GRE
from scapy.packet import Raw

from config import config
from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_gre_interface import VppGreInterface
from vpp_ip_route import VppIpRoute, VppIpTable, VppRoutePath
from vpp_papi import VppEnum
from vpp_teib import VppTeib


@unittest.skipIf("gre" in config.excluded_plugins, "Exclude GRE plugin tests")
class TestGreTeib(VppTestCase):
    """GRE configuration identity and TEIB ingress ownership"""

    def setUp(self):
        super().setUp()
        self.create_pg_interfaces(range(2))
        for interface in self.pg_interfaces:
            interface.admin_up()
            interface.config_ip4()
            interface.resolve_arp()
            interface.config_ip6()
            interface.resolve_ndp()

    def tearDown(self):
        for interface in self.pg_interfaces:
            interface.unconfig()
            interface.admin_down()
        super().tearDown()

    def make_tunnel(self, is_ip6, key, multipoint=False, table=0):
        modes = VppEnum.vl_api_tunnel_mode_t
        source = self.pg0.local_ip6 if is_ip6 else self.pg0.local_ip4
        destination = self.pg0.remote_ip6 if is_ip6 else self.pg0.remote_ip4
        if multipoint:
            destination = "::" if is_ip6 else "0.0.0.0"
        tunnel = VppGreInterface(
            self,
            source,
            destination,
            outer_table_id=table,
            mode=modes.TUNNEL_API_MODE_MP if multipoint else modes.TUNNEL_API_MODE_P2P,
            gre_key=key,
        ).add_vpp_config()
        tunnel.admin_up()
        tunnel.config_ip4()
        self.assert_tunnels(tunnel)
        return tunnel

    def assert_tunnels(self, *tunnels):
        for tunnel in tunnels:
            details = self.vapi.gre_tunnel_v2_dump(sw_if_index=tunnel.sw_if_index)
            self.assertEqual(len(details), 1)
            actual = details[0].tunnel
            self.assertEqual(actual.sw_if_index, tunnel.sw_if_index)
            self.assertEqual(str(actual.src), tunnel.t_src)
            expected_dst = tunnel.t_dst
            if (
                tunnel.t_mode == VppEnum.vl_api_tunnel_mode_t.TUNNEL_API_MODE_MP
                and expected_dst == "::"
            ):
                expected_dst = "0.0.0.0"
            self.assertEqual(str(actual.dst), expected_dst)
            self.assertEqual(actual.mode, tunnel.t_mode)
            self.assertEqual(actual.type, tunnel.t_type)
            self.assertEqual(actual.key, tunnel.t_gre_key)
            self.assertEqual(actual.outer_table_id, tunnel.t_outer_table)
            self.assertEqual(actual.session_id, tunnel.t_session)
            interfaces = self.vapi.sw_interface_dump(sw_if_index=tunnel.sw_if_index)
            self.assertEqual([i.sw_if_index for i in interfaces], [tunnel.sw_if_index])

    def delete_tunnel(self, tunnel):
        tunnel.unconfig()
        response = self.vapi.gre_tunnel_add_del_v2(
            is_add=0,
            tunnel={
                "src": tunnel.t_src,
                "dst": tunnel.t_dst,
                "outer_table_id": tunnel.t_outer_table,
                "instance": 0xFFFFFFFF,
                "type": tunnel.t_type,
                "mode": tunnel.t_mode,
                "flags": tunnel.t_flags,
                "session_id": tunnel.t_session,
                "key": tunnel.t_gre_key,
            },
        )
        self.assertEqual(response.sw_if_index, tunnel.sw_if_index)
        self.assertEqual(
            list(self.vapi.gre_tunnel_v2_dump(sw_if_index=tunnel.sw_if_index)), []
        )
        self.assertEqual(
            list(self.vapi.sw_interface_dump(sw_if_index=tunnel.sw_if_index)), []
        )

    def make_peer(self, tunnel, is_ip6, peer):
        next_hop = self.pg0.remote_ip6 if is_ip6 else self.pg0.remote_ip4
        entry = VppTeib(self, tunnel, peer, next_hop).add_vpp_config()
        self.assertTrue(entry.query_vpp_config())
        return entry

    def bind_pg1_to_table(self, is_ip6, table_id):
        """bind pg1's family to a table, failing here if VPP declines"""
        bind = self.vapi.sw_interface_set_table(
            self.pg1.sw_if_index, 1 if is_ip6 else 0, table_id
        )
        self.assertEqual(bind.retval, 0)

    def add_peer_raw(self, tunnel, is_ip6, peer):
        """add peer the way make_peer does, without registering or checking"""
        next_hop = self.pg0.remote_ip6 if is_ip6 else self.pg0.remote_ip4
        return VppTeib(self, tunnel, peer, next_hop).add_vpp_config()

    def peer_has_adj_fib(self, is_ip6, table_id, peer):
        """whether peer has an adj fib on pg1 in the table by that table id"""
        for route in self.vapi.ip_route_dump(table_id, bool(is_ip6)):
            if (
                str(route.route.prefix) == peer
                and route.route.paths[0].sw_if_index == self.pg1.sw_if_index
            ):
                return True
        return False

    def test_gre_teib_unbound_peer(self):
        """a peer's adj fib leaves its own table once the binding is gone

        An unbind only removes the address, so the peer added before it stays,
        in table 1, while the interface is bound to table 0 again by the time
        the peer goes. Deleting the peer then has to take its adj fib out of
        table 1, and release what it holds there, rather than out of table 0,
        which is where the interface is bound by then.

        Before the fix the delete looked the adj fib up in table 0, where there
        was nothing to remove, so the path stayed in table 1 and the
        FIB_SOURCE_ADJ lock table 1 was given on the way in was kept for good.
        The double add is exercised too: the second add is refused with the
        existing entry and leaves the adj fib as it was.

        Every subTest stands on its own: table 1 is created empty for it, and
        the family under test is bound back to table 0 before it is bound to
        table 1, because VPP refuses to move an interface that still has a
        global address, and setUp leaves pg1 holding one of each family. The
        bind to table 1 is asserted, so a refusal fails here instead of
        leaving the peer in table 0.
        """
        for is_ip6 in (False, True):
            with self.subTest(is_ip6=is_ip6):
                table = VppIpTable(self, 1, is_ip6=is_ip6).add_vpp_config()
                try:
                    self.bind_pg1_to_table(is_ip6, 0)
                    self.bind_pg1_to_table(is_ip6, 1)
                    tunnel = self.make_tunnel(is_ip6, 0x12345678, multipoint=True)
                    peer = "198.19.0.4" if not is_ip6 else "2001:db8::4"
                    entry = self.make_peer(tunnel, is_ip6, peer)
                    self.assertTrue(self.peer_has_adj_fib(is_ip6, 1, peer))
                    with self.assertRaisesRegex(Exception, "ALREADY_EXISTS"):
                        self.add_peer_raw(tunnel, is_ip6, peer)
                    self.bind_pg1_to_table(is_ip6, 0)
                    entry.remove_vpp_config()
                    self.assertFalse(entry.query_vpp_config())
                    self.assertFalse(self.peer_has_adj_fib(is_ip6, 1, peer))
                    self.bind_pg1_to_table(is_ip6, 1)
                    self.assertTrue(
                        self.add_peer_raw(tunnel, is_ip6, peer).query_vpp_config()
                    )
                    self.bind_pg1_to_table(is_ip6, 0)
                    self.delete_tunnel(tunnel)
                finally:
                    self.registry.unregister(table.object_id(), self.logger)
                    table.remove_vpp_config()

    def test_gre_teib_sourced_peer_unbound(self):
        """a peer whose prefix the route table already holds leaves no lock

        The adj fib is only ever created for a peer whose prefix the table
        does not source yet, so a static route to the peer added first makes
        that same adj fib a no-op. Deleting the peer then has to leave the
        static route alone, and release nothing, since nothing was taken.

        Before the fix the delete went at table 0, where VPP then unlocked a
        live table whose FIB_SOURCE_ADJ count was already zero; that count is
        visible to no route dump and checked only under a debug build, so what
        this test pins is the static route surviving the delete, which it does
        on the old tree too. It guards the install check against a release that
        overwrites or drops the peer's source.

        Every subTest stands on its own: table 1 is created empty for it, and
        the family under test is bound back to table 0 before it is bound to
        table 1, because VPP refuses to move an interface that still has a
        global address, and setUp leaves pg1 holding one of each family. The
        bind to table 1 is asserted.
        """
        for is_ip6 in (False, True):
            with self.subTest(is_ip6=is_ip6):
                table = VppIpTable(self, 1, is_ip6=is_ip6).add_vpp_config()
                try:
                    self.bind_pg1_to_table(is_ip6, 0)
                    self.bind_pg1_to_table(is_ip6, 1)
                    peer = "198.19.0.5" if not is_ip6 else "2001:db8::5"
                    route = VppIpRoute(
                        self,
                        peer,
                        128 if is_ip6 else 32,
                        [VppRoutePath(self.pg0.remote_ip4, self.pg0.sw_if_index)],
                        table_id=1,
                    ).add_vpp_config()
                    tunnel = self.make_tunnel(is_ip6, 0x12345678, multipoint=True)
                    entry = self.make_peer(tunnel, is_ip6, peer)
                    self.bind_pg1_to_table(is_ip6, 0)
                    entry.remove_vpp_config()
                    self.assertFalse(entry.query_vpp_config())
                    self.assertTrue(route.query_vpp_config())
                    route.remove_vpp_config()
                    self.delete_tunnel(tunnel)
                finally:
                    self.registry.unregister(table.object_id(), self.logger)
                    table.remove_vpp_config()

    def packet(self, is_ip6, key):
        outer = (
            IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6)
            if is_ip6
            else IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4)
        )
        header = GRE(key_present=1, key=key) if key else GRE()
        return (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / outer
            / header
            / IP(src="198.18.0.2", dst=self.pg1.remote_ip4)
            / UDP(sport=1234, dport=4321)
            / Raw(b"GRE TEIB ownership")
        )

    def assert_ingress(self, is_ip6, owner, *other_tunnels):
        before = owner.get_rx_stats()
        others_before = [tunnel.get_rx_stats() for tunnel in other_tunnels]
        packets = [self.packet(is_ip6, owner.t_gre_key)] * 3
        received = self.send_and_expect(self.pg0, packets, self.pg1)
        for packet in received:
            self.assertFalse(packet.haslayer(GRE))
            self.assertEqual(packet[IP].dst, self.pg1.remote_ip4)
            self.assertEqual(bytes(packet[Raw]), b"GRE TEIB ownership")
        self.assertEqual(owner.get_rx_stats() - before, len(packets))
        for tunnel, count in zip(other_tunnels, others_before):
            self.assertEqual(tunnel.get_rx_stats(), count)

    def check_p2p_precedence(self, is_ip6, key, p2p_first):
        if p2p_first:
            p2p = self.make_tunnel(is_ip6, key)
        multipoint = self.make_tunnel(is_ip6, key, multipoint=True)
        first = self.make_peer(multipoint, is_ip6, "198.19.0.2")
        if not p2p_first:
            self.assert_ingress(is_ip6, multipoint)
            p2p = self.make_tunnel(is_ip6, key)
        self.assert_tunnels(p2p, multipoint)
        self.assert_ingress(is_ip6, p2p, multipoint)

        first.remove_vpp_config()
        self.assertFalse(first.query_vpp_config())
        self.assert_tunnels(p2p, multipoint)
        self.assert_ingress(is_ip6, p2p, multipoint)
        first.add_vpp_config()
        second = self.make_peer(multipoint, is_ip6, "198.19.0.3")
        self.assert_ingress(is_ip6, p2p, multipoint)

        self.delete_tunnel(p2p)
        self.assert_tunnels(multipoint)
        self.assert_ingress(is_ip6, multipoint)
        first.remove_vpp_config()
        self.assertFalse(first.query_vpp_config())
        self.assertTrue(second.query_vpp_config())
        self.assert_ingress(is_ip6, multipoint)

        p2p = self.make_tunnel(is_ip6, key)
        self.assert_tunnels(p2p, multipoint)
        self.assert_ingress(is_ip6, p2p, multipoint)
        second.remove_vpp_config()
        self.assert_ingress(is_ip6, p2p, multipoint)
        self.delete_tunnel(multipoint)
        self.assert_tunnels(p2p)
        self.assert_ingress(is_ip6, p2p)
        self.delete_tunnel(p2p)

        multipoint = self.make_tunnel(is_ip6, key, multipoint=True)
        first = self.make_peer(multipoint, is_ip6, "198.19.0.2")
        self.assert_ingress(is_ip6, multipoint)
        first.remove_vpp_config()
        self.send_and_assert_no_replies(self.pg0, [self.packet(is_ip6, key)])
        self.delete_tunnel(multipoint)
        self.assertEqual(list(self.vapi.gre_tunnel_v2_dump(sw_if_index=0xFFFFFFFF)), [])

    def test_gre_teib_ipv4(self):
        """IPv4 keyless and keyed P2P precedence in both creation orders"""
        for key in (0, 0x12345678):
            for p2p_first in (True, False):
                with self.subTest(key=key, p2p_first=p2p_first):
                    self.check_p2p_precedence(False, key, p2p_first)

    def test_gre_teib_ipv6(self):
        """IPv6 keyless and keyed P2P precedence in both creation orders"""
        for key in (0, 0x12345678):
            for p2p_first in (True, False):
                with self.subTest(key=key, p2p_first=p2p_first):
                    self.check_p2p_precedence(True, key, p2p_first)

    def test_gre_teib_cross_mp(self):
        """Conflicting MP aliases preserve their owner and restore a survivor"""
        for is_ip6 in (False, True):
            table = VppIpTable(self, 1, is_ip6=is_ip6).add_vpp_config()
            for key in (0, 0x12345678):
                with self.subTest(is_ip6=is_ip6, key=key):
                    first = self.make_tunnel(is_ip6, key, multipoint=True)
                    second = self.make_tunnel(is_ip6, key, multipoint=True, table=1)
                    first_peer = self.make_peer(first, is_ip6, "198.19.0.2")
                    second_peer = self.make_peer(second, is_ip6, "198.19.0.2")
                    self.assert_tunnels(first, second)
                    self.assert_ingress(is_ip6, first, second)
                    second_peer.remove_vpp_config()
                    self.assert_ingress(is_ip6, first, second)
                    second_peer.add_vpp_config()
                    self.assert_ingress(is_ip6, first, second)
                    previous_index = first.sw_if_index
                    self.delete_tunnel(first)
                    self.assertTrue(first_peer.query_vpp_config())
                    self.assert_tunnels(second)
                    self.assert_ingress(is_ip6, second)
                    first = self.make_tunnel(is_ip6, key, multipoint=True)
                    self.assertEqual(first.sw_if_index, previous_index)
                    self.assertTrue(first_peer.query_vpp_config())
                    self.assert_tunnels(first, second)
                    self.assert_ingress(is_ip6, second, first)
                    second_peer.remove_vpp_config()
                    self.assert_ingress(is_ip6, first, second)
                    first_peer.remove_vpp_config()
                    self.delete_tunnel(first)
                    self.delete_tunnel(second)
            table.remove_vpp_config()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
