#!/usr/bin/env python3
import unittest
from ipaddress import IPv4Address

from scapy.layers.inet import UDP

from config import config
from framework import VppTestCase
from ipfix import IPFIX, Template
from test_flowprobe import VppCFLOW


class TestIpfixExporter(VppTestCase):
    """Ipfix Exporter Tests"""

    def setUp(self):
        super(TestIpfixExporter, self).setUp()
        self.create_pg_interfaces(range(4))
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()
            i.disable_ipv6_ra()

    def tearDown(self):
        super(TestIpfixExporter, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()

    def find_exp_by_collector_addr(self, exporters, addr):
        """Find the exporter in the list of exportes with the given  addr"""

        for exp in exporters:
            if exp.collector_address == IPv4Address(addr):
                return exp
        return None

    def verify_exporter_detail(
        self, exp, collector_addr, src_addr, collector_port=4739, mtu=1400, interval=20
    ):
        self.assertTrue(exp is not None)
        self.assert_equal(exp.collector_address, collector_addr)
        self.assert_equal(exp.src_address, src_addr)
        self.assert_equal(exp.collector_port, collector_port)
        self.assert_equal(exp.path_mtu, mtu)
        self.assert_equal(exp.template_interval, interval)

    def capture_template_stream(self, timeout=5):
        packet = self.pg0.wait_for_packet(
            timeout=timeout, filter_out_fn=lambda packet: not packet.haslayer(Template)
        )
        return packet[IPFIX].observationDomainID, packet[UDP].sport

    @unittest.skipIf(
        "flowprobe" in config.excluded_plugins, "Exclude Flowprobe plugin tests"
    )
    def test_classify_stream_update(self):
        """Changing the classify stream refreshes only its export template"""
        self.pg_enable_capture([self.pg0])
        template_interval = 15
        flowprobe = VppCFLOW(test=self, layer="l2", timeout=template_interval)
        flowprobe.add_vpp_config()
        try:
            self.assertEqual(self.capture_template_stream(), (1, 4739))
            self.vapi.set_ipfix_classify_stream(domain_id=10, src_port=4740)
            mask = b"\x00" * 26 + b"\xff" * 12 + b"\x00" * 10
            table = self.vapi.classify_add_del_table(
                is_add=True, mask=mask, mask_len=len(mask), match_n_vectors=3
            ).new_table_index
            try:
                self.vapi.cli(f"ipfix classify table add {table} ip4 udp")
                try:
                    self.vapi.cli("ipfix flush")
                    self.assertEqual(self.capture_template_stream(), (10, 4740))

                    self.vapi.set_ipfix_classify_stream(domain_id=20, src_port=4741)
                    self.vapi.cli("ipfix flush")
                    self.assertEqual(self.capture_template_stream(), (20, 4741))
                    self.assertEqual(
                        self.capture_template_stream(timeout=template_interval + 5),
                        (1, 4739),
                    )
                finally:
                    self.vapi.cli(f"ipfix classify table del {table} ip4 udp")
            finally:
                self.vapi.classify_add_del_table(is_add=False, table_index=table)
        finally:
            flowprobe.remove_vpp_config()

    def test_create_multipe_exporters(self):
        """test that we can create and dump multiple exporters"""

        mtu = 1400
        interval = 20
        port = 4739

        # Old API - always gives us pool index 0.
        self.vapi.set_ipfix_exporter(
            collector_address=self.pg1.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=4739,
            path_mtu=mtu,
            template_interval=interval,
        )

        exporters = self.vapi.ipfix_exporter_dump()
        exp = self.find_exp_by_collector_addr(exporters, self.pg1.remote_ip4)
        self.verify_exporter_detail(
            exp, IPv4Address(self.pg1.remote_ip4), IPv4Address(self.pg0.local_ip4)
        )

        exporters = list(self.vapi.vpp.details_iter(self.vapi.ipfix_all_exporter_get))
        exp = self.find_exp_by_collector_addr(exporters, self.pg1.remote_ip4)
        self.verify_exporter_detail(
            exp, IPv4Address(self.pg1.remote_ip4), IPv4Address(self.pg0.local_ip4)
        )

        # create a 2nd exporter
        self.vapi.ipfix_exporter_create_delete(
            collector_address=self.pg2.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=4739,
            path_mtu=mtu,
            template_interval=interval,
            is_create=True,
        )

        exporters = list(self.vapi.vpp.details_iter(self.vapi.ipfix_all_exporter_get))
        self.assertTrue(len(exporters) == 2)
        exp = self.find_exp_by_collector_addr(exporters, self.pg1.remote_ip4)
        self.verify_exporter_detail(
            exp, IPv4Address(self.pg1.remote_ip4), IPv4Address(self.pg0.local_ip4)
        )
        exp = self.find_exp_by_collector_addr(exporters, self.pg2.remote_ip4)
        self.verify_exporter_detail(
            exp, IPv4Address(self.pg2.remote_ip4), IPv4Address(self.pg0.local_ip4)
        )

        # Create a 3rd exporter
        self.vapi.ipfix_exporter_create_delete(
            collector_address=self.pg3.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=4739,
            path_mtu=mtu,
            template_interval=interval,
            is_create=True,
        )

        exporters = list(self.vapi.vpp.details_iter(self.vapi.ipfix_all_exporter_get))
        self.assertTrue(len(exporters) == 3)
        exp = self.find_exp_by_collector_addr(exporters, self.pg1.remote_ip4)
        self.verify_exporter_detail(
            exp, IPv4Address(self.pg1.remote_ip4), IPv4Address(self.pg0.local_ip4)
        )
        exp = self.find_exp_by_collector_addr(exporters, self.pg2.remote_ip4)
        self.verify_exporter_detail(
            exp, IPv4Address(self.pg2.remote_ip4), IPv4Address(self.pg0.local_ip4)
        )
        exp = self.find_exp_by_collector_addr(exporters, self.pg3.remote_ip4)
        self.verify_exporter_detail(
            exp, IPv4Address(self.pg3.remote_ip4), IPv4Address(self.pg0.local_ip4)
        )

        # Modify the 2nd exporter.
        self.vapi.ipfix_exporter_create_delete(
            collector_address=self.pg2.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=4739,
            path_mtu=mtu + 1,
            template_interval=interval + 1,
            is_create=True,
        )

        exporters = list(self.vapi.vpp.details_iter(self.vapi.ipfix_all_exporter_get))
        self.assertTrue(len(exporters) == 3)
        exp = self.find_exp_by_collector_addr(exporters, self.pg1.remote_ip4)
        self.verify_exporter_detail(
            exp, IPv4Address(self.pg1.remote_ip4), IPv4Address(self.pg0.local_ip4)
        )
        exp = self.find_exp_by_collector_addr(exporters, self.pg2.remote_ip4)
        self.verify_exporter_detail(
            exp,
            IPv4Address(self.pg2.remote_ip4),
            IPv4Address(self.pg0.local_ip4),
            mtu=mtu + 1,
            interval=interval + 1,
        )
        exp = self.find_exp_by_collector_addr(exporters, self.pg3.remote_ip4)
        self.verify_exporter_detail(
            exp, IPv4Address(self.pg3.remote_ip4), IPv4Address(self.pg0.local_ip4)
        )

        # Delete 2nd exporter
        self.vapi.ipfix_exporter_create_delete(
            collector_address=self.pg2.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=4739,
            path_mtu=mtu,
            template_interval=interval,
            is_create=False,
        )

        exporters = list(self.vapi.vpp.details_iter(self.vapi.ipfix_all_exporter_get))
        self.assertTrue(len(exporters) == 2)
        exp = self.find_exp_by_collector_addr(exporters, self.pg1.remote_ip4)
        self.verify_exporter_detail(
            exp, IPv4Address(self.pg1.remote_ip4), IPv4Address(self.pg0.local_ip4)
        )
        exp = self.find_exp_by_collector_addr(exporters, self.pg3.remote_ip4)
        self.verify_exporter_detail(
            exp, IPv4Address(self.pg3.remote_ip4), IPv4Address(self.pg0.local_ip4)
        )

        # Delete final exporter (exporter in slot 0 can not be deleted)
        self.vapi.ipfix_exporter_create_delete(
            collector_address=self.pg3.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=4739,
            path_mtu=mtu,
            template_interval=interval,
            is_create=False,
        )

        exporters = list(self.vapi.vpp.details_iter(self.vapi.ipfix_all_exporter_get))
        self.assertTrue(len(exporters) == 1)
        exp = self.find_exp_by_collector_addr(exporters, self.pg1.remote_ip4)
        self.verify_exporter_detail(
            exp, IPv4Address(self.pg1.remote_ip4), IPv4Address(self.pg0.local_ip4)
        )
