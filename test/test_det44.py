#!/usr/bin/env python3

import socket
import struct
import unittest
import scapy.compat
from time import sleep
from config import config
from framework import VppTestCase
from ipfix import IPFIX, Set, Template, Data, IPFIXDecoder
from scapy.data import IP_PROTOS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet import IPerror, UDPerror
from scapy.layers.l2 import Ether
from util import ppp
from vpp_pg_interface import CaptureTimeoutError
from config import config


# tearDown disables the plugin after every test, and det44_plugin_disable
# frees the maps and their sessions, so nothing survives from one test into
# the next. Each IPFIX test starts with an empty pool: it adds the map with
# add_ipfix_tcp_test_map, which puts every session on 10.0.0.3, and opens the
# session it works on.
#
# The expiry walk closes the ICMP session of test_ipfix_icmp_session_events,
# whose expire is fixed when the echo request creates it, by
# icmp_match_in2out_det (det44_in2out.c:236-241), to the clock plus the ICMP
# timeout; the test sets that timeout to 5 seconds before it opens the session
# and then sleeps 15, so the first run of the 10 second walk after the sleep
# finds it expired. The create-once assertion rests on the opposite: the
# second echo request and both echo replies find the session, so they never
# reach the code that creates one and logs its create, which is why the
# identifier has one create record.
@unittest.skipIf("nat" in config.excluded_plugins, "Exclude NAT plugin tests")
class TestDET44(VppTestCase):
    """Deterministic NAT Test Cases"""

    # natEvent values of the NAT44 session events
    NAT_EVENT_SESSION_CREATE = 4
    NAT_EVENT_SESSION_DELETE = 5

    # The NAT44 session data record: observationTimeMilliseconds, then the
    # template fields of nat_template_rewrite, 26 octets as NAT44_SESSION_CREATE_LEN
    # in src/plugins/nat/lib/ipfix_logging.c
    NAT44_SESSION_RECORD_LAYOUT = [
        (230, 1),  # natEvent
        (8, 4),  # sourceIPv4Address
        (225, 4),  # postNATSourceIPv4Address
        (4, 1),  # protocolIdentifier
        (7, 2),  # sourceTransportPort
        (227, 2),  # postNAPTSourceTransportPort
        (234, 4),  # ingressVRFID
    ]
    NAT44_SESSION_RECORD_FIELDS = (153,) + tuple(
        f for f, _ in NAT44_SESSION_RECORD_LAYOUT
    )
    NAT44_SESSION_RECORD_LEN = 8 + sum(
        length for _, length in NAT44_SESSION_RECORD_LAYOUT
    )

    # Polls of one second that a collector snapshot waits for the exporter to
    # send the flushed buffers, whose cycle waits up to 5 seconds of VPP time
    IPFIX_EXPORT_POLLS = 10

    @classmethod
    def setUpClass(cls):
        super(TestDET44, cls).setUpClass()
        cls.vapi.cli("set log class det44 level debug")

        cls.tcp_port_in = 6303
        cls.tcp_external_port = 6303
        cls.udp_port_in = 6304
        cls.udp_external_port = 6304
        cls.icmp_id_in = 6305
        cls.nat_addr = "10.0.0.3"

        cls.create_pg_interfaces(range(3))
        cls.interfaces = list(cls.pg_interfaces)

        for i in cls.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        cls.pg0.generate_remote_hosts(2)
        cls.pg0.configure_ipv4_neighbors()

    @classmethod
    def tearDownClass(cls):
        super(TestDET44, cls).tearDownClass()

    def setUp(self):
        super(TestDET44, self).setUp()
        self.vapi.det44_plugin_enable_disable(enable=1)

    def tearDown(self):
        super(TestDET44, self).tearDown()
        if not self.vpp_dead:
            self.vapi.det44_plugin_enable_disable(enable=0)

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show det44 interfaces"))
        self.logger.info(self.vapi.cli("show det44 timeouts"))
        self.logger.info(self.vapi.cli("show det44 mappings"))
        self.logger.info(self.vapi.cli("show det44 sessions"))

    def verify_capture_in(self, capture, in_if):
        """
        Verify captured packets on inside network

        :param capture: Captured packets
        :param in_if: Inside interface
        """
        fired = False
        for packet in capture:
            try:
                self.assert_packet_checksums_valid(packet)
                self.assertEqual(packet[IP].dst, in_if.remote_ip4)
                if packet.haslayer(TCP):
                    self.assertEqual(packet[TCP].dport, self.tcp_port_in)
                elif packet.haslayer(UDP):
                    self.assertEqual(packet[UDP].dport, self.udp_port_in)
                else:
                    self.assertEqual(packet[ICMP].id, self.icmp_id_in)
            except:
                fired = True
                self.logger.error(
                    ppp("Unexpected or invalid packet (inside network):", packet)
                )
        if fired:
            raise

    def verify_ipfix_max_entries_per_user(self, data, limit, src_addr):
        """
        Verify IPFIX maximum entries per user exceeded event

        :param data: Decoded IPFIX data records
        :param limit: Number of maximum entries per user
        :param src_addr: IPv4 source address
        """
        self.assertEqual(1, len(data))
        record = data[0]
        # natEvent
        self.assertEqual(scapy.compat.orb(record[230]), 13)
        # natQuotaExceededEvent
        self.assertEqual(struct.pack("!I", 3), record[466])
        # maxEntriesPerUser
        self.assertEqual(struct.pack("!I", limit), record[473])
        # sourceIPv4Address
        self.assertEqual(socket.inet_pton(socket.AF_INET, src_addr), record[8])

    def configure_ipfix_collector(self):
        """
        Export NAT sessions to the collector on pg2

        The capture of pg2 is enabled here, once per test. Enabling a capture
        deletes its pcap, so it has to be on before the exporter sends its
        first packet, and nothing else clears it afterwards. A call at the
        start of every snapshot would also delete the packets an earlier
        snapshot left unread.
        """
        if not self.pg2._pcap_reader:
            self.pg_enable_capture([self.pg2])
        self.vapi.set_ipfix_exporter(
            collector_address=self.pg2.remote_ip4,
            src_address=self.pg2.local_ip4,
            path_mtu=512,
            template_interval=10,
        )
        self.vapi.nat_ipfix_enable_disable(domain_id=1, src_port=4739, enable=1)
        # The flow reporting process sends a template while it has not sent
        # one yet, and no template leaves before it sees a report. Move the
        # clock past the reporting cycle behind this call, so the template of
        # the session stream is in the capture before the first snapshot: a
        # data set that arrives before its template cannot be decoded.
        self.virtual_sleep(1)

    def ipfix_collector_packet(self):
        """Return the next IPFIX packet exported to the collector on pg2"""
        try:
            return self.pg2.wait_for_packet(timeout=2)
        except CaptureTimeoutError:
            return None

    def drain_ipfix_collector(self):
        """
        Return the IPFIX packets the collector accumulated since the last
        drain and leave nothing behind

        The packet generator writes the collector pcap while the process
        that exports runs, so a packet can land between two waits. The
        packets are read while they arrive and one last wait confirms the
        interface went idle.

        :returns: Captured IPFIX packets
        """
        capture = []
        while True:
            p = self.ipfix_collector_packet()
            if p is None:
                return capture
            capture.append(p)

    def collect_ipfix_session_events(self):
        """
        Return the NAT44 session records exported to the collector on pg2
        after this call started

        ipfix_flush is not synchronous: it only signals the process that
        exports, which sends the buffers of every thread on its next cycle,
        and a cycle waits up to 5 seconds of VPP time. So the collector is
        drained and then polled with the clock moved forward one second per
        poll, up to IPFIX_EXPORT_POLLS polls, until a packet arrives; the
        remaining packets of that cycle are read until the interface goes
        idle. A cycle slower than the budget fails the test, it never passes
        with fewer records.

        The polling has a second effect that keeps snapshots apart. The
        process that exports waits on a clock event, so its cycle only
        advances while the clock moves, and the clock moves one second per
        empty poll. A record written after this snapshot waits for a later
        snapshot to move the clock far enough for its cycle to run.

        :returns: Decoded NAT44 session records
        """
        self.configure_ipfix_collector()
        self.drain_ipfix_collector()
        self.vapi.ipfix_flush()
        capture = []
        for _ in range(IPFIX_EXPORT_POLLS):
            p = self.ipfix_collector_packet()
            if p is None:
                # the process that exports waits on a clock, so time passes
                # for it only while the clock moves
                self.virtual_sleep(1)
                continue
            capture = [p] + self.drain_ipfix_collector()
            break
        for p in capture:
            self.assertTrue(p.haslayer(IPFIX))
        ipfix = IPFIXDecoder()
        for p in capture:
            if p.haslayer(Template):
                ipfix.add_template(p.getlayer(Template))
        records = self.ipfix_data_records(ipfix, capture)
        records += self.ipfix_stream_records(capture)
        if capture:
            self.assertTrue(
                records,
                "the snapshot holds IPFIX packets but no data set decodes "
                "against the session stream",
            )
        return [
            record
            for record in records
            if NAT_EVENT_SESSION_CREATE
            <= scapy.compat.orb(record[230])
            <= NAT_EVENT_SESSION_DELETE
        ]

    def ipfix_data_records(self, ipfix, packets):
        """
        Decode the data sets of the session stream

        Only the templates and the data sets of the template identifier the
        capture names are used, so a data set of another stream in the same
        packets cannot shift the records of this one.

        :param ipfix: Decoder collecting the templates of the stream
        :param packets: Captured IPFIX packets
        :returns: Decoded data records
        """
        template_id = next(
            (int(p[Set].setID) for p in packets if p.haslayer(Template)), None
        )
        records = []
        for p in packets:
            if not p.haslayer(Data):
                continue
            # a capture without any template is decoded by ipfix_stream_records
            if template_id is not None:
                self.assertEqual(template_id, int(p[Set].setID))
            records.extend(ipfix.decode_data_set(p.getlayer(Set)))
        return records

    def ipfix_stream_records(self, packets):
        """
        Decode the data sets of the session stream with the fields the stream
        sends, whether or not the capture carried its template

        The template is only in a capture when the stream sends it, and the
        stream sends it as a set with a data set, so a snapshot of one
        message after the template normally holds a bare data set.

        :param packets: Captured IPFIX packets
        :returns: Decoded data records
        """
        ipfix = IPFIXDecoder()
        known_ids = set()
        for p in packets:
            if p.haslayer(Template):
                ipfix.add_template(p.getlayer(Template))
                known_ids.add(int(p[Template].templateID))
        records = []
        for p in packets:
            if not p.haslayer(Data) or int(p[Set].setID) in known_ids:
                continue
            data = p[Data].data
            for offset in range(0, len(data), NAT44_SESSION_RECORD_LEN):
                raw = data[offset : offset + NAT44_SESSION_RECORD_LEN]
                if len(raw) < NAT44_SESSION_RECORD_LEN:
                    break
                records.append(
                    dict(
                        zip(
                            NAT44_SESSION_RECORD_FIELDS,
                            [
                                raw[o : o + length]
                                for o, length in NAT44_SESSION_RECORD_LAYOUT
                            ],
                        )
                    )
                )
        return records

    def find_ipfix_session_event(self, records, nat_event, proto, port_pair):
        """
        Return the NAT44 session events of a session

        :param records: Decoded NAT44 session records
        :param nat_event: natEvent value, 4 for create and 5 for delete
        :param proto: IP protocol of the session, None matches every protocol
        :param port_pair: Source and post NAPT transport ports of the session
        :returns: List of matching records
        """
        return [
            record
            for record in records
            if nat_event == scapy.compat.orb(record[230])
            and (proto is None or proto == scapy.compat.orb(record[4]))
            and struct.pack("!H", port_pair[0]) == record[7]
            and struct.pack("!H", port_pair[1]) == record[227]
        ]

    def verify_ipfix_session_event(
        self, records, nat_event, proto, in_addr, out_addr, port_pair
    ):
        """
        Verify that exactly one event of a session names its inside and
        outside address, its protocol and its ports

        :param records: Decoded NAT44 session records
        :param nat_event: natEvent value, 4 for create and 5 for delete
        :param proto: IP protocol of the session
        :param in_addr: Inside IPv4 address of the session
        :param out_addr: Outside IPv4 address of the session
        :param port_pair: Source and post NAPT transport ports of the session
        """
        events = self.find_ipfix_session_event(records, nat_event, proto, port_pair)
        self.assertEqual(1, len(events))
        record = events[0]
        # sourceIPv4Address
        self.assertEqual(socket.inet_pton(socket.AF_INET, in_addr), record[8])
        # postNATSourceIPv4Address
        self.assertEqual(socket.inet_pton(socket.AF_INET, out_addr), record[225])
        # sourceTransportPort
        self.assertEqual(struct.pack("!H", port_pair[0]), record[7])
        # postNAPTSourceTransportPort
        self.assertEqual(struct.pack("!H", port_pair[1]), record[227])
        # ingressVRFID
        self.assertEqual(struct.pack("!I", 0), record[234])

    def verify_ipfix_no_session_event(self, records, nat_event, proto, port_pair):
        """
        Verify that no event of a session was exported

        :param records: Decoded NAT44 session records
        :param nat_event: natEvent value, 4 for create and 5 for delete
        :param proto: IP protocol of the session
        :param port_pair: Source and post NAPT transport ports of the session
        """
        events = self.find_ipfix_session_event(records, nat_event, proto, port_pair)
        self.assertEqual(0, len(events))

    def add_ipfix_tcp_test_map(self):
        """
        Map the inside host on pg0 to the outside address on pg1

        The map puts every session on 10.0.0.3. The /32 map holds the inside
        host, so the detector places a session with it before any other map
        that covers the address, and the ICMP test tells its sessions apart
        from the TCP ones by protocol and port alone.
        """
        self.vapi.det44_add_del_map(
            is_add=1,
            in_addr=self.pg0.remote_ip4,
            in_plen=32,
            out_addr=socket.inet_aton(self.nat_addr),
            out_plen=32,
        )
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index, is_add=1, is_inside=1
        )
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index, is_add=1, is_inside=0
        )

    def send_session_packet(self, in_if, out_if, p, from_inside=True):
        """
        Send one packet through the map and wait for its translation

        The capture of both interfaces is enabled before each packet, so the
        translation is read from pg1 or pg0. pg2 is not in that list, and its
        collector pcap is on already, so it keeps writing while the session
        runs.

        :param in_if: Inside interface
        :param out_if: Outside interface
        :param p: Packet to send
        :param from_inside: Packet goes from inside to outside
        :returns: Translated packet
        """
        src_if, dst_if = (in_if, out_if) if from_inside else (out_if, in_if)
        src_if.add_stream(p)
        self.pg_enable_capture([in_if, out_if])
        self.pg_start()
        return dst_if.get_capture(1)[0]

    def tcp_session_packet(self, in_if, out_if, flags, from_inside=True):
        """
        Return a TCP packet of the session the inside port claims

        :param in_if: Inside interface
        :param out_if: Outside interface
        :param flags: TCP flags like "S", "A", "SA" or "FA"
        :param from_inside: Packet goes from inside to outside
        """
        if from_inside:
            return (
                Ether(src=in_if.remote_mac, dst=in_if.local_mac)
                / IP(src=in_if.remote_ip4, dst=out_if.remote_ip4)
                / TCP(
                    sport=self.tcp_port_in,
                    dport=self.tcp_external_port,
                    flags=flags,
                )
            )
        return (
            Ether(src=out_if.remote_mac, dst=out_if.local_mac)
            / IP(src=out_if.remote_ip4, dst=self.nat_addr)
            / TCP(
                sport=self.tcp_external_port,
                dport=self.tcp_port_out,
                flags=flags,
            )
        )

    def close_tcp_session(self, in_if, out_if):
        """
        Close the TCP session the way test_tcp_session_close_detection_in
        does, which closes it from the node

        The session has to be open when the first FIN arrives. Once it is
        closed its slot holds in_port 0, which snat_det_find_ses_by_in does
        not match, so the packets that follow build a new session and close
        that one instead of finding nothing.

        :param in_if: Inside interface
        :param out_if: Outside interface
        """
        self.send_session_packet(
            in_if, out_if, self.tcp_session_packet(in_if, out_if, "F")
        )
        self.send_session_packet(
            in_if,
            out_if,
            self.tcp_session_packet(in_if, out_if, "A", from_inside=False),
            from_inside=False,
        )
        self.send_session_packet(
            in_if,
            out_if,
            self.tcp_session_packet(in_if, out_if, "F", from_inside=False),
            from_inside=False,
        )
        self.send_session_packet(
            in_if, out_if, self.tcp_session_packet(in_if, out_if, "A")
        )

    def open_icmp_session(self, in_if, out_if):
        """
        Open an ICMP echo session from the inside host, then send a second
        echo request and its reply so the session is reused rather than
        created again

        :param in_if: Inside interface
        :param out_if: Outside interface
        :returns: Translated identifier of the session
        """
        p = self.send_session_packet(
            in_if,
            out_if,
            Ether(src=in_if.remote_mac, dst=in_if.local_mac)
            / IP(src=in_if.remote_ip4, dst=out_if.remote_ip4)
            / ICMP(id=self.icmp_id_in, type="echo-request"),
        )
        out_id = p[ICMP].id
        echo_reply = (
            Ether(src=out_if.remote_mac, dst=out_if.local_mac)
            / IP(src=out_if.remote_ip4, dst=self.nat_addr)
            / ICMP(id=out_id, type="echo-reply")
        )
        self.send_session_packet(in_if, out_if, echo_reply, from_inside=False)
        self.send_session_packet(
            in_if,
            out_if,
            Ether(src=in_if.remote_mac, dst=in_if.local_mac)
            / IP(src=in_if.remote_ip4, dst=out_if.remote_ip4)
            / ICMP(id=self.icmp_id_in, type="echo-request"),
        )
        self.send_session_packet(in_if, out_if, echo_reply, from_inside=False)
        return out_id

    def set_icmp_timeout(self, seconds):
        """
        Set the ICMP timeout of det44 and return the timeouts it replaced

        The timeout applies to the sessions created from now on, and a session
        that exists already keeps the expire it was given: icmp_match_in2out_det
        sets the expire to the clock plus the timeout whenever an echo request
        is translated (det44_in2out.c:236-241), and no other packet writes it.
        """
        timeouts = self.vapi.det44_get_timeouts()
        self.vapi.det44_set_timeouts(
            udp=timeouts.udp,
            tcp_established=timeouts.tcp_established,
            tcp_transitory=timeouts.tcp_transitory,
            icmp=seconds,
        )
        return timeouts

    def terminate_icmp_session_sleep(self, timeouts):
        """
        Move the clock past the expire of the ICMP session and restore timeouts

        The session was opened while the ICMP timeout was 5 seconds, so its
        expire is about 5 seconds after it was opened, and this sleep moves
        the clock 15 seconds past it. That buys the walk a window wider than
        its own period, so the first wake after the sleep ends falls past the
        expire whatever phase the walk's 10 second schedule is in, and the
        delete is written before the sleep ends. The walk has no phase the
        sleep can aim at: every snapshot that ends in an empty poll moves the
        clock, so its wake times drift between tests.

        :param timeouts: Timeouts returned by set_icmp_timeout, put back after
                         the sleep
        """
        self.virtual_sleep(15)
        self.vapi.det44_set_timeouts(
            udp=timeouts.udp,
            tcp_established=timeouts.tcp_established,
            tcp_transitory=timeouts.tcp_transitory,
            icmp=timeouts.icmp,
        )

    def close_tcp_session_by_cli(self):
        """Close the TCP session of the inside host with the session CLI"""
        self.vapi.cli(
            "det44 close session out %s:%d %s:%d"
            % (
                self.nat_addr,
                self.tcp_port_out,
                self.pg1.remote_ip4,
                self.tcp_external_port,
            )
        )

    def tcp_sessions(self):
        """
        Collect the sessions of the inside host of pg0

        The dump reports every slot whose outside key is set, so the reply of
        a close that frees the slot is left out here: a session of the host
        that is gone, and one that holds no slot, both give an empty list.

        :returns: List of det44_session_details of the inside host
        """
        return [
            s
            for s in self.vapi.det44_session_dump(self.pg0.remote_ip4)
            if 0 != s.out_port
        ]

    def initiate_tcp_session(self, in_if, out_if):
        """
        Initiates TCP session 3 WAY HAND SHAKE

        :param in_if: Inside interface
        :param out_if: Outside interface
        """

        # SYN packet in->out
        p = (
            Ether(src=in_if.remote_mac, dst=in_if.local_mac)
            / IP(src=in_if.remote_ip4, dst=out_if.remote_ip4)
            / TCP(sport=self.tcp_port_in, dport=self.tcp_external_port, flags="S")
        )
        in_if.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = out_if.get_capture(1)
        p = capture[0]
        self.tcp_port_out = p[TCP].sport

        # SYN + ACK packet out->in
        p = (
            Ether(src=out_if.remote_mac, dst=out_if.local_mac)
            / IP(src=out_if.remote_ip4, dst=self.nat_addr)
            / TCP(sport=self.tcp_external_port, dport=self.tcp_port_out, flags="SA")
        )
        out_if.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        in_if.get_capture(1)

        # ACK packet in->out
        p = (
            Ether(src=in_if.remote_mac, dst=in_if.local_mac)
            / IP(src=in_if.remote_ip4, dst=out_if.remote_ip4)
            / TCP(sport=self.tcp_port_in, dport=self.tcp_external_port, flags="A")
        )
        in_if.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        out_if.get_capture(1)

    def create_stream_in(self, in_if, out_if, ttl=64):
        """
        Create packet stream for inside network

        :param in_if: Inside interface
        :param out_if: Outside interface
        :param ttl: TTL of generated packets
        """
        pkts = []
        # TCP
        p = (
            Ether(dst=in_if.local_mac, src=in_if.remote_mac)
            / IP(src=in_if.remote_ip4, dst=out_if.remote_ip4, ttl=ttl)
            / TCP(sport=self.tcp_port_in, dport=self.tcp_external_port)
        )
        pkts.append(p)

        # UDP
        p = (
            Ether(dst=in_if.local_mac, src=in_if.remote_mac)
            / IP(src=in_if.remote_ip4, dst=out_if.remote_ip4, ttl=ttl)
            / UDP(sport=self.udp_port_in, dport=self.udp_external_port)
        )
        pkts.append(p)

        # ICMP
        p = (
            Ether(dst=in_if.local_mac, src=in_if.remote_mac)
            / IP(src=in_if.remote_ip4, dst=out_if.remote_ip4, ttl=ttl)
            / ICMP(id=self.icmp_id_in, type="echo-request")
        )
        pkts.append(p)

        return pkts

    def create_stream_out(self, out_if, dst_ip=None, ttl=64):
        """
        Create packet stream for outside network

        :param out_if: Outside interface
        :param dst_ip: Destination IP address (Default use global NAT address)
        :param ttl: TTL of generated packets
        """
        if dst_ip is None:
            dst_ip = self.nat_addr
        pkts = []
        # TCP
        p = (
            Ether(dst=out_if.local_mac, src=out_if.remote_mac)
            / IP(src=out_if.remote_ip4, dst=dst_ip, ttl=ttl)
            / TCP(dport=self.tcp_port_out, sport=self.tcp_external_port)
        )
        pkts.append(p)

        # UDP
        p = (
            Ether(dst=out_if.local_mac, src=out_if.remote_mac)
            / IP(src=out_if.remote_ip4, dst=dst_ip, ttl=ttl)
            / UDP(dport=self.udp_port_out, sport=self.udp_external_port)
        )
        pkts.append(p)

        # ICMP
        p = (
            Ether(dst=out_if.local_mac, src=out_if.remote_mac)
            / IP(src=out_if.remote_ip4, dst=dst_ip, ttl=ttl)
            / ICMP(id=self.icmp_external_id, type="echo-reply")
        )
        pkts.append(p)

        return pkts

    def verify_capture_out(self, capture, nat_ip=None):
        """
        Verify captured packets on outside network

        :param capture: Captured packets
        :param nat_ip: Translated IP address (Default use global NAT address)
        :param same_port: Source port number is not translated (Default False)
        """
        if nat_ip is None:
            nat_ip = self.nat_addr
        for packet in capture:
            try:
                self.assertEqual(packet[IP].src, nat_ip)
                if packet.haslayer(TCP):
                    self.tcp_port_out = packet[TCP].sport
                elif packet.haslayer(UDP):
                    self.udp_port_out = packet[UDP].sport
                else:
                    self.icmp_external_id = packet[ICMP].id
            except:
                self.logger.error(
                    ppp("Unexpected or invalid packet (outside network):", packet)
                )
                raise

    def test_deterministic_mode(self):
        """NAT plugin run deterministic mode"""
        in_addr = "172.16.255.0"
        out_addr = "172.17.255.50"
        in_addr_t = "172.16.255.20"
        in_plen = 24
        out_plen = 32

        self.vapi.det44_add_del_map(
            is_add=1,
            in_addr=in_addr,
            in_plen=in_plen,
            out_addr=out_addr,
            out_plen=out_plen,
        )

        rep1 = self.vapi.det44_forward(in_addr_t)
        self.assertEqual(str(rep1.out_addr), out_addr)
        rep2 = self.vapi.det44_reverse(rep1.out_port_hi, out_addr)

        self.assertEqual(str(rep2.in_addr), in_addr_t)

        deterministic_mappings = self.vapi.det44_map_dump()
        self.assertEqual(len(deterministic_mappings), 1)
        dsm = deterministic_mappings[0]
        self.assertEqual(in_addr, str(dsm.in_addr))
        self.assertEqual(in_plen, dsm.in_plen)
        self.assertEqual(out_addr, str(dsm.out_addr))
        self.assertEqual(out_plen, dsm.out_plen)

    def test_set_timeouts(self):
        """Set deterministic NAT timeouts"""
        timeouts_before = self.vapi.det44_get_timeouts()

        self.vapi.det44_set_timeouts(
            udp=timeouts_before.udp + 10,
            tcp_established=timeouts_before.tcp_established + 10,
            tcp_transitory=timeouts_before.tcp_transitory + 10,
            icmp=timeouts_before.icmp + 10,
        )

        timeouts_after = self.vapi.det44_get_timeouts()

        self.assertNotEqual(timeouts_before.udp, timeouts_after.udp)
        self.assertNotEqual(timeouts_before.icmp, timeouts_after.icmp)
        self.assertNotEqual(
            timeouts_before.tcp_established, timeouts_after.tcp_established
        )
        self.assertNotEqual(
            timeouts_before.tcp_transitory, timeouts_after.tcp_transitory
        )

    def test_in(self):
        """DET44 translation test (TCP, UDP, ICMP)"""

        nat_ip = "10.0.0.10"

        self.vapi.det44_add_del_map(
            is_add=1,
            in_addr=self.pg0.remote_ip4,
            in_plen=32,
            out_addr=socket.inet_aton(nat_ip),
            out_plen=32,
        )

        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index, is_add=1, is_inside=1
        )
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index, is_add=1, is_inside=0
        )

        # in2out
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip)

        # out2in
        pkts = self.create_stream_out(self.pg1, nat_ip)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

        # session dump test
        sessions = self.vapi.det44_session_dump(self.pg0.remote_ip4)
        self.assertEqual(len(sessions), 3)

        # TCP session
        s = sessions[0]
        self.assertEqual(str(s.ext_addr), self.pg1.remote_ip4)
        self.assertEqual(s.in_port, self.tcp_port_in)
        self.assertEqual(s.out_port, self.tcp_port_out)
        self.assertEqual(s.ext_port, self.tcp_external_port)

        # UDP session
        s = sessions[1]
        self.assertEqual(str(s.ext_addr), self.pg1.remote_ip4)
        self.assertEqual(s.in_port, self.udp_port_in)
        self.assertEqual(s.out_port, self.udp_port_out)
        self.assertEqual(s.ext_port, self.udp_external_port)

        # ICMP session
        s = sessions[2]
        self.assertEqual(str(s.ext_addr), self.pg1.remote_ip4)
        self.assertEqual(s.in_port, self.icmp_id_in)
        self.assertEqual(s.out_port, self.icmp_external_id)

    def test_multiple_users(self):
        """Deterministic NAT multiple users"""

        nat_ip = "10.0.0.10"
        port_in = 80
        external_port = 6303

        host0 = self.pg0.remote_hosts[0]
        host1 = self.pg0.remote_hosts[1]

        self.vapi.det44_add_del_map(
            is_add=1,
            in_addr=host0.ip4,
            in_plen=24,
            out_addr=socket.inet_aton(nat_ip),
            out_plen=32,
        )
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index, is_add=1, is_inside=1
        )
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index, is_add=1, is_inside=0
        )

        # host0 to out
        p = (
            Ether(src=host0.mac, dst=self.pg0.local_mac)
            / IP(src=host0.ip4, dst=self.pg1.remote_ip4)
            / TCP(sport=port_in, dport=external_port)
        )
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, nat_ip)
            self.assertEqual(ip.dst, self.pg1.remote_ip4)
            self.assertEqual(tcp.dport, external_port)
            port_out0 = tcp.sport
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # host1 to out
        p = (
            Ether(src=host1.mac, dst=self.pg0.local_mac)
            / IP(src=host1.ip4, dst=self.pg1.remote_ip4)
            / TCP(sport=port_in, dport=external_port)
        )
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, nat_ip)
            self.assertEqual(ip.dst, self.pg1.remote_ip4)
            self.assertEqual(tcp.dport, external_port)
            port_out1 = tcp.sport
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        dms = self.vapi.det44_map_dump()
        self.assertEqual(1, len(dms))
        self.assertEqual(2, dms[0].ses_num)

        # out to host0
        p = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=nat_ip)
            / TCP(sport=external_port, dport=port_out0)
        )
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.pg1.remote_ip4)
            self.assertEqual(ip.dst, host0.ip4)
            self.assertEqual(tcp.dport, port_in)
            self.assertEqual(tcp.sport, external_port)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # out to host1
        p = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=nat_ip)
            / TCP(sport=external_port, dport=port_out1)
        )
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.pg1.remote_ip4)
            self.assertEqual(ip.dst, host1.ip4)
            self.assertEqual(tcp.dport, port_in)
            self.assertEqual(tcp.sport, external_port)
        except:
            self.logger.error(ppp("Unexpected or invalid packet", p))
            raise

        # session close api test
        self.vapi.det44_close_session_out(
            socket.inet_aton(nat_ip), port_out1, self.pg1.remote_ip4, external_port
        )
        dms = self.vapi.det44_map_dump()
        self.assertEqual(dms[0].ses_num, 1)

        self.vapi.det44_close_session_in(
            host0.ip4, port_in, self.pg1.remote_ip4, external_port
        )
        dms = self.vapi.det44_map_dump()
        self.assertEqual(dms[0].ses_num, 0)

    def test_tcp_session_close_detection_in(self):
        """DET44 TCP session close from inside network"""
        self.vapi.det44_add_del_map(
            is_add=1,
            in_addr=self.pg0.remote_ip4,
            in_plen=32,
            out_addr=socket.inet_aton(self.nat_addr),
            out_plen=32,
        )
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index, is_add=1, is_inside=1
        )
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index, is_add=1, is_inside=0
        )

        self.initiate_tcp_session(self.pg0, self.pg1)

        # close the session from inside
        try:
            # FIN packet in -> out
            p = (
                Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
                / TCP(sport=self.tcp_port_in, dport=self.tcp_external_port, flags="F")
            )
            self.pg0.add_stream(p)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.pg1.get_capture(1)

            pkts = []

            # ACK packet out -> in
            p = (
                Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
                / IP(src=self.pg1.remote_ip4, dst=self.nat_addr)
                / TCP(sport=self.tcp_external_port, dport=self.tcp_port_out, flags="A")
            )
            pkts.append(p)

            # FIN packet out -> in
            p = (
                Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
                / IP(src=self.pg1.remote_ip4, dst=self.nat_addr)
                / TCP(sport=self.tcp_external_port, dport=self.tcp_port_out, flags="F")
            )
            pkts.append(p)

            self.pg1.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.pg0.get_capture(2)

            # ACK packet in -> out
            p = (
                Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
                / TCP(sport=self.tcp_port_in, dport=self.tcp_external_port, flags="A")
            )
            self.pg0.add_stream(p)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.pg1.get_capture(1)

            # Check if deterministic NAT44 closed the session
            dms = self.vapi.det44_map_dump()
            self.assertEqual(0, dms[0].ses_num)
        except:
            self.logger.error("TCP session termination failed")
            raise

    def test_tcp_session_close_detection_out(self):
        """Deterministic NAT TCP session close from outside network"""
        self.vapi.det44_add_del_map(
            is_add=1,
            in_addr=self.pg0.remote_ip4,
            in_plen=32,
            out_addr=socket.inet_aton(self.nat_addr),
            out_plen=32,
        )
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index, is_add=1, is_inside=1
        )
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index, is_add=1, is_inside=0
        )

        self.initiate_tcp_session(self.pg0, self.pg1)

        # close the session from outside
        try:
            # FIN packet out -> in
            p = (
                Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
                / IP(src=self.pg1.remote_ip4, dst=self.nat_addr)
                / TCP(sport=self.tcp_external_port, dport=self.tcp_port_out, flags="F")
            )
            self.pg1.add_stream(p)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.pg0.get_capture(1)

            pkts = []

            # ACK packet in -> out
            p = (
                Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
                / TCP(sport=self.tcp_port_in, dport=self.tcp_external_port, flags="A")
            )
            pkts.append(p)

            # ACK packet in -> out
            p = (
                Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
                / TCP(sport=self.tcp_port_in, dport=self.tcp_external_port, flags="F")
            )
            pkts.append(p)

            self.pg0.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.pg1.get_capture(2)

            # ACK packet out -> in
            p = (
                Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
                / IP(src=self.pg1.remote_ip4, dst=self.nat_addr)
                / TCP(sport=self.tcp_external_port, dport=self.tcp_port_out, flags="A")
            )
            self.pg1.add_stream(p)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.pg0.get_capture(1)

            # Check if deterministic NAT44 closed the session
            dms = self.vapi.det44_map_dump()
            self.assertEqual(0, dms[0].ses_num)
        except:
            self.logger.error("TCP session termination failed")
            raise

    def test_session_timeout(self):
        """Deterministic NAT session timeouts"""
        self.vapi.det44_add_del_map(
            is_add=1,
            in_addr=self.pg0.remote_ip4,
            in_plen=32,
            out_addr=socket.inet_aton(self.nat_addr),
            out_plen=32,
        )
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index, is_add=1, is_inside=1
        )
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index, is_add=1, is_inside=0
        )

        self.initiate_tcp_session(self.pg0, self.pg1)
        self.vapi.det44_set_timeouts(udp=5, tcp_established=5, tcp_transitory=5, icmp=5)
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(len(pkts))
        self.virtual_sleep(15)

        dms = self.vapi.det44_map_dump()
        self.assertEqual(0, dms[0].ses_num)

    def test_ipfix_tcp_session_events(self):
        """DET44 IPFIX logging of a TCP session create and delete"""
        self.add_ipfix_tcp_test_map()

        # the SYN claims the session and prints its translated port
        p = self.send_session_packet(
            self.pg0, self.pg1, self.tcp_session_packet(self.pg0, self.pg1, "S")
        )
        self.tcp_port_out = p[TCP].sport
        port_pair = (self.tcp_port_in, self.tcp_port_out)
        self.verify_ipfix_session_event(
            self.collect_ipfix_session_events(),
            NAT_EVENT_SESSION_CREATE,
            IP_PROTOS.tcp,
            self.pg0.remote_ip4,
            self.nat_addr,
            port_pair,
        )

        # the ACK and the SYN/ACK reuse the session, so the next snapshot,
        # which starts after the first one was drained, must name neither a
        # second create nor a delete of it
        self.send_session_packet(
            self.pg0, self.pg1, self.tcp_session_packet(self.pg0, self.pg1, "A")
        )
        self.send_session_packet(
            self.pg0,
            self.pg1,
            self.tcp_session_packet(self.pg0, self.pg1, "SA", from_inside=False),
            from_inside=False,
        )
        records = self.collect_ipfix_session_events()
        self.verify_ipfix_no_session_event(
            records,
            NAT_EVENT_SESSION_CREATE,
            IP_PROTOS.tcp,
            self.pg0.remote_ip4,
            self.nat_addr,
            port_pair,
        )
        self.verify_ipfix_no_session_event(
            records,
            NAT_EVENT_SESSION_DELETE,
            IP_PROTOS.tcp,
            self.pg0.remote_ip4,
            self.nat_addr,
            port_pair,
        )

        # the FIN/ACK handshake closes the session from the node
        self.pg_enable_capture(self.pg_interfaces)
        self.close_tcp_session(self.pg0, self.pg1)
        self.assertEqual([], self.tcp_sessions())
        self.verify_ipfix_session_event(
            self.collect_ipfix_session_events(),
            NAT_EVENT_SESSION_DELETE,
            IP_PROTOS.tcp,
            self.pg0.remote_ip4,
            self.nat_addr,
            port_pair,
        )

    def test_ipfix_icmp_session_events(self):
        """DET44 IPFIX logging of an ICMP echo session create and delete"""
        self.add_ipfix_tcp_test_map()
        # the timeout has to be short before the session exists, since the
        # create fixes its expire
        timeouts = self.set_icmp_timeout(5)
        out_id = self.open_icmp_session(self.pg0, self.pg1)
        # tearDown disables the plugin after every test and that frees the
        # maps, so the table holds the ICMP session and nothing else
        port_pair = (self.icmp_id_in, out_id)
        self.verify_ipfix_session_event(
            self.collect_ipfix_session_events(),
            NAT_EVENT_SESSION_CREATE,
            IP_PROTOS.icmp,
            self.pg0.remote_ip4,
            self.nat_addr,
            port_pair,
        )

        # The walk closes the ICMP session, and the order matters: the delete
        # has to be written before the sleep ends, or the polls of the next
        # snapshot would be what runs the walk that closes it.
        self.terminate_icmp_session_sleep(timeouts)
        # What proves the expiry path ran is the delete record below, an ICMP
        # one with the identifier of this session. It is written by
        # snat_det_ses_close_local into the buffer of thread 0 and leaves on
        # the cycle of the flow report process, which ipfix_flush does not
        # wake; the snapshot polls the clock for that cycle.
        self.verify_ipfix_session_event(
            self.collect_ipfix_session_events(),
            NAT_EVENT_SESSION_DELETE,
            IP_PROTOS.icmp,
            self.pg0.remote_ip4,
            self.nat_addr,
            port_pair,
        )

    def test_ipfix_cli_session_close_event(self):
        """
        DET44 IPFIX logging of a session the CLI closes

        This is a code-path check: the CLI runs its close on the main thread,
        and nat_ipfix_logging_nat44_ses writes the record into the per thread
        data of the thread index it is given (ipfix_logging.c:545). With no
        worker configured, the main thread is thread 0 and the only thread
        that runs, so the close writes thread 0's buffer and the main thread
        flushes it. A delete event of this close therefore proves that the CLI
        close path logged an event, not that a session closed by a node writes
        the index of its thread.
        """
        self.add_ipfix_tcp_test_map()

        # a single SYN claims the session, the close below ends it
        p = self.send_session_packet(
            self.pg0, self.pg1, self.tcp_session_packet(self.pg0, self.pg1, "S")
        )
        self.tcp_port_out = p[TCP].sport
        port_pair = (self.tcp_port_in, self.tcp_port_out)
        self.verify_ipfix_session_event(
            self.collect_ipfix_session_events(),
            NAT_EVENT_SESSION_CREATE,
            IP_PROTOS.tcp,
            self.pg0.remote_ip4,
            self.nat_addr,
            port_pair,
        )

        # The CLI takes the outside address and port first, then the outside
        # address and port of the external host, and keys the lookup on the
        # first address (det44_close_session_out_fn, det44_cli.c:212-236). It
        # closes from the main thread, and the flush that gathers the delete
        # event reaches that thread through nat_ipfix_flush_from_main.
        self.close_tcp_session_by_cli()
        self.assertEqual([], self.tcp_sessions())
        self.verify_ipfix_session_event(
            self.collect_ipfix_session_events(),
            NAT_EVENT_SESSION_DELETE,
            IP_PROTOS.tcp,
            self.pg0.remote_ip4,
            self.nat_addr,
            port_pair,
        )

    # TODO: ipfix needs to be separated from NAT base plugin
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_session_limit_per_user(self):
        """Deterministic NAT maximum sessions per user limit"""
        self.vapi.det44_add_del_map(
            is_add=1,
            in_addr=self.pg0.remote_ip4,
            in_plen=32,
            out_addr=socket.inet_aton(self.nat_addr),
            out_plen=32,
        )
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index, is_add=1, is_inside=1
        )
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index, is_add=1, is_inside=0
        )
        self.vapi.set_ipfix_exporter(
            collector_address=self.pg2.remote_ip4,
            src_address=self.pg2.local_ip4,
            path_mtu=512,
            template_interval=10,
        )
        self.vapi.nat_ipfix_enable_disable(domain_id=1, src_port=4739, enable=1)

        pkts = []
        for port in range(1025, 2025):
            p = (
                Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
                / UDP(sport=port, dport=port)
            )
            pkts.append(p)

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(len(pkts))

        p = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
            / UDP(sport=3001, dport=3002)
        )
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()

        # verify ICMP error packet
        capture = self.pg0.get_capture(1)
        p = capture[0]
        self.assertTrue(p.haslayer(ICMP))
        icmp = p[ICMP]
        self.assertEqual(icmp.type, 3)
        self.assertEqual(icmp.code, 1)
        self.assertTrue(icmp.haslayer(IPerror))
        inner_ip = icmp[IPerror]
        self.assertEqual(inner_ip[UDPerror].sport, 3001)
        self.assertEqual(inner_ip[UDPerror].dport, 3002)

        dms = self.vapi.det44_map_dump()

        self.assertEqual(1000, dms[0].ses_num)

        # verify IPFIX logging
        self.vapi.ipfix_flush()
        capture = self.pg2.get_capture(7)
        ipfix = IPFIXDecoder()
        # first load template
        for p in capture:
            self.assertTrue(p.haslayer(IPFIX))
            if p.haslayer(Template):
                ipfix.add_template(p.getlayer(Template))
        # verify events in data set
        for p in capture:
            if p.haslayer(Data):
                data = ipfix.decode_data_set(p.getlayer(Set))
                self.verify_ipfix_max_entries_per_user(data, 1000, self.pg0.remote_ip4)
        self.vapi.nat_ipfix_enable_disable(domain_id=1, src_port=4739, enable=0)
