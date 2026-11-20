from vpp_interface import VppInterface
import socket
from vpp_papi import mac_pton


class VppPppoeInterface(VppInterface):
    """
    VPP Pppoe interface
    """

    def __init__(
        self,
        test,
        client_ip,
        client_mac,
        session_id,
        decap_vrf_id=0,
        encap_if_index=None,
        disable_fib=0,
    ):
        """Create VPP PPPoE4 interface"""
        super(VppPppoeInterface, self).__init__(test)
        self.client_ip = client_ip
        self.client_mac = client_mac
        self.session_id = session_id
        self.decap_vrf_id = decap_vrf_id
        self.encap_if_index = encap_if_index
        self.disable_fib = disable_fib
        self.vpp_sw_if_index = -1

    def _session_args(self):
        args = {
            "session_id": self.session_id,
            "decap_vrf_id": self.decap_vrf_id,
            "disable_fib": self.disable_fib,
        }
        if self.encap_if_index is not None:
            args["encap_if_index"] = self.encap_if_index
        return args

    def add_vpp_config(self):
        r = self.test.vapi.pppoe_add_del_session_v2(
            self.client_ip, self.client_mac, **self._session_args()
        )
        self.set_sw_if_index(r.sw_if_index)
        self.vpp_sw_if_index = r.sw_if_index
        self.generate_remote_hosts()

    def del_vpp_config(self):
        """Delete the session, returning the reply without examining it"""
        return self.test.vapi.pppoe_add_del_session_v2(
            self.client_ip, self.client_mac, is_add=0, **self._session_args()
        )

    def remove_vpp_config(self):
        self.unconfig()
        self.del_vpp_config()

    def set_unnumbered(self, swif_iface):
        self.test.vapi.sw_interface_set_unnumbered(swif_iface, self.vpp_sw_if_index)
