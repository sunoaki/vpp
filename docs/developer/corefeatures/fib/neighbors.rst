.. _neighbors:

Neighbours
^^^^^^^^^^^

.. figure:: /_images/ip-neighbor.png

Figure 1: Neighbour data model

Figure 1 shows the data model for IP neighbours. An IP neighbour contains the mapping
between a peer, identified by an IPv4 or IPv6 address, and its MAC address on a given
interface. An IP-table (VRF) is not part of the neighbour's
data/identity. This is because the virtualization of a router into
different tables (VRFs) is performed at the interface level, i.e. an
IP-table is bound to a particular interface. A neighbour, which is
attached to an interface, is thus implicitly in that table, and
only in that table. It is also worth noting that IP neighbours
contribute forwarding for the egress direction, whereas an IP-table
is an ingress only function.

The *ip_neighbor_t* represents the control-plane addition of the
neighbour. The *ip_adjacency_t* contains the data derived from the *ip_neighbor_t* that is needed to
forward packets to the peer. The additional data in the adjacency are the *rewrite*
and the *link_type*. The *link_type* is a description of the protocol of the packets
that will be forwarded with this adjacency; e.g. IPv4, IPv6 or MPLS. The *link_type*
maps directly to the ether-type in an Ethernet header, or the protocol filed in a
GRE header. The rewrite is a byte string representation of the header that will be
prepended to the packet when it is sent to that peer. For Ethernet interfaces this
is be the src,dst MAC and the ether-type. For LISP tunnels, the IP src,dst pair
and the LISP header.

The *ip_neighbor_t* for an IPv4 peer (learned e.g. over ARP) will
install a *link_type=IPv4* when the entry is created and a
link_type=MPLS on demand (i.e. when a route with output labels resolves via the peer).

A neighbour is keyed by its address and interface, so the same address can
exist on several interfaces. When that happens in one IP table, both entries
install a */32* adj-fib for the same prefix and only one of them can be what the
control plane intends. VPP keeps both and logs a warning naming the two
interfaces, leaving the choice to the operator.

Removing the last interface address that covers a neighbour also removes the
neighbour, and its adj-fib, whether the entry is dynamic or static. A static
entry is operator configuration and nothing re-adds it, so it is kept as long
as any address still configured on the interface covers it: deleting one of
several addresses that share a prefix does not discard neighbours the others
still resolve. A dynamic entry is removed with the address and is learned
again from the next packet.

Aging is off by default. Both address families start with an age of 0, which
means no neighbour is ever probed or expired: a dynamic entry stays until
the interface address that covers it is removed, the interface goes down, the
control plane deletes it, or the table it resolves through is deleted. The
total number of neighbours per address family is bounded by *limit* instead
(50000 by default), counted across every interface and every table, and with
aging off reaching that limit refuses new learns rather than expiring old ones
unless *recycle* is set. Aging is enabled per address family with
``set ip neighbor-config ip4|ip6 age <seconds>``, and an entry is then probed
once its age has passed and destroyed after three unanswered probes.

Moving an address from one interface to another is two operations, and the
order decides what happens to the neighbours of the old interface. Deleting
the address from the old interface first destroys every neighbour that address
covered, static ones included, before the address exists on the new interface:
the traffic is blackholed for the interval between the two calls, and after the
second call a dynamic entry is learned again while a static entry is not, so a
control plane that programs static neighbours has to program them again on the
new interface. The other order is only available inside a replace window: a
plain add of a prefix that another interface in the same table already holds is
refused, and a control plane has to bracket the move with
``sw_interface_address_replace_begin`` and ``sw_interface_address_replace_end``.
Inside that window the add of the prefix on the new interface deletes the old
interface's copy first, which destroys the neighbours that address covered at
that moment, so the old interface's neighbours go either way. Nothing migrates
a neighbour between interfaces, because the interface is part of its key.

A complete adjacency forwards to its rewrite and never asks ARP or ND for the
address again, so the MAC of a static entry is only ever replaced by the
control plane. When the device behind a static neighbour is replaced and the
new device answers with a different MAC, the data plane's learn is refused in
order to keep the entry the control plane programmed, and the entry keeps
forwarding to the old MAC. The refusal is not silent: it is logged, it
increments the ``/net/ip-neighbor/refused-learn`` counter for the interface,
and the entry carries the *refused* flag until the control plane rewrites or
deletes it, or a learn confirms the MAC it already holds. ``show ip neighbors``
prints that flag as an ``R`` in its Flags column, and ``show ip neighbor-stats``
prints the counter as ``if:`` on the interface's line. An entry carrying that
flag is the one to look at when traffic to an address keeps reaching a device
that was replaced. The flag is internal to this module and deliberately absent
from the binary API, because it describes what the data plane observed rather
than configuration, and adding it to the API would change the wire format of
messages that downstream users already encode against.

Adjacency
---------

There are three sub-types of adjacencies. Purists would argue that some
of these sub-types are not really adjacencies but are instead other
forms of DPOs, and it would be hard to argue against that, but
historically (not just in VPP, but in the FIB implementations from
which VPP draws on for some of its concepts), these have been modelled
as adjacency types, the one thing they have in common is that they
have an associated interface and are terminal. The [sub] sub-types are:

* A Neighbour Adjacency (key={interface, next-hop, link-type}). A
  representation of a peer on a link (as described above). A neighbour adjacency itself has
  two sub-types; terminal and mid-chain. When one speak of 'an
  adjacency' one is usually referring to a terminal neighbour
  sub-type. A mid-chain adjacency represents a neighbor on a virtual
  interface which relies on the FIB to perform further forwarding. This
  adjacency is thus not terminal for the FIB object graph but instead
  appears in the 'middle' (the term chain is a synonym for graph in
  some contexts).
  A neighbour adjacency can be in one of two states; complete and
  incomplete. A complete adjacency knows the rewrite string that
  should be used to reach the peer, an incomplete adjacency does
  not. If the adjacency was added as a result of the addition of an
  *ip_neighbor_t* then the adjacency will be complete (because the
  *ip_neighbor_t* knows the peer's MAC address). An incomplete
  adjacency is created on demand by the FIB when a route's path
  requires to resolve through such an adjacency. It is thus created in
  order to resolve the missing dependency, it will become complete
  once the *ip_neighbor_t* is discovered.
  In the forwarding path a complete adjacency will prepend the rewrite
  string and transmit on the egress interface, an incomplete adjacency
  will construct a ARP/ND request to resolve the peer's IP address.

* A Glean Adjacency (key={interface}). This is a representation of the need to discover
  a peer on the given interface. It is used when it is known that the
  packet is destined to an undiscovered peer on that interface. The
  difference between the glean adjacency and an
  incomplete neighbour adjacency is that in the forwarding path the
  glean adjacency will construct an ARP/ND request for the peer as
  determined from the packet's destination address. The glean
  adjacency is used to resolve connected prefixes on multi-access
  interfaces.

* A Multicast Adjacency (key={interface}). This represents the need to send an IP
  multicast packet out of the adjacency's associated interface. Since
  IP multicast constructs the destination MAC address from the IP
  packet's destination/group address, the rewrite is always known and
  hence the adjacency is always complete.


All adjacency types can be shared between routes, hence each type is
stored in a DB whose key is appropriate for the type.
