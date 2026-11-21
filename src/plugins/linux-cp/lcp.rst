.. _Linux_control_plane:

.. toctree::

Linux Control Plane Integration
===============================

Overview
________

This plugin allows VPP to integrate with the Linux kernel. The
general model is that Linux is the network stack, i.e. it has the
control plane protocols, like ARP, IPv6 ND/MLD, ping, etc, and VPP
provides a SW based ASIC for forwarding.

Interfaces
__________

VPP owns the interfaces in the system; physical (.e.g PCI), quasi
physical (e.g. vhost), or virtual (e.g. tunnel). However,
for the Linux networking stack to function it needs a representation
of these interfaces; it needs a mirror image in the kernel. For this
mirror we use a TAP interface, if the VPP interface is multi-point, a
TUN if it's point-to-point. A physical and its mirror form an
interface 'pair'.

The host interface has two identities; the sw_if_index of the TAP and
the virtual interface index in the kernel. It may be in a Linux network
namespace.

The creation of the interface pairs is required from the control
plane. It can be statically configured in the VPP startup
configuration file. The intent here is to make the pair creation
explicit, rather than have VPP guess which of the interfaces it owns
require a mirror.

Configuration
_____________

Linux will send and receive packets on the mirrored tap/tun
interfaces. Any configuration that is made on these Linux interfaces,
also needs to be applied on the corresponding physical interface in
VPP.

This is functionality is provided by the "linux_nl" plugin.

Linux will own the [ARP/ND] neighbor tables (which will be copied via
netlink to VPP also). This means that Linux will send packets with the
peer's MAC address in the rewrite to VPP. The receiving TAP interface
must therefore be in promiscuous mode.

Netlink listener
________________

The ``linux_nl`` plugin mirrors kernel link, address, neighbor, and route
state into VPP through netlink notifications. A notification socket
receives messages into a queue that is processed in batches. Creating
an interface pair opens the socket if necessary; deleting the last pair
closes it. These callbacks do not cancel an active recovery loop.

Recovery
^^^^^^^^

The following conditions request synchronization with the kernel:

* the poller reports an error on the notification socket;
* reading the notification socket fails with an error other than EAGAIN;
* opening the notification socket fails when an interface pair is created.

The polling error callback logs the notification socket descriptor and
queries ``SO_ERROR``. A successful query logs the pending error text and
code, including zero; a failed query logs the query's errno text and
code. Reading ``SO_ERROR`` clears the pending error, so recovery is
requested even if the query fails or returns zero. This diagnostic does
not establish the cause of an earlier incident; in particular, a past
receive-buffer overflow cannot be confirmed without a recorded error.

Each existing recovery attempt performs these steps:

1. Close the notification socket and discard queued notifications.
2. Wait for the synchronization attempt delay (2 seconds by default).
3. Open separate dump sockets for links, addresses, neighbors, and routes,
   then reopen the notification socket. Failure to set nonblocking mode
   or the initial notification socket buffers follows the socket-open
   cleanup and retry path.
4. Request and process the kernel dumps in batches while new notifications
   are queued. A dump read failure, EOF, or notification error event
   observed between batches abandons the attempt.
5. Run the synchronization-end callbacks and resume queued notification
   processing after all dumps complete.

Failed attempts close the dump sockets and repeat the same loop with
its fixed delay; there is no retry limit or increasing delay. The
notification socket is opened before the dump requests to collect
updates during synchronization. The diagnostics add no new recovery
trigger and do not change this synchronization sequence. Updating the
receive buffer size at runtime logs a failure to apply the new size to
an open socket; it does not trigger synchronization.

Diagnostics
^^^^^^^^^^^

``show lcp netlink`` reads listener state without starting recovery or
changing configuration. For example::

  State: notification
  Socket: 7
  Queued messages: 0
  Synchronization attempts: 1
  Synchronization completed: 1
  Synchronization failed: 0

``State`` is ``notification`` during normal notification processing,
including before any socket has been opened, and ``synchronizing``
during recovery and its retry delay. ``Socket`` is the notification
socket descriptor, or -1 when that socket is closed. ``Queued messages``
counts messages received by the plugin that have not yet been applied.

The synchronization counters are cumulative for the lifetime of the
process and have no reset command. An attempt is counted before its
delay; completion is counted after all dump and synchronization-end
callbacks finish, and failure is counted when an attempt is abandoned.
An active attempt can make attempts exceed completed plus failed by one.
The logger records each attempt's start and result. Associated error
messages provide further details where available.

Route ownership
^^^^^^^^^^^^^^^

Each mirrored unicast prefix and route source retains one router table
reference. Replacing or replaying a route preserves that reference; a
partial path deletion releases it only when the source loses its last
path. MPLS end-of-stack and non-end-of-stack entries each retain one
reference. Synchronization releases references for stale sources removed
by the route sweep, including the last route in a table with no paired
interface bound to it. Static, dynamic, and independent API route sources
retain separate ownership.

The permanent IPv4 limited-broadcast receive contribution uses the
``lcp-rt-special`` source. It remains installed once for the router table's
lifetime, independently of learned routes and synchronization sweeps.
A learned static route at that prefix takes priority over the permanent
contribution; the permanent contribution takes priority over learned
dynamic routes. Withdrawing a learned route preserves the permanent
receive contribution.

Limits
^^^^^^

The queue count does not measure notifications dropped before delivery.
The synchronization counters describe the recovery loop; they do not
verify that all Linux and VPP forwarding information base (FIB) entries
are consistent, or that every callback successfully applied each entry.
A completed attempt can still have queued notifications to process.
These diagnostics do not add periodic reconciliation or guarantee
recovery from changes for which no error was detected.

Route mirroring reports, once per path, a nexthop device that is bound
to a different IPv4 or IPv6 FIB table than the mirrored route. Whether
such a path forwards depends on the source address selected in the
route's table being local in the nexthop's table, which mirroring does
not evaluate, so the route is installed unchanged. Multicast and MPLS
paths are not checked this way.

Neighbour synchronization
^^^^^^^^^^^^^^^^^^^^^^^^^

A neighbour record from the kernel is applied to VPP only when it says
the kernel has confirmed the link layer address. The states
``NUD_REACHABLE``, ``NUD_PERMANENT`` and ``NUD_NOARP`` carry a
confirmed address and are synced. The states ``NUD_STALE``,
``NUD_DELAY`` and ``NUD_PROBE`` say the kernel still holds the address
but is revalidating it, and are not synced.

The skip is deliberate. ``ip_neighbor_add()`` clears
``IP_NEIGHBOR_FLAG_STALE`` and resets the probe count on every call, so
a record the kernel is revalidating cannot arrive in VPP as anything
but a just-confirmed entry. Syncing it would turn the kernel's pending
revalidation into VPP's confirmation, which is how a device that has
stopped answering keeps looking alive. The next confirmed record for
the address is what updates VPP.

During a synchronization, such a record keeps the dynamic entry VPP
already holds, without marking that entry as confirmed.

A record with no link layer address, and one whose state is none of the
six above, is treated as a delete: VPP holds no usable address for it.
This covers ``NUD_FAILED``, which the kernel sends for a host that
stopped answering, and ``NUD_INCOMPLETE``.

A static entry in VPP is changed only by the owner that installed it.
Under linux-cp the kernel is that owner for the static neighbours the
plugin installed from its own records, so the plugin remembers which
address and interface pairs it wrote and with which link layer address.
When the kernel later reports a different link layer address for one of
them, the add is refused by the neighbour module, and the plugin makes
the delete and add an operator would do by hand. The correction is
counted as replaced. The correction is not made when the entry no
longer carries the address the plugin wrote: an operator has
reprogrammed it since, and it is that owner's to change.

Refusals are counted, whether or not the plugin can correct them. Three
cumulative counters are kept for the lifetime of the process, and
``show lcp neighbors`` prints them::

  Refused: 0
  Replaced: 0
  Stale skipped: 0

``Refused`` counts neighbour adds the neighbour module rejected.
``Replaced`` counts static entries the plugin corrected with a delete
and add. ``Stale skipped`` counts records the kernel reported as
revalidating, outside a synchronization; a dump repeats the state of
every revalidating neighbour it holds, so those are not counted.

The same three numbers are published in the statistics segment as
``/lcp/neighbor/refused``, ``/lcp/neighbor/replaced`` and
``/lcp/neighbor/stale-skipped``. Reading a path reads one directory
entry and walks no counter set.

Forwarding
__________

The basic principle is to x-connect traffic from a Linux host interface
(received on the tap/tun) to its paired the physical, and vice-versa.

Host to Physical
^^^^^^^^^^^^^^^^

All packets sent by the host, and received by VPP on a tap/tun should
be sent to its paired physical interface. However, they should be sent
with the same consequences as if they had originated from VPP,
i.e. they should be subject to all output features on the physical
interface. To achieve this there is a per-IP-address-family (AF) node
inserted in the per-AF input feature arc. The node must be per-AF,
since it must be a sibling of a start node for the ipX-output feature
arc. This node uses the packet's L2 rewrite to search for the
adjacency that VPP would have used to send this packet; this adjacency
is stored in the buffer's meta data so that it is available to all
output features. Then the packet is sent through the physical
interface's IP output feature arc.

All ARP packets are x-connected from the tap to the physical.

Physical to Host
^^^^^^^^^^^^^^^^

All ARP packets received on the physical are sent to the paired
tap. This allows the Linux network stack to build the neighbor table.

IP packets that are punted are sent to the host. They are sent on the
tap that is paired with the physical on which they were originally
received. The packet is sent on the tap/tun 'exactly' as it was
received (i.e. with the L2 rewrite) but post any translations that
input features may have made.


Recommendations
^^^^^^^^^^^^^^^

When using this plugin disable the ARP, ND, IGMP plugins; this is the
task for Linux.  Disable ping plugin, since Linux will now respond.
