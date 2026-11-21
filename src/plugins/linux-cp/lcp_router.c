/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#include <sys/socket.h>
#include <linux/if.h>
#include <linux/mpls.h>

#include <vlib/unix/plugin.h>
#include <linux-cp/lcp_nl.h>
#include <linux-cp/lcp_interface.h>
#include <linux-cp/lcp_router.h>

#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/nexthop.h>
#include <netlink/route/addr.h>
#include <netlink/route/link/vlan.h>

#include <vlib/stats/stats.h>

#include <vnet/api_errno.h>
#include <vnet/fib/fib_entry_src.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/ip/ip6_ll_table.h>
#include <vnet/ip-neighbor/ip_neighbor.h>
#include <vnet/ip/ip6_link.h>

/*
 * A group or source and group pair the plugin installed in the MFIB. The
 * plugin keeps the list because the MFIB offers no way to ask which entries
 * a given source installed, and a synchronization has to tell the ones the
 * kernel no longer has from the ones it does.
 */
typedef struct
{
  mfib_prefix_t lcme_prefix;
  /* the synchronization in progress replayed this one */
  u8 lcme_replayed;
} lcp_router_mcast_entry_t;

/*
 * An IPv4 route whose kernel nexthop carries RTNH_F_ONLINK names a gateway the
 * kernel treats as directly reachable although no connected prefix covers it.
 * The FIB has no path flag with that meaning, and arp_reply() accepts a reply
 * only when an attached or connected FIB entry covers its sender, so without
 * such an entry the gateway's neighbour is never learned and the route never
 * forwards.  The plugin installs the gateway's host prefix as an attached
 * entry of its own, shaped like the adj-fib ip_neighbor_adj_fib_add() creates,
 * and keeps one record per route and gateway that holds it: a gateway named by
 * several routes is installed once and removed when the last record goes.
 */
typedef struct
{
  /* the route that named the gateway */
  fib_prefix_t lcor_route;
  ip46_address_t lcor_gateway;
  u32 lcor_sw_if_index;
} lcp_router_onlink_route_t;

typedef struct lcp_router_table_t_
{
  uint32_t nlt_id;
  fib_protocol_t nlt_proto;
  /* the source whose lock holds nlt_fib_index, and which the unlock uses */
  fib_source_t nlt_fib_src;
  /* the table counted an API or CLI lock when the record was made, and that
   * is the lock a delete of the table spends */
  u8 nlt_api_owned;
  u32 nlt_fib_index;
  u32 nlt_mfib_index;
  u32 nlt_refs;
  /* multicast routes the plugin holds in nlt_mfib_index, one reference each */
  lcp_router_mcast_entry_t *nlt_mcast_entries;
  /* onlink gateways the plugin installed an attached host prefix for */
  lcp_router_onlink_route_t *nlt_onlink_routes;
} lcp_router_table_t;

static uword *lcp_router_table_db[FIB_PROTOCOL_MAX];
static lcp_router_table_t *lcp_router_table_pool;
static vlib_log_class_t lcp_router_logger;

/*
 * A route can name a nexthop device that belongs to a different FIB table than
 * the table the route is installed into.  Whether such a path forwards depends
 * on the source address the route's table selects being local in the nexthop's
 * table, so the condition cannot be resolved here.  The route is installed
 * unchanged; these keys remember which paths have already been reported, so a
 * netlink replay or a socket rebuild reports each one once.  The keys are
 * bounded: past the limit the whole set is dropped and the paths are reported
 * again rather than growing without limit.
 */
#define LCP_ROUTER_CROSS_FIB_MAX_KEYS 1024

typedef struct
{
  u32 lcf_key_table_id;
  u32 lcf_sw_if_index;
  u32 lcf_fib_index;
  u32 lcf_nexthop_fib_index;
  ip46_address_t lcf_addr;
  u16 lcf_prefix_len;
  fib_protocol_t lcf_proto;
} lcp_router_cross_fib_key_t;

static uword *lcp_router_cross_fib_db;
static u32 lcp_router_cross_fib_reports;

const static fib_prefix_t pfx_all1s = {
  .fp_addr = {
    .ip4 = {
      .as_u32 = 0xffffffff,
    }
  },
  .fp_proto = FIB_PROTOCOL_IP4,
  .fp_len = 32,
};

static fib_source_t lcp_rt_fib_src;
static fib_source_t lcp_rt_fib_src_dynamic;
static fib_source_t lcp_rt_fib_src_special;
/* attached host prefixes installed for RTNH_F_ONLINK gateways */
static fib_source_t lcp_rt_fib_src_onlink;

#define LCP_ROUTER_DBG(...) vlib_log_debug (lcp_router_logger, __VA_ARGS__);

#define LCP_ROUTER_INFO(...) vlib_log_notice (lcp_router_logger, __VA_ARGS__);

#define LCP_ROUTER_WARN(...) vlib_log_warn (lcp_router_logger, __VA_ARGS__);

#define LCP_ROUTER_ERROR(...) vlib_log_err (lcp_router_logger, __VA_ARGS__);

/* Set between the neighbour synchronization's begin and end steps. A dump
 * delivers every neighbour's current state, so a failed neighbour arrives
 * there on every resynchronization and is reported at debug level instead. */
static u8 lcp_router_neigh_sync_active;

/* Set for a synchronization whose begin step marked the dynamic neighbours,
 * which is what makes its end step sweep them. The mark is the sweep's
 * subject, not a general stale bit: a mark set by anything else, the
 * neighbour replace API's begin step among them, is that caller's to clear. */
static u8 lcp_router_neigh_sync_marked;

/*
 * The neighbour states that say the kernel has confirmed the link layer
 * address. ip_neighbor_add() has no way to express the states that say it has
 * not: ip_neighbor_refresh() calls ip_neighbor_touch(), which clears
 * IP_NEIGHBOR_FLAG_STALE and resets the probe count on every add, so a
 * neighbour synced from a revalidating kernel record arrives in VPP as one
 * just confirmed. Syncing nothing for those records is what keeps the
 * kernel's pending revalidation from becoming VPP's confirmation.
 */
#define LCP_ROUTER_NUD_CONFIRMED    (NUD_REACHABLE | NUD_PERMANENT | NUD_NOARP)
#define LCP_ROUTER_NUD_REVALIDATING (NUD_STALE | NUD_DELAY | NUD_PROBE)

/*
 * A neighbour synchronization is a netlink callback, not a graph node, so it
 * has no error counters to raise, and a refusal logged at LCP_ROUTER_ERROR is
 * invisible where the lcp logger is off. The outcomes an operator has to be
 * able to see are published as stat segment gauges instead: the plugin keeps
 * the totals, which only the main thread writes, and copies them out.
 */
static u64 lcp_router_neigh_refused;
static u64 lcp_router_neigh_replaced;
static u64 lcp_router_neigh_stale_skipped;
static u32 lcp_router_neigh_refused_stat = STAT_SEGMENT_INDEX_INVALID;
static u32 lcp_router_neigh_replaced_stat = STAT_SEGMENT_INDEX_INVALID;
static u32 lcp_router_neigh_stale_skipped_stat = STAT_SEGMENT_INDEX_INVALID;

static void
lcp_router_neigh_stat_publish (u32 entry, u64 value)
{
  if (STAT_SEGMENT_INDEX_INVALID != entry)
    vlib_stats_set_gauge (entry, value);
}

/*
 * The static neighbours the plugin installed, by address and interface. The
 * kernel owns a static neighbour under linux-cp: the plugin installs one for
 * a record the kernel marks NUD_PERMANENT or NUD_NOARP, and the kernel can
 * change that record into one it learned, with another device's link layer
 * address. A static entry in VPP is only changed by its owner, so the plugin
 * may only correct an entry it installed itself. This records which those
 * are, and the link layer address the plugin wrote, so an entry an operator
 * reprogrammed in the meantime is left alone.
 */
typedef struct
{
  ip_address_t lcns_ip;
  u32 lcns_sw_if_index;
} lcp_router_neigh_static_key_t;

/* the key to the link layer address the plugin wrote, packed into the value */
static uword *lcp_router_neigh_static_db;

static void
lcp_router_neigh_static_key (lcp_router_neigh_static_key_t *key, const ip_address_t *ip,
			     u32 sw_if_index)
{
  clib_memset (key, 0, sizeof (*key));
  ip_address_copy (&key->lcns_ip, ip);
  key->lcns_sw_if_index = sw_if_index;
}

/*
 * Record that the plugin wrote the static entry at a key with this link layer
 * address. Only a static write is recorded: a dynamic entry is re-installed
 * from the next kernel record, so nothing about it is the plugin's to correct
 * later, and a refusal of it says the static entry belongs to someone else.
 */
static void
lcp_router_neigh_static_record (const ip_address_t *ip, u32 sw_if_index, const mac_address_t *mac)
{
  lcp_router_neigh_static_key_t key;

  lcp_router_neigh_static_key (&key, ip, sw_if_index);

  /*
   * A key that is already recorded keeps its allocation: hash_set_mem_alloc()
   * copies the key and would leave the previous copy to no one on a key the
   * hash already holds, and a resynchronization re-records every static entry
   * it dumps.
   */
  if (lcp_router_neigh_static_db)
    {
      uword *recorded = hash_get_mem (lcp_router_neigh_static_db, &key);

      if (recorded)
	{
	  recorded[0] = mac_address_as_u64 (mac);
	  return;
	}
    }
  else
    lcp_router_neigh_static_db = hash_create_mem (0, sizeof (key), sizeof (uword));

  hash_set_mem_alloc (&lcp_router_neigh_static_db, &key, mac_address_as_u64 (mac));
}

/*
 * Forget the plugin's ownership of the entry at a key. An add never demotes a
 * static entry by itself, but a correction does: it deletes the entry the
 * plugin wrote and adds the dynamic one the kernel reported, so the entry is
 * no longer static and the record goes with the ownership. A delete of the
 * entry, or of its interface, ends the ownership the same way.
 */
static void
lcp_router_neigh_static_forget (const ip_address_t *ip, u32 sw_if_index)
{
  lcp_router_neigh_static_key_t key;

  if (NULL == lcp_router_neigh_static_db)
    return;

  lcp_router_neigh_static_key (&key, ip, sw_if_index);
  hash_unset_mem_free (lcp_router_neigh_static_db, &key);
}

/* The link layer address the plugin wrote for the entry at a key. */
static u8
lcp_router_neigh_static_recorded (const ip_address_t *ip, u32 sw_if_index, mac_address_t *mac)
{
  lcp_router_neigh_static_key_t key;
  uword *recorded;

  if (NULL == lcp_router_neigh_static_db)
    return 0;

  lcp_router_neigh_static_key (&key, ip, sw_if_index);

  recorded = hash_get_mem (lcp_router_neigh_static_db, &key);
  if (NULL == recorded)
    return 0;

  mac_address_from_u64 (mac, recorded[0]);

  return 1;
}

typedef struct
{
  const ip_address_t *lcnow_ip;
  ip_neighbor_t *lcnow_ipn;
} lcp_router_neigh_owned_ctx_t;

static walk_rc_t
lcp_router_neigh_owned_walk (index_t ipni, void *arg)
{
  lcp_router_neigh_owned_ctx_t *ctx = arg;
  ip_neighbor_t *ipn = ip_neighbor_get (ipni);

  if (0 != ip_address_cmp (ip_neighbor_get_ip (ipn), ctx->lcnow_ip))
    return WALK_CONTINUE;

  ctx->lcnow_ipn = ipn;

  return WALK_STOP;
}

/* The neighbour at a key, as the neighbour module holds it now. */
static ip_neighbor_t *
lcp_router_neigh_find (const ip_address_t *ip, u32 sw_if_index)
{
  lcp_router_neigh_owned_ctx_t ctx = { .lcnow_ip = ip };

  ip_neighbor_walk (ip_addr_version (ip), sw_if_index, lcp_router_neigh_owned_walk, &ctx);

  return ctx.lcnow_ipn;
}

/*
 * Whether the static entry at a key is still the plugin's to change: the
 * plugin wrote it, and the entry still carries the link layer address the
 * plugin wrote. An operator who reprogrammed the entry since owns it now, and
 * an entry the plugin never installed is not its own either.
 */
static u8
lcp_router_neigh_static_owned (const ip_address_t *ip, u32 sw_if_index)
{
  ip_neighbor_t *ipn;
  mac_address_t recorded;

  if (!lcp_router_neigh_static_recorded (ip, sw_if_index, &recorded))
    return 0;

  ipn = lcp_router_neigh_find (ip, sw_if_index);
  if (NULL == ipn)
    return 0;

  return (0 == mac_address_cmp (ip_neighbor_get_mac (ipn), &recorded));
}

/*
 * Record the entry an add just wrote, or drop the ownership record for it.
 * The neighbour module never demotes a static entry, so an add that carried a
 * dynamic flag leaves a static entry static and its record stands. Only an
 * entry that is static now is recorded, with the link layer address the module
 * holds for it; an entry that is dynamic has nothing the plugin would later
 * correct, and any record left over for the key belongs to an entry that is
 * gone.
 */
static void
lcp_router_neigh_static_reconcile (const ip_address_t *ip, u32 sw_if_index,
				   ip_neighbor_flags_t flags)
{
  mac_address_t recorded;
  ip_neighbor_t *ipn;

  /*
   * The lookup walks the neighbours of the interface, so it is only done when
   * a record can exist or be wanted. A dynamic add for a key the plugin never
   * wrote has nothing to record and no record to drop, and walking for it
   * would make a dump of a large table quadratic.
   */
  if (!(flags & IP_NEIGHBOR_FLAG_STATIC) &&
      !lcp_router_neigh_static_recorded (ip, sw_if_index, &recorded))
    return;

  ipn = lcp_router_neigh_find (ip, sw_if_index);

  if (ipn && (ipn->ipn_flags & IP_NEIGHBOR_FLAG_STATIC))
    lcp_router_neigh_static_record (ip, sw_if_index, ip_neighbor_get_mac (ipn));
  else
    lcp_router_neigh_static_forget (ip, sw_if_index);
}

/*
 * An interface is gone, and so is every static entry the plugin installed on
 * it, since the neighbour flush on interface delete removes them whatever
 * their kind. Their keys can no longer be reached by a netlink record, and a
 * sw_if_index later handed to another interface must not inherit them.
 */
static void
lcp_router_neigh_static_flush_if (u32 sw_if_index)
{
  lcp_router_neigh_static_key_t **doomed = NULL;
  hash_pair_t *p;
  u32 i;

  if (NULL == lcp_router_neigh_static_db)
    return;

  /*
   * The keys are collected first: a hash cannot be walked while it is being
   * unset. The key memory outlives the walk, because hash_set_mem_alloc()
   * allocates each key on its own.
   */
  hash_foreach_pair (p, lcp_router_neigh_static_db, ({
		       lcp_router_neigh_static_key_t *key = uword_to_pointer (p->key, void *);

		       if (key->lcns_sw_if_index == sw_if_index)
			 vec_add1 (doomed, key);
		     }));

  for (i = 0; i < vec_len (doomed); i++)
    hash_unset_mem_free (lcp_router_neigh_static_db, doomed[i]);

  vec_free (doomed);
}

static const mfib_prefix_t ip4_specials[] = {
  /* ALL prefixes are in network order */
  {
   /* (*,224.0.0.0)/24 - all local subnet */
   .fp_grp_addr = {
		   .ip4.data_u32 = 0x000000e0,
		   },
   .fp_len = 24,
   .fp_proto = FIB_PROTOCOL_IP4,
   },
};

static const mfib_prefix_t ip6_specials[] = {
  /* ALL prefixes are in network order */
  {
   /* (*,ff00::)/8 - all local subnet */
   .fp_grp_addr = {
		   .ip6.as_u64[0] = 0x00000000000000ff,
		   },
   .fp_len = 8,
   .fp_proto = FIB_PROTOCOL_IP6,
   },
};

static u32
lcp_router_intf_h2p (u32 host)
{
  lcp_itf_pair_t *lip;
  index_t lipi;

  /*
   * Find the PHY interface paired with the Linux VIF named in the netlink
   * message.
   */
  lipi = lcp_itf_pair_find_by_vif (host);

  if (INDEX_INVALID == lipi)
    return (~0);

  lip = lcp_itf_pair_get (lipi);

  return lip->lip_phy_sw_if_index;
}

/*
 * Check timestamps on netlink message and interface pair to decide whether
 * the message should be applied. See the declaration of nl_msg_info_t for
 * an explanation on why this is necessary.
 * If timestamps are good (message ts is newer than intf pair ts), return 0.
 * Else, return -1.
 */
static int
lcp_router_lip_ts_check (nl_msg_info_t *msg_info, lcp_itf_pair_t *lip)
{
  if (!msg_info)
    return 0;

  if (msg_info->ts > lip->lip_create_ts)
    return 0;

  LCP_ROUTER_INFO ("Early message received for %U",
		   format_vnet_sw_if_index_name, vnet_get_main (),
		   lip->lip_phy_sw_if_index);
  return -1;
}

static void
lcp_router_link_del (struct rtnl_link *rl, void *ctx)
{
  index_t lipi;

  if (!lcp_auto_subint ())
    return;

  lipi = lcp_itf_pair_find_by_vif (rtnl_link_get_ifindex (rl));

  if (INDEX_INVALID != lipi)
    {
      lcp_itf_pair_t *lip;

      lip = lcp_itf_pair_get (lipi);

      if (lcp_router_lip_ts_check ((nl_msg_info_t *) ctx, lip))
	return;

      u32 phy_sw_if_index = lip->lip_phy_sw_if_index;
      u32 host_sw_if_index = lip->lip_host_sw_if_index;

      LCP_ROUTER_INFO ("delete link: %s - %U", rtnl_link_get_type (rl),
		       format_vnet_sw_if_index_name, vnet_get_main (), phy_sw_if_index);
      lcp_itf_pair_delete (phy_sw_if_index);

      if (rtnl_link_is_vlan (rl))
	{
	  LCP_ROUTER_INFO ("delete vlan: %s -> %U", rtnl_link_get_name (rl),
			   format_vnet_sw_if_index_name, vnet_get_main (), phy_sw_if_index);
	  vnet_delete_sub_interface (phy_sw_if_index);
	  vnet_delete_sub_interface (host_sw_if_index);
	}
    }
  else
    LCP_ROUTER_INFO ("ignore link del: %s - %s", rtnl_link_get_type (rl),
		     rtnl_link_get_name (rl));
}

static void
lcp_router_ip4_mroutes_add_del (u32 sw_if_index, u8 is_add)
{
  const fib_route_path_t path = {
    .frp_proto = DPO_PROTO_IP4,
    .frp_addr = zero_addr,
    .frp_sw_if_index = sw_if_index,
    .frp_fib_index = ~0,
    .frp_weight = 1,
    .frp_mitf_flags = MFIB_ITF_FLAG_ACCEPT,
  };
  u32 mfib_index;
  int ii;

  mfib_index =
    mfib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index);

  for (ii = 0; ii < ARRAY_LEN (ip4_specials); ii++)
    {
      if (is_add)
	{
	  mfib_table_entry_path_update (mfib_index, &ip4_specials[ii], MFIB_SOURCE_SPECIAL,
					MFIB_ENTRY_FLAG_NONE, &path);
	}
      else
	{
	  mfib_table_entry_path_remove (mfib_index, &ip4_specials[ii], MFIB_SOURCE_SPECIAL, &path);
	}
    }
}

static void
lcp_router_ip6_mroutes_add_del (u32 sw_if_index, u8 is_add)
{
  const fib_route_path_t path = {
    .frp_proto = DPO_PROTO_IP6,
    .frp_addr = zero_addr,
    .frp_sw_if_index = sw_if_index,
    .frp_fib_index = ~0,
    .frp_weight = 1,
    .frp_mitf_flags = MFIB_ITF_FLAG_ACCEPT,
  };
  u32 mfib_index;
  int ii;

  mfib_index =
    mfib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6, sw_if_index);

  for (ii = 0; ii < ARRAY_LEN (ip6_specials); ii++)
    {
      if (is_add)
	{
	  mfib_table_entry_path_update (mfib_index, &ip6_specials[ii], MFIB_SOURCE_SPECIAL,
					MFIB_ENTRY_FLAG_NONE, &path);
	}
      else
	{
	  mfib_table_entry_path_remove (mfib_index, &ip6_specials[ii], MFIB_SOURCE_SPECIAL, &path);
	}
    }
}

static void
lcp_router_link_mtu (struct rtnl_link *rl, u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 mtu;
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hw;

  mtu = rtnl_link_get_mtu (rl);
  if (!mtu)
    return;

  sw = vnet_get_sw_interface (vnm, sw_if_index);
  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);

  /* If HW interface, try to change hw link */
  if ((sw->sw_if_index == sw->sup_sw_if_index) &&
      (hw->hw_class_index == ethernet_hw_interface_class.index))
    vnet_hw_interface_set_mtu (vnm, hw->hw_if_index, mtu);
  else
    vnet_sw_interface_set_mtu (vnm, sw->sw_if_index, mtu);
}

static walk_rc_t
lcp_router_link_addr_adj_upd_cb (vnet_main_t *vnm, u32 sw_if_index, void *arg)
{
  lcp_itf_pair_t *lip;

  lip = lcp_itf_pair_get (lcp_itf_pair_find_by_phy (sw_if_index));
  if (!lip)
    {
      return WALK_CONTINUE;
    }

  vnet_update_adjacency_for_sw_interface (vnm, lip->lip_phy_sw_if_index,
					  lip->lip_phy_adjs.adj_index[AF_IP4]);
  vnet_update_adjacency_for_sw_interface (vnm, lip->lip_phy_sw_if_index,
					  lip->lip_phy_adjs.adj_index[AF_IP6]);

  return WALK_CONTINUE;
}

static void
lcp_router_link_addr (struct rtnl_link *rl, lcp_itf_pair_t *lip)
{
  vnet_main_t *vnm = vnet_get_main ();
  struct nl_addr *mac_addr;
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hw;
  void *mac_addr_bytes;

  mac_addr = rtnl_link_get_addr (rl);
  if (!mac_addr || (nl_addr_get_family (mac_addr) != AF_LLC))
    return;

  sw = vnet_get_sw_interface (vnm, lip->lip_phy_sw_if_index);

  /* can only change address on hw interface */
  if (sw->sw_if_index != sw->sup_sw_if_index)
    return;

  hw = vnet_get_sup_hw_interface (vnm, lip->lip_phy_sw_if_index);

  /* vnet_hw_interface_change_mac_address() copies a six byte address:
   * require the netlink address and the hardware address to be exactly
   * that long before the compare and the copy. */
  if ((nl_addr_get_len (mac_addr) != sizeof (mac_address_t)) ||
      (vec_len (hw->hw_address) != sizeof (mac_address_t)))
    return;

  mac_addr_bytes = nl_addr_get_binary_addr (mac_addr);
  if (clib_memcmp (mac_addr_bytes, hw->hw_address, nl_addr_get_len (mac_addr)))
    vnet_hw_interface_change_mac_address (vnm, hw->hw_if_index,
					  mac_addr_bytes);

  /* mcast adjacencies need to be updated */
  vnet_hw_interface_walk_sw (vnm, hw->hw_if_index,
			     lcp_router_link_addr_adj_upd_cb, NULL);
}

static void lcp_router_table_flush (lcp_router_table_t *nlt,
				    u32 *sw_if_index_to_bool,
				    fib_source_t source);

static void
lcp_router_link_add (struct rtnl_link *rl, void *ctx)
{
  index_t lipi;
  int up;
  vnet_main_t *vnm = vnet_get_main ();

  lipi = lcp_itf_pair_find_by_vif (rtnl_link_get_ifindex (rl));
  up = IFF_UP & rtnl_link_get_flags (rl);

  if (INDEX_INVALID != lipi)
    {
      lcp_itf_pair_t *lip;
      u32 sw_if_flags;
      u32 sw_if_up;

      lip = lcp_itf_pair_get (lipi);
      if (NULL == vnet_get_sw_interface_or_null (vnm, lip->lip_phy_sw_if_index))
	return;

      if (lcp_router_lip_ts_check ((nl_msg_info_t *) ctx, lip))
	return;

      sw_if_flags =
	vnet_sw_interface_get_flags (vnm, lip->lip_phy_sw_if_index);
      sw_if_up = (sw_if_flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP);

      if (!sw_if_up && up)
	{
	  vnet_sw_interface_admin_up (vnet_get_main (),
				      lip->lip_phy_sw_if_index);
	}
      else if (sw_if_up && !up)
	{
	  vnet_sw_interface_admin_down (vnet_get_main (),
					lip->lip_phy_sw_if_index);

	  /* When an interface is brought down administratively, the kernel
	   * removes routes which resolve through that interface. For IPv4
	   * routes, the kernel will not send any explicit RTM_DELROUTE
	   * messages about removing them. In order to synchronize with the
	   * kernel, affected IPv4 routes need to be manually removed from the
	   * FIB. The behavior is different for IPv6 routes. Explicit
	   * RTM_DELROUTE messages are sent about IPv6 routes being removed.
	   */
	  u32 fib_index;
	  lcp_router_table_t *nlt;

	  fib_index = fib_table_get_index_for_sw_if_index (
	    FIB_PROTOCOL_IP4, lip->lip_phy_sw_if_index);

	  pool_foreach (nlt, lcp_router_table_pool)
	    {
	      if (fib_index == nlt->nlt_fib_index &&
		  FIB_PROTOCOL_IP4 == nlt->nlt_proto)
		{
		  u32 *sw_if_index_to_bool = NULL;

		  vec_validate_init_empty (sw_if_index_to_bool,
					   lip->lip_phy_sw_if_index, false);
		  sw_if_index_to_bool[lip->lip_phy_sw_if_index] = true;

		  lcp_router_table_flush (nlt, sw_if_index_to_bool,
					  lcp_rt_fib_src);
		  lcp_router_table_flush (nlt, sw_if_index_to_bool,
					  lcp_rt_fib_src_dynamic);

		  vec_free (sw_if_index_to_bool);
		  break;
		}
	    }
	}

      LCP_ROUTER_DBG ("link: %s (%d) -> %U/%U %s", rtnl_link_get_name (rl),
		      rtnl_link_get_ifindex (rl), format_vnet_sw_if_index_name,
		      vnm, lip->lip_phy_sw_if_index,
		      format_vnet_sw_if_index_name, vnm,
		      lip->lip_host_sw_if_index, (up ? "up" : "down"));

      lcp_router_link_mtu (rl, lip->lip_phy_sw_if_index);
      lcp_router_link_addr (rl, lip);
    }
  else if (lcp_auto_subint () && rtnl_link_is_vlan (rl))
    {
      /* Find the pair based on the parent VIF */
      lipi = lcp_itf_pair_find_by_vif (rtnl_link_get_link (rl));

      if (INDEX_INVALID != lipi)
	{
	  u32 sub_phy_sw_if_index, sub_host_sw_if_index;
	  const lcp_itf_pair_t *lip;
	  int vlan;
	  u8 *ns = 0; /* FIXME */

	  lip = lcp_itf_pair_get (lipi);

	  vlan = rtnl_link_vlan_get_id (rl);

	  /* create the vlan interface on the parent phy */
	  if (vnet_create_sub_interface (lip->lip_phy_sw_if_index, vlan, 18, 0,
					 vlan, &sub_phy_sw_if_index))
	    {
	      LCP_ROUTER_INFO ("failed create phy vlan: %s on %U",
			       rtnl_link_get_name (rl),
			       format_vnet_sw_if_index_name, vnet_get_main (),
			       lip->lip_phy_sw_if_index);
	      return;
	    }

	  /* pool could grow during the previous operation */
	  lip = lcp_itf_pair_get (lipi);

	  /* create the vlan interface on the parent host */
	  if (vnet_create_sub_interface (lip->lip_host_sw_if_index, vlan, 18,
					 0, vlan, &sub_host_sw_if_index))
	    {
	      LCP_ROUTER_INFO ("failed create vlan: %s on %U",
			       rtnl_link_get_name (rl),
			       format_vnet_sw_if_index_name, vnet_get_main (),
			       lip->lip_host_sw_if_index);
	      return;
	    }

	  char *if_name;
	  u8 *if_namev = 0;

	  LCP_ROUTER_INFO (
	    "create vlan: %s -> (%U, %U) : (%U, %U)", rtnl_link_get_name (rl),
	    format_vnet_sw_if_index_name, vnet_get_main (),
	    lip->lip_phy_sw_if_index, format_vnet_sw_if_index_name,
	    vnet_get_main (), sub_phy_sw_if_index,
	    format_vnet_sw_if_index_name, vnet_get_main (),
	    lip->lip_host_sw_if_index, format_vnet_sw_if_index_name,
	    vnet_get_main (), sub_host_sw_if_index);

	  if ((if_name = rtnl_link_get_name (rl)) != NULL)
	    vec_validate_init_c_string (if_namev, if_name,
					strnlen (if_name, IFNAMSIZ));
	  lcp_itf_pair_add (sub_host_sw_if_index, sub_phy_sw_if_index,
			    if_namev, rtnl_link_get_ifindex (rl),
			    lip->lip_host_type, ns);
	  if (up)
	    vnet_sw_interface_admin_up (vnet_get_main (), sub_phy_sw_if_index);
	  vnet_sw_interface_admin_up (vnet_get_main (), sub_host_sw_if_index);

	  vec_free (if_namev);
	}
      else
	{
	  LCP_ROUTER_INFO ("ignore parent-link add: %s - %s",
			   rtnl_link_get_type (rl), rtnl_link_get_name (rl));
	}
    }
  else
    LCP_ROUTER_INFO ("ignore link add: %s - %s", rtnl_link_get_type (rl),
		     rtnl_link_get_name (rl));
}

static void
lcp_router_link_sync_begin (void)
{
  LCP_ROUTER_INFO ("Begin synchronization of interface configurations");
}

static void
lcp_router_link_sync_end (void)
{
  LCP_ROUTER_INFO ("End synchronization of interface configurations");
}

static clib_error_t *
lcp_router_link_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi;
  index_t lipi;

  hi = vnet_get_hw_interface_or_null (vnm, hw_if_index);
  if (!hi)
    return 0;

  lipi = lcp_itf_pair_find_by_phy (hi->sw_if_index);
  if (lipi == INDEX_INVALID)
    return 0;

  /* When the link goes down on an interface, the kernel processes routes which
   * resolve through that interface depending on how they were created:
   *   - Legacy Route API: the kernel retains the routes and marks them as
   *     "linkdown";
   *   - Nexthop API: the kernel removes the next-hop objects and the routes
   *     which reference them.
   *
   * For IPv4 routes created with Nexthop API, the kernel will not send any
   * explicit RTM_DELROUTE messages about removing them. In order to
   * synchronize with the kernel, affected routes need to be manually removed
   * from the FIB.
   *
   * The behavior is different for IPv6 routes created with Nexthop API. The
   * kernel will send explicit RTM_DELROUTE messages about IPv6 routes being
   * removed.
   */
  if (!(flags & VNET_HW_INTERFACE_FLAG_LINK_UP) &&
      (lcp_get_del_static_on_link_down () ||
       lcp_get_del_dynamic_on_link_down ()))
    {
      u32 fib_index;
      u32 **fib_index_to_sw_if_index_to_bool = NULL;
      u32 id, sw_if_index;
      lcp_router_table_t *nlt;

      fib_index = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						       hi->sw_if_index);

      vec_validate_init_empty (fib_index_to_sw_if_index_to_bool, fib_index,
			       NULL);
      vec_validate_init_empty (fib_index_to_sw_if_index_to_bool[fib_index],
			       hi->sw_if_index, false);
      fib_index_to_sw_if_index_to_bool[fib_index][hi->sw_if_index] = true;

      /* clang-format off */
      hash_foreach (id, sw_if_index, hi->sub_interface_sw_if_index_by_id,
      ({
	fib_index = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
							 sw_if_index);
	vec_validate_init_empty (fib_index_to_sw_if_index_to_bool, fib_index,
				 NULL);
	vec_validate_init_empty (fib_index_to_sw_if_index_to_bool[fib_index],
				 sw_if_index, false);
	fib_index_to_sw_if_index_to_bool[fib_index][sw_if_index] = true;
      }));
      /* clang-format on */

      vec_foreach_index (fib_index, fib_index_to_sw_if_index_to_bool)
	{
	  u32 *sw_if_index_to_bool;

	  sw_if_index_to_bool = fib_index_to_sw_if_index_to_bool[fib_index];
	  if (NULL == sw_if_index_to_bool)
	    continue;

	  pool_foreach (nlt, lcp_router_table_pool)
	    {
	      if (fib_index == nlt->nlt_fib_index &&
		  FIB_PROTOCOL_IP4 == nlt->nlt_proto)
		{
		  if (lcp_get_del_static_on_link_down ())
		    lcp_router_table_flush (nlt, sw_if_index_to_bool,
					    lcp_rt_fib_src);
		  if (lcp_get_del_dynamic_on_link_down ())
		    lcp_router_table_flush (nlt, sw_if_index_to_bool,
					    lcp_rt_fib_src_dynamic);
		  break;
		}
	    }

	  vec_free (sw_if_index_to_bool);
	}

      vec_free (fib_index_to_sw_if_index_to_bool);
    }

  return 0;
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION (lcp_router_link_up_down);

static fib_protocol_t
lcp_router_proto_k2f (uint32_t k)
{
  switch (k)
    {
    case AF_INET6:
      return FIB_PROTOCOL_IP6;
    case AF_INET:
      return FIB_PROTOCOL_IP4;
    case AF_MPLS:
      return FIB_PROTOCOL_MPLS;
    /* A multicast route names a routing family of its own,
     * RTNL_FAMILY_IPMR for IPv4 and RTNL_FAMILY_IP6MR for IPv6. It is the
     * family the kernel reports such a route under, and the one its group
     * and source addresses are built in. */
    case RTNL_FAMILY_IPMR:
      return FIB_PROTOCOL_IP4;
    case RTNL_FAMILY_IP6MR:
      return FIB_PROTOCOL_IP6;
    default:
      /* Not a family this plugin can translate. Return the sentinel instead
       * of aborting on a message the kernel can send; the callers either gate
       * on the family or reject FIB_PROTOCOL_NONE. */
      return FIB_PROTOCOL_NONE;
    }
}

static int
lcp_router_mk_addr (const struct nl_addr *rna, ip_address_t *ia)
{
  uint32_t family = nl_addr_get_family (rna);
  fib_protocol_t fproto;

  ip_address_reset (ia);

  /* A neighbor or address message can carry an address that has no IP
   * meaning, AF_MPLS in particular. Reject the entry instead of aborting on
   * the assert that used to sit here. */
  if (AF_INET != family && AF_INET6 != family)
    {
      LCP_ROUTER_ERROR ("ignore address of family %u", family);
      return -1;
    }

  /*
   * ip_address_set() copies the whole family-sized struct out of the netlink
   * buffer, whose length is whatever the message carried. Reject an oversized
   * attribute instead of reading past it.
   */
  if (nl_addr_get_len (rna) > ip_version_to_size (AF_INET == family ? AF_IP4 : AF_IP6))
    {
      LCP_ROUTER_ERROR ("ignore address with a %u byte attribute", nl_addr_get_len (rna));
      return -1;
    }

  fproto = lcp_router_proto_k2f (family);

  ip_address_set (ia, nl_addr_get_binary_addr (rna), FIB_PROTOCOL_IP4 == fproto ? AF_IP4 : AF_IP6);

  return 0;
}

/*
 * Convert a libnl address into an ip46_address_t and report its family.
 * Returns 0 on success and -1 when the address has no IP meaning or its
 * netlink attribute is longer than the destination field. The callers reject
 * the whole record rather than continuing with a reset address that would be
 * read as 0.0.0.0 / ::.
 */
static int
lcp_router_mk_addr46 (const struct nl_addr *rna, ip46_address_t *ia, fib_protocol_t *out_fproto)
{
  uint32_t family = nl_addr_get_family (rna);
  fib_protocol_t fproto;
  unsigned int alen;

  /* Same gate as lcp_router_mk_addr(): a family whose address is not an IP
   * address has no ip46_address_t representation, so the callers drop the
   * path rather than copy a foreign buffer. AF_MPLS is one such family: it
   * translates to a protocol, but its bytes are a label stack. The
   * multicast families carry an IPv4 or an IPv6 address and pass. */
  fproto = lcp_router_proto_k2f (family);
  if (FIB_PROTOCOL_IP4 != fproto && FIB_PROTOCOL_IP6 != fproto)
    {
      LCP_ROUTER_ERROR ("ignore address of family %u", family);
      return -1;
    }

  ip46_address_reset (ia);
  alen = nl_addr_get_len (rna);
  if (FIB_PROTOCOL_IP4 == fproto)
    {
      if (PREDICT_FALSE (alen > sizeof (ia->ip4)))
	return -1;
      memcpy (&ia->ip4, nl_addr_get_binary_addr (rna), alen);
    }
  else
    {
      if (PREDICT_FALSE (alen > sizeof (ia->ip6)))
	return -1;
      memcpy (&ia->ip6, nl_addr_get_binary_addr (rna), alen);
    }

  *out_fproto = fproto;
  return 0;
}

static u32
lcp_router_count_interface_addresses (u32 sw_if_index, u8 address_family)
{
  ip_lookup_main_t *lm = NULL;
  ip_interface_address_t *ia = NULL;
  u32 count = 0;

  if (address_family == AF_IP4)
    lm = &ip4_main.lookup_main;
  else if (address_family == AF_IP6)
    lm = &ip6_main.lookup_main;
  else
    return 0;

  foreach_ip_interface_address (lm, ia, sw_if_index, 1 /* honor unnumbered */,
				({
				  (void) ia;
				  count++;
				}));

  return count;
}

static void
lcp_router_link_addr_add_del (struct rtnl_addr *rla, int is_del)
{
  u32 sw_if_index;

  sw_if_index = lcp_router_intf_h2p (rtnl_addr_get_ifindex (rla));

  if (~0 != sw_if_index)
    {
      ip_address_t nh;

      if (lcp_router_mk_addr (rtnl_addr_get_local (rla), &nh))
	return;

      if (AF_IP4 == ip_addr_version (&nh))
	{
	  ip4_add_del_interface_address (
	    vlib_get_main (), sw_if_index, &ip_addr_v4 (&nh),
	    rtnl_addr_get_prefixlen (rla), is_del);
	  if (!is_del ||
	      !lcp_router_count_interface_addresses (sw_if_index, AF_IP4))
	    lcp_router_ip4_mroutes_add_del (sw_if_index, !is_del);
	}
      else if (AF_IP6 == ip_addr_version (&nh))
	{
	  if (ip6_address_is_link_local_unicast (&ip_addr_v6 (&nh)))
	    if (is_del)
	      ip6_link_disable (sw_if_index);
	    else
	      {
		ip6_link_enable (sw_if_index, NULL);
		ip6_link_set_local_address (sw_if_index, &ip_addr_v6 (&nh));
	      }
	  else
	    ip6_add_del_interface_address (
	      vlib_get_main (), sw_if_index, &ip_addr_v6 (&nh),
	      rtnl_addr_get_prefixlen (rla), is_del);
	  if (!is_del ||
	      !lcp_router_count_interface_addresses (sw_if_index, AF_IP6))
	    lcp_router_ip6_mroutes_add_del (sw_if_index, !is_del);
	}

      LCP_ROUTER_DBG ("link-addr: %U %U/%d", format_vnet_sw_if_index_name,
		      vnet_get_main (), sw_if_index, format_ip_address, &nh,
		      rtnl_addr_get_prefixlen (rla));
    }
}

static void
lcp_router_link_addr_del (struct rtnl_addr *la)
{
  lcp_router_link_addr_add_del (la, 1);
}

static void
lcp_router_link_addr_add (struct rtnl_addr *la)
{
  lcp_router_link_addr_add_del (la, 0);
}

static walk_rc_t
lcp_router_address_mark (index_t index, void *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw;

  lcp_itf_pair_t *lip = lcp_itf_pair_get (index);
  if (!lip)
    return WALK_CONTINUE;

  sw = vnet_get_sw_interface_or_null (vnm, lip->lip_phy_sw_if_index);
  if (NULL == sw)
    return WALK_CONTINUE;

  ip_interface_address_mark_one_interface (vnm, sw, 0);

  return WALK_CONTINUE;
}

/*
 * Clear the stale flag on the pool element that a successful delete left
 * behind. The delete frees the slot when the address is the only owner of its
 * prefix, and then one element of the same interface holds the prefix, so the
 * element is looked up again by its fib index, address and length and the flag
 * is cleared only when that element belongs to the swept interface and still
 * carries the address key recorded before the delete.
 *
 * A successful delete removes the element and its key, so the lookup normally
 * finds nothing and this returns without touching anything. The two tests
 * guard the remaining case, a slot reused before the lookup: a reused element
 * is added with its flags zeroed and belongs to the other interface, so
 * clearing its flag would be harmless and the interface test excludes it
 * anyway. A key offset is handed out again after a free, so the key alone
 * would not exclude it; it is the interface that does that.
 */
static void
lcp_router_address_sweep_clear (ip_lookup_main_t *lm, void *addr_fib, u32 address_length,
				u32 sw_if_index, u32 deleted_key)
{
  u32 pool_index;
  ip_interface_address_t *ia;

  pool_index = ip_interface_address_find (lm, addr_fib, address_length);
  if (~0 == pool_index)
    return;

  ia = pool_elt_at_index (lm->if_address_pool, pool_index);
  if (ia->sw_if_index != sw_if_index || ia->address_key != deleted_key)
    return;

  ia->flags &= ~IP_INTERFACE_ADDRESS_FLAG_STALE;
}

static void
lcp_router_address_sweep (u32 sw_if_index, u8 is_ip4)
{
  ip_lookup_main_t *lm = is_ip4 ? &ip4_main.lookup_main : &ip6_main.lookup_main;
  ip4_address_t *ip4_addrs = 0;
  ip6_address_t *ip6_addrs = 0;
  u32 *masks = 0;
  u32 *keys = 0;
  ip_interface_address_t *ia = 0;
  int i;

  foreach_ip_interface_address (lm, ia, sw_if_index, 1 /* honor unnumbered */, ({
				  if (ia->flags & IP_INTERFACE_ADDRESS_FLAG_STALE)
				    {
				      void *addr = ip_interface_address_get_address (lm, ia);

				      if (is_ip4)
					vec_add1 (ip4_addrs, (*(ip4_address_t *) addr));
				      else
					vec_add1 (ip6_addrs, (*(ip6_address_t *) addr));
				      vec_add1 (masks, ia->address_length);
				      vec_add1 (keys, ia->address_key);
				    }
				}));

  for (i = 0; i < vec_len (masks); i++)
    {
      clib_error_t *error;

      if (is_ip4)
	{
	  ip4_address_fib_t af;

	  ip4_addr_fib_init (&af, &ip4_addrs[i],
			     vec_elt (ip4_main.fib_index_by_sw_if_index, sw_if_index));
	  error = ip4_add_del_interface_address (vlib_get_main (), sw_if_index, &ip4_addrs[i],
						 masks[i], 1 /* is_del */);
	  if (!error)
	    lcp_router_address_sweep_clear (lm, &af, masks[i], sw_if_index, keys[i]);
	}
      else
	{
	  ip6_address_fib_t af;

	  ip6_addr_fib_init (&af, &ip6_addrs[i],
			     vec_elt (ip6_main.fib_index_by_sw_if_index, sw_if_index));
	  error = ip6_add_del_interface_address (vlib_get_main (), sw_if_index, &ip6_addrs[i],
						 masks[i], 1 /* is_del */);
	  if (!error)
	    lcp_router_address_sweep_clear (lm, &af, masks[i], sw_if_index, keys[i]);
	}

      if (error)
	{
	  LCP_ROUTER_ERROR ("address sweep: %U failed: %U", format_vnet_sw_if_index_name,
			    vnet_get_main (), sw_if_index, format_clib_error, error);
	  clib_error_free (error);
	}
    }

  vec_free (ip4_addrs);
  vec_free (ip6_addrs);
  vec_free (masks);
  vec_free (keys);
}

static walk_rc_t
lcp_router_address_sweep_pair (index_t index, void *ctx)
{
  lcp_itf_pair_t *lip = lcp_itf_pair_get (index);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw;
  ip_address_family_t af;

  if (!lip)
    return WALK_CONTINUE;

  sw = vnet_get_sw_interface_or_null (vnm, lip->lip_phy_sw_if_index);
  if (NULL == sw)
    return WALK_CONTINUE;

  FOR_EACH_IP_ADDRESS_FAMILY (af)
  lcp_router_address_sweep (sw->sw_if_index, AF_IP4 == af);

  return WALK_CONTINUE;
}

static void
lcp_router_link_addr_sync_begin (void)
{
  lcp_itf_pair_walk (lcp_router_address_mark, 0);

  LCP_ROUTER_INFO ("Begin synchronization of interface addresses");
}

/*
 * Sweep only the interfaces the begin pass marked. ip_interface_address_sweep()
 * visits every sw interface, and the stale flag is shared with the
 * sw_interface_address_replace API, so sweeping every interface would delete
 * addresses a replace pass marked but never re-added.
 */
static void
lcp_router_link_addr_sync_end (void)
{
  lcp_itf_pair_walk (lcp_router_address_sweep_pair, 0);

  LCP_ROUTER_INFO ("End synchronization of interface addresses");
}

static void
lcp_router_mk_mac_addr (const struct nl_addr *rna, mac_address_t *mac)
{
  mac_address_from_bytes (mac, nl_addr_get_binary_addr (rna));
}

static void
lcp_router_neigh_del (struct rtnl_neigh *rn)
{
  u32 sw_if_index;

  sw_if_index = lcp_router_intf_h2p (rtnl_neigh_get_ifindex (rn));

  if (~0 != sw_if_index)
    {
      ip_address_t nh;
      int rv;
      struct nl_addr *rna;

      if ((rna = rtnl_neigh_get_dst (rn)) == NULL)
	return;
      if (lcp_router_mk_addr (rna, &nh))
	return;

      if (ip46_address_is_multicast (&ip_addr_46 (&nh)))
	{
	  LCP_ROUTER_DBG ("ignore neighbor del: %U %U", format_ip_address, &nh,
			  format_vnet_sw_if_index_name, vnet_get_main (),
			  sw_if_index);
	  return;
	}

      rv = ip_neighbor_del (&nh, sw_if_index);

      /* ip_neighbor_del() only ever fails with
       * VNET_API_ERROR_NO_SUCH_ENTRY, so a plain if (rv) covers every
       * error case - log at debug level to tolerate neighbors that are
       * already gone. */
      if (rv)
	{
	  LCP_ROUTER_DBG ("ignore neighbor del missing: %U %U", format_ip_address, &nh,
			  format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index);
	}
      else
	{
	  /*
	   * The entry is gone, so any ownership record for it is stale. It is
	   * dropped here rather than left behind: the address can be learned
	   * again, and a left-over record would make the plugin treat the new
	   * entry as its own to correct.
	   */
	  lcp_router_neigh_static_forget (&nh, sw_if_index);

	  LCP_ROUTER_DBG ("neighbor del: %U %U", format_ip_address, &nh,
			  format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index);
	}
    }
  else
    LCP_ROUTER_INFO ("ignore neighbour del on: %d",
		     rtnl_neigh_get_ifindex (rn));
}

static void
lcp_router_neigh_add (struct rtnl_neigh *rn)
{
  u32 sw_if_index;

  sw_if_index = lcp_router_intf_h2p (rtnl_neigh_get_ifindex (rn));

  if (~0 != sw_if_index)
    {
      struct nl_addr *ll;
      ip_address_t nh;
      int state;
      struct nl_addr *rna;

      if ((rna = rtnl_neigh_get_dst (rn)) == NULL)
	return;
      if (lcp_router_mk_addr (rna, &nh))
	return;

      if (ip46_address_is_multicast (&ip_addr_46 (&nh)))
	{
	  LCP_ROUTER_DBG ("ignore neighbor add: %U %U", format_ip_address, &nh,
			  format_vnet_sw_if_index_name, vnet_get_main (),
			  sw_if_index);
	  return;
	}

      /*
       * A kernel neighbour is a link layer address of the interface's link.
       * An interface without an ethernet header, such as an L3 tunnel, has no
       * such link, and the neighbour's rewrite would replace the tunnel's own
       * outer header.
       */
      if (!ip_neighbor_sw_if_index_has_ethernet_rewrite (sw_if_index))
	{
	  LCP_ROUTER_DBG ("ignore non-ethernet neighbor add: %U %U", format_ip_address, &nh,
			  format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index);
	  return;
	}

      ll = rtnl_neigh_get_lladdr (rn);
      state = rtnl_neigh_get_state (rn);

      /*
       * A record the kernel is revalidating says the link layer address was
       * usable once, not that it is now. ip_neighbor_add() cannot carry that
       * distinction: ip_neighbor_refresh() calls ip_neighbor_touch(), which
       * clears IP_NEIGHBOR_FLAG_STALE and resets the probe count, so the
       * entry would arrive in VPP as one just confirmed. The record is
       * therefore not synced, and the next confirmed record for the address,
       * if one comes, is what updates VPP.
       *
       * A synchronization marks every dynamic neighbour before its dump and
       * sweeps the ones still marked after it, and the mark clears only
       * through the refresh the skip above does without. A record the kernel
       * still holds would therefore be deleted at the end of the
       * synchronization it was reported in, so the mark is cleared here when
       * the entry exists and the sweep can reach it. Clearing the flag is not
       * the refresh: the probe count and the update time are left as they
       * are, and the entry stays one the kernel has not confirmed.
       *
       * Only a record that arrives outside a synchronization is counted: a
       * dump repeats the state of every revalidating neighbour it holds, and
       * counting those would add one skip per resynchronization to a signal
       * that describes what the kernel reported.
       */
      if (ll && (state & LCP_ROUTER_NUD_REVALIDATING))
	{
	  if (lcp_router_neigh_sync_active && lcp_router_neigh_sync_marked)
	    {
	      ip_neighbor_t *ipn = lcp_router_neigh_find (&nh, sw_if_index);

	      if (ipn && (ipn->ipn_flags & IP_NEIGHBOR_FLAG_DYNAMIC))
		ipn->ipn_flags &= ~IP_NEIGHBOR_FLAG_STALE;
	    }
	  else if (!lcp_router_neigh_sync_active)
	    {
	      lcp_router_neigh_stale_skipped++;
	      lcp_router_neigh_stat_publish (lcp_router_neigh_stale_skipped_stat,
					     lcp_router_neigh_stale_skipped);
	    }

	  LCP_ROUTER_DBG ("skip revalidating neighbor: %U %U state 0x%x", format_ip_address, &nh,
			  format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index, state);
	  return;
	}

      if (ll && (state & LCP_ROUTER_NUD_CONFIRMED))
	{
	  mac_address_t mac;
	  ip_neighbor_flags_t flags;
	  int rv;

	  if (nl_addr_get_len (ll) != sizeof (mac_address_t))
	    {
	      LCP_ROUTER_ERROR ("ignore neighbor with a %u byte lladdr",
				nl_addr_get_len (ll));
	      return;
	    }

	  lcp_router_mk_mac_addr (ll, &mac);

	  if (state & (NUD_NOARP | NUD_PERMANENT))
	    flags = IP_NEIGHBOR_FLAG_STATIC;
	  else
	    flags = IP_NEIGHBOR_FLAG_DYNAMIC;

	  rv = ip_neighbor_add (&nh, &mac, sw_if_index, flags, NULL);

	  /*
	   * A static entry is only changed by its owner. The kernel owns the
	   * static neighbours the plugin installed from its records, and it can
	   * change one: a permanent record can become one the kernel learned,
	   * with another device's link layer address, which arrives here as a
	   * dynamic record. ip_neighbor_add() refuses that, so the correction is
	   * the delete and add an operator would do by hand, made on the entry
	   * the plugin itself wrote.
	   *
	   * The entry must still carry the link layer address the plugin wrote,
	   * or an operator has reprogrammed it since and it is that owner's to
	   * change. An entry with no ownership record was never installed by the
	   * plugin, and is left untouched as well.
	   */
	  if (VNET_API_ERROR_ENTRY_ALREADY_EXISTS == rv &&
	      lcp_router_neigh_static_owned (&nh, sw_if_index))
	    {
	      ip_neighbor_del (&nh, sw_if_index);
	      rv = ip_neighbor_add (&nh, &mac, sw_if_index, flags, NULL);

	      if (!rv)
		{
		  lcp_router_neigh_replaced++;
		  lcp_router_neigh_stat_publish (lcp_router_neigh_replaced_stat,
						 lcp_router_neigh_replaced);
		}
	    }

	  if (rv)
	    {
	      lcp_router_neigh_refused++;
	      lcp_router_neigh_stat_publish (lcp_router_neigh_refused_stat,
					     lcp_router_neigh_refused);

	      LCP_ROUTER_ERROR ("Failed to create neighbor: %U %U", format_ip_address, &nh,
				format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index);
	    }
	  else
	    {
	      lcp_router_neigh_static_reconcile (&nh, sw_if_index, flags);

	      LCP_ROUTER_DBG ("neighbor add: %U %U", format_ip_address, &nh,
			      format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index);
	    }
	}
      else
	{
	  /*
	   * The kernel reports a failed neighbour as RTM_NEWNEIGH with
	   * NUD_FAILED and no state that makes it valid, so it reaches the
	   * delete below like an aged-out entry. The delete is the same, but
	   * an explicit failure is the record of a host that stopped
	   * answering, which an operator chasing a stale link layer address
	   * has no other way to see. Report it outside a synchronization only:
	   * a dump repeats the state of every failed neighbour on each
	   * resynchronization.
	   */
	  if (state & NUD_FAILED)
	    {
	      mac_address_t mac;
	      u8 *mac_str = NULL;

	      ll = rtnl_neigh_get_lladdr (rn);
	      if (ll && nl_addr_get_len (ll) == sizeof (mac_address_t))
		{
		  lcp_router_mk_mac_addr (ll, &mac);
		  mac_str = format (NULL, "%U", format_mac_address_t, &mac);
		}

	      if (lcp_router_neigh_sync_active)
		{
		  LCP_ROUTER_DBG ("neighbor failed: %U %U %v", format_ip_address, &nh,
				  format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index,
				  mac_str);
		}
	      else
		{
		  LCP_ROUTER_WARN ("neighbor failed: %U %U %v", format_ip_address, &nh,
				   format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index,
				   mac_str);
		}

	      vec_free (mac_str);
	    }

	  /* It's a delete */
	  lcp_router_neigh_del (rn);
	}
    }
  else
    LCP_ROUTER_INFO ("ignore neighbour add on: %d", rtnl_neigh_get_ifindex (rn));
}

/*
 * A synchronization marks every dynamic neighbour on a paired interface and,
 * at its end, sweeps the ones the kernel did not report. It does this only
 * while del-dynamic-on-link-down is on; with the flag off VPP owns those
 * neighbours and the kernel only mirrors them. The dump is then not an
 * authoritative view of them, because the kernel drops an entry from its
 * neighbour table once a probe goes unanswered, so sweeping on the dump alone
 * would delete the neighbour together with every flow that resolves through
 * it. They are removed by the explicit RTM_DELNEIGH records instead.
 *
 * Static neighbours take no part in the sweep. ip_neighbor_sweep() destroys
 * every stale entry whatever its kind, so a static entry marked here could
 * only be cleared by the same sweep that removes dynamic ones, and marking it
 * without sweeping would leave STALE set for the next sweep of the neighbour
 * replace API to destroy. A synchronization therefore leaves static
 * neighbours alone; del-static-on-link-down governs routes only and does not
 * reach them.
 */
static walk_rc_t
lcp_router_neigh_mark_dynamic (index_t ipni, void *ctx)
{
  ip_neighbor_t *ipn = ip_neighbor_get (ipni);

  if (ipn->ipn_flags & IP_NEIGHBOR_FLAG_DYNAMIC)
    ipn->ipn_flags |= IP_NEIGHBOR_FLAG_STALE;

  return WALK_CONTINUE;
}

static walk_rc_t
lcp_router_neighbor_mark (index_t index, void *ctx)
{
  lcp_itf_pair_t *lip = lcp_itf_pair_get (index);
  if (!lip)
    return WALK_CONTINUE;

  ip_neighbor_walk (AF_IP4, lip->lip_phy_sw_if_index, lcp_router_neigh_mark_dynamic, 0);
  ip_neighbor_walk (AF_IP6, lip->lip_phy_sw_if_index, lcp_router_neigh_mark_dynamic, 0);

  return WALK_CONTINUE;
}

static void
lcp_router_neigh_sync_begin (void)
{
  lcp_router_neigh_sync_active = 1;

  if (lcp_get_del_dynamic_on_link_down ())
    {
      lcp_itf_pair_walk (lcp_router_neighbor_mark, 0);
      lcp_router_neigh_sync_marked = 1;
    }

  LCP_ROUTER_INFO ("Begin synchronization of neighbors");
}

static void
lcp_router_neigh_sync_sweep (void)
{
  ip_neighbor_sweep (AF_IP4);
  ip_neighbor_sweep (AF_IP6);
}

static void
lcp_router_neigh_sync_end (void)
{
  lcp_router_neigh_sync_active = 0;

  if (lcp_get_del_dynamic_on_link_down ())
    lcp_router_neigh_sync_sweep ();

  lcp_router_neigh_sync_marked = 0;

  LCP_ROUTER_INFO ("End synchronization of neighbors");
}

/*
 * Steps of a neighbor synchronization, driven by the test plugin so a test
 * does not depend on whether a real dump happens to deliver a record before
 * the sweep runs. Marking regardless of the ownership flag is what the begin
 * step used to do, which is the condition a regression test reproduces.
 */
void
lcp_router_neigh_test_mark_all (void)
{
  lcp_itf_pair_walk (lcp_router_neighbor_mark, 0);
}

void
lcp_router_neigh_test_end (void)
{
  lcp_router_neigh_sync_end ();
}

/*
 * The neighbour synchronization's outcome totals. The stat segment gauges
 * under /lcp/neighbor/ carry the same numbers; this command prints them
 * without touching a counter set, an interface, or a graph node, so it is
 * safe to run on a box where walking counters is not.
 */
static clib_error_t *
lcp_router_show_neighbours_command_fn (vlib_main_t *vm, unformat_input_t *input,
				       vlib_cli_command_t *cmd)
{
  vlib_cli_output (vm, "Refused: %lu", lcp_router_neigh_refused);
  vlib_cli_output (vm, "Replaced: %lu", lcp_router_neigh_replaced);
  vlib_cli_output (vm, "Stale skipped: %lu", lcp_router_neigh_stale_skipped);

  return 0;
}

VLIB_CLI_COMMAND (lcp_router_show_neighbours_command, static) = {
  .path = "show lcp neighbors",
  .short_help = "show lcp neighbors",
  .function = lcp_router_show_neighbours_command_fn,
};

/*
 * Whether a table counts a lock of one source. A table that never took the
 * source has no slot for it, which reads as no lock.
 */
static bool
lcp_router_table_lock_held (const fib_table_t *table, fib_source_t source)
{
  return (uword) source < vec_len (table->ft_locks) && 0 != table->ft_locks[source];
}

/*
 * Whether the FIB index a record names still holds the table the record
 * locked, for a record the record itself keeps. The record holds a lock on
 * its own table, so that table is freed only after the record is gone; this
 * finds a record whose index was reused by a table it never locked, and the
 * record must then not install into, or remove from, it. The id decides it,
 * not the lock count: a table the record never locked can still count a lock
 * this source took for another record.
 *
 * A table the API made can also be deleted under the record. ip_table_delete()
 * clears the lock it took under FIB_SOURCE_API or FIB_SOURCE_CLI, so the
 * record's own lock keeps the table alive and the id still matches; only that
 * lock going away tells the record its table is gone. The record asks for it
 * only when the table counted one as the record was made, which is also what
 * keeps table 0: the API neither makes nor deletes it, so its record outlives
 * every delete and must not be read as one. A table the plugin made itself
 * holds no such lock either and stays as long as the record does.
 *
 * fib_table_find() cannot answer the question: it reads the table id hash of
 * the protocol, and ip4_fib_table_destroy() unsets an entry only for a table
 * whose id is not ~0, so table 0 keeps its stale index there.
 */
static bool
lcp_router_table_fib_owned (const lcp_router_table_t *nlt)
{
  const fib_table_t *table = fib_table_get_or_null (nlt->nlt_fib_index, nlt->nlt_proto);

  if (NULL == table || table->ft_table_id != nlt->nlt_id)
    return false;

  if (!nlt->nlt_api_owned)
    return true;

  return (lcp_router_table_lock_held (table, FIB_SOURCE_API) ||
	  lcp_router_table_lock_held (table, FIB_SOURCE_CLI));
}

static void lcp_router_table_special_punt_add_del (lcp_router_table_t *nlt, u8 is_add);
static void lcp_router_table_special_mfibs_add_del (lcp_router_table_t *nlt, u8 is_add);
static void lcp_router_table_special_routes_del (lcp_router_table_t *nlt);
static void lcp_router_table_mcast_release (lcp_router_table_t *nlt);

/*
 * Take a record out of the database after giving up everything it holds: the
 * multicast routes' references, the special routes of the table, the table
 * reference, and the FIB and MFIB locks. Nothing else names the table at this
 * point, so the FIB index the record still holds is the table it locked.
 *
 * A recorded multicast route holds one reference of the table, and that is
 * the reference this gives back for it. The record has no reference of its
 * own beyond those: a table whose record was made by an interface binding
 * and holds no route yet counts the binding's reference, which is not the
 * record's to spend here.
 */
static void
lcp_router_table_forget (lcp_router_table_t *nlt)
{
  ASSERT (nlt->nlt_refs >= vec_len (nlt->nlt_mcast_entries));

  lcp_router_table_mcast_release (nlt);
  lcp_router_table_special_routes_del (nlt);
  nlt->nlt_refs -= vec_len (nlt->nlt_mcast_entries);

  fib_table_unlock (nlt->nlt_fib_index, nlt->nlt_proto, nlt->nlt_fib_src);
  if (nlt->nlt_mfib_index != ~0)
    mfib_table_unlock (nlt->nlt_mfib_index, nlt->nlt_proto, MFIB_SOURCE_PLUGIN_LOW);

  vec_free (nlt->nlt_onlink_routes);
  hash_unset (lcp_router_table_db[nlt->nlt_proto], nlt->nlt_id);
  pool_put (lcp_router_table_pool, nlt);
}

/*
 * Look a record up, dropping it when the FIB index it names no longer holds the
 * table it locked. The record holds a lock on its own table, so that table is
 * freed only after the record is gone and this finds a record whose index was
 * reused by a table the record never locked. The record is dropped before the
 * index is read as a table.
 *
 * The record found here is the caller's, and the caller releases it, so a
 * record dropped instead comes back as absent rather than as a freed one.
 */
static lcp_router_table_t *
lcp_router_table_find (uint32_t id, fib_protocol_t fproto)
{
  lcp_router_table_t *nlt;
  uword *p;

  p = hash_get (lcp_router_table_db[fproto], id);
  if (NULL == p)
    return NULL;

  nlt = pool_elt_at_index (lcp_router_table_pool, p[0]);
  if (lcp_router_table_fib_owned (nlt))
    return nlt;

  LCP_ROUTER_INFO ("drop the record of %U table %u, whose fib index %u names another table",
		   format_fib_protocol, fproto, id, nlt->nlt_fib_index);

  lcp_router_table_forget (nlt);
  return NULL;
}

static uint32_t
lcp_router_table_k2f (uint32_t k)
{
  // the kernel's table ID 255 is the default table
  if (k == 255 || k == 254)
    return 0;
  return k;
}

/*
 * The all 1s address of an IPv4 table. Installed under the plugin's own
 * unswept source: it must survive the route sweep at the end of a
 * synchronization, and it ranks below a learned static route at the same
 * prefix but above a learned dynamic one.
 */
static void
lcp_router_table_special_punt_add_del (lcp_router_table_t *nlt, u8 is_add)
{
  if (FIB_PROTOCOL_IP4 != nlt->nlt_proto)
    return;

  if (is_add)
    fib_table_entry_special_add (nlt->nlt_fib_index, &pfx_all1s, lcp_rt_fib_src_special,
				 FIB_ENTRY_FLAG_LOCAL);
  else
    fib_table_entry_special_remove (nlt->nlt_fib_index, &pfx_all1s, lcp_rt_fib_src_special);
}

/*
 * The (*,224.0.0.0)/24 and (*,ff00::)/8 routes of the table, installed in its
 * MFIB under MFIB_SOURCE_SPECIAL rather than the plugin's own source.
 */
static void
lcp_router_table_special_mfibs_add_del (lcp_router_table_t *nlt, u8 is_add)
{
  if (nlt->nlt_mfib_index == ~0)
    return;

  if (FIB_PROTOCOL_IP4 == nlt->nlt_proto)
    {
      const fib_route_path_t path = {
	.frp_proto = DPO_PROTO_IP4,
	.frp_addr = zero_addr,
	.frp_sw_if_index = ~0,
	.frp_fib_index = ~0,
	.frp_weight = 1,
	.frp_mitf_flags = MFIB_ITF_FLAG_FORWARD,
	.frp_flags = FIB_ROUTE_PATH_LOCAL,
      };
      int ii;

      for (ii = 0; ii < ARRAY_LEN (ip4_specials); ii++)
	{
	  if (is_add)
	    mfib_table_entry_path_update (nlt->nlt_mfib_index, &ip4_specials[ii],
					  MFIB_SOURCE_SPECIAL, MFIB_ENTRY_FLAG_NONE, &path);
	  else
	    mfib_table_entry_path_remove (nlt->nlt_mfib_index, &ip4_specials[ii],
					  MFIB_SOURCE_SPECIAL, &path);
	}
    }
  else if (FIB_PROTOCOL_IP6 == nlt->nlt_proto)
    {
      const fib_route_path_t path = {
	.frp_proto = DPO_PROTO_IP6,
	.frp_addr = zero_addr,
	.frp_sw_if_index = ~0,
	.frp_fib_index = ~0,
	.frp_weight = 1,
	.frp_mitf_flags = MFIB_ITF_FLAG_FORWARD,
	.frp_flags = FIB_ROUTE_PATH_LOCAL,
      };
      int ii;

      for (ii = 0; ii < ARRAY_LEN (ip6_specials); ii++)
	{
	  if (is_add)
	    mfib_table_entry_path_update (nlt->nlt_mfib_index, &ip6_specials[ii],
					  MFIB_SOURCE_SPECIAL, MFIB_ENTRY_FLAG_NONE, &path);
	  else
	    mfib_table_entry_path_remove (nlt->nlt_mfib_index, &ip6_specials[ii],
					  MFIB_SOURCE_SPECIAL, &path);
	}
    }
}

/*
 * Both sets of special routes, for a record whose table is one the plugin
 * created and still holds.
 */
static void
lcp_router_table_add_del_special_routes (lcp_router_table_t *nlt, u8 is_add)
{
  lcp_router_table_special_punt_add_del (nlt, is_add);
  lcp_router_table_special_mfibs_add_del (nlt, is_add);
}

/*
 * Give up the special routes of a record whose table the API deleted. The
 * delete clears only its own lock, so the plugin's lock keeps the table and
 * the entries under the plugin's sources are still there; taking them back is
 * what a table the plugin gives up has to do, or the table it still holds
 * would keep the routes every new table gets.
 */
static void
lcp_router_table_special_routes_del (lcp_router_table_t *nlt)
{
  lcp_router_table_special_punt_add_del (nlt, 0);
  lcp_router_table_special_mfibs_add_del (nlt, 0);
}

/*
 * One multicast route the record holds: its paths, under the plugin's own
 * source, and its reference. A group or source pair is one MFIB entry, so the
 * paths are removed before the entry, which takes the source with it.
 */
static void
lcp_router_table_mcast_route_release (lcp_router_table_t *nlt, const mfib_prefix_t *prefix)
{
  if (FIB_NODE_INDEX_INVALID == mfib_table_lookup_exact_match (nlt->nlt_mfib_index, prefix))
    return;

  mfib_table_entry_delete (nlt->nlt_mfib_index, prefix, MFIB_SOURCE_PLUGIN_LOW);
  mfib_table_entry_paths_remove (nlt->nlt_mfib_index, prefix, MFIB_SOURCE_PLUGIN_LOW, NULL);
}

/*
 * Give up the multicast routes recorded for a table the record is being
 * forgotten for, and the lock the record holds on the MFIB it names.
 */
static void
lcp_router_table_mcast_release (lcp_router_table_t *nlt)
{
  lcp_router_mcast_entry_t *entry;

  if (nlt->nlt_mfib_index == ~0)
    return;

  vec_foreach (entry, nlt->nlt_mcast_entries)
    lcp_router_table_mcast_route_release (nlt, &entry->lcme_prefix);

  mfib_table_unlock (nlt->nlt_mfib_index, nlt->nlt_proto, MFIB_SOURCE_PLUGIN_LOW);
  nlt->nlt_mfib_index = ~0;
}

static lcp_router_table_t *
lcp_router_table_add_or_lock (uint32_t id, fib_protocol_t fproto)
{
  lcp_router_table_t *nlt;

  id = lcp_router_table_k2f (id);
  nlt = lcp_router_table_find (id, fproto);

  if (NULL == nlt)
    {
      pool_get_zero (lcp_router_table_pool, nlt);

      nlt->nlt_id = id;
      nlt->nlt_proto = fproto;

      nlt->nlt_fib_src = lcp_rt_fib_src;
      nlt->nlt_fib_index =
	fib_table_find_or_create_and_lock (nlt->nlt_proto, nlt->nlt_id, nlt->nlt_fib_src);
      nlt->nlt_mfib_index = mfib_table_find_or_create_and_lock (
	nlt->nlt_proto, nlt->nlt_id, MFIB_SOURCE_PLUGIN_LOW);

      /*
       * A table the API made counts the lock its delete then clears, and one
       * it did not make, table 0 above all, never does. The record asks about
       * that lock from here on, so the answer is taken while the table is
       * certainly the one the plugin locked.
       */
      {
	const fib_table_t *table = fib_table_get_or_null (nlt->nlt_fib_index, nlt->nlt_proto);
	nlt->nlt_api_owned = NULL != table && (lcp_router_table_lock_held (table, FIB_SOURCE_API) ||
					       lcp_router_table_lock_held (table, FIB_SOURCE_CLI));
      }

      hash_set (lcp_router_table_db[fproto], nlt->nlt_id,
		nlt - lcp_router_table_pool);

      lcp_router_table_add_del_special_routes (nlt, 1);
    }

  nlt->nlt_refs++;

  return (nlt);
}

static void
lcp_router_table_unlock (lcp_router_table_t *nlt)
{
  ASSERT (nlt->nlt_refs > 0);
  nlt->nlt_refs--;

  if (0 == nlt->nlt_refs)
    {
      lcp_router_table_add_del_special_routes (nlt, 0);

      fib_table_unlock (nlt->nlt_fib_index, nlt->nlt_proto, lcp_rt_fib_src);
      if (nlt->nlt_mfib_index != ~0)
	mfib_table_unlock (nlt->nlt_mfib_index, nlt->nlt_proto, MFIB_SOURCE_PLUGIN_LOW);

      hash_unset (lcp_router_table_db[nlt->nlt_proto], nlt->nlt_id);
      vec_free (nlt->nlt_onlink_routes);
      pool_put (lcp_router_table_pool, nlt);
    }
}

/*
 * Find the record of an attached host prefix the plugin installed for a
 * gateway on this route. Each route and gateway pair holds one record, so a
 * gateway several routes name is installed once and removed with the last one.
 */
static lcp_router_onlink_route_t *
lcp_router_table_onlink_find (lcp_router_table_t *nlt, const fib_prefix_t *route,
			      const ip46_address_t *gateway, u32 sw_if_index)
{
  lcp_router_onlink_route_t *entry;

  vec_foreach (entry, nlt->nlt_onlink_routes)
    {
      if (entry->lcor_sw_if_index != sw_if_index)
	continue;
      if (0 != ip46_address_cmp (&entry->lcor_gateway, gateway))
	continue;
      if (fib_prefix_cmp (&entry->lcor_route, route))
	continue;
      return entry;
    }

  return NULL;
}

/*
 * Whether a route other than the one being released still needs the same
 * gateway over the same interface. The attached host prefix is removed only
 * when none does.
 */
static bool
lcp_router_table_onlink_gateway_held (lcp_router_table_t *nlt,
				      const lcp_router_onlink_route_t *released,
				      const ip46_address_t *gateway, u32 sw_if_index)
{
  const lcp_router_onlink_route_t *entry;

  vec_foreach (entry, nlt->nlt_onlink_routes)
    {
      if (entry == released)
	continue;
      if (entry->lcor_sw_if_index != sw_if_index)
	continue;
      if (0 == ip46_address_cmp (&entry->lcor_gateway, gateway))
	return true;
    }

  return false;
}

/*
 * Whether a path the route still has in the FIB, under the source the route
 * came from, names the same gateway over the same interface. The attached host
 * prefix outlives the record for as long as one does: a multipath route keeps
 * the prefix its surviving paths resolve through.
 */
static bool
lcp_router_table_onlink_path_held (lcp_router_table_t *nlt, const fib_prefix_t *route,
				   fib_source_t source, const ip46_address_t *gateway,
				   u32 sw_if_index)
{
  fib_node_index_t fei;
  fib_entry_t *fib_entry;
  fib_entry_src_t *esrc;
  fib_path_encode_ctx_t ctx = {
    .rpaths = NULL,
  };
  fib_route_path_t *rpath;
  bool held = false;

  fei = fib_table_lookup_exact_match (nlt->nlt_fib_index, route);
  if (FIB_NODE_INDEX_INVALID == fei)
    return false;

  fib_entry = fib_entry_get (fei);
  esrc = fib_entry_src_find (fib_entry, source);
  if (NULL == esrc || FIB_NODE_INDEX_INVALID == esrc->fes_pl)
    return false;

  fib_path_list_walk_w_ext (esrc->fes_pl, NULL, fib_path_encode, &ctx);
  vec_foreach (rpath, ctx.rpaths)
    {
      if (rpath->frp_sw_if_index != sw_if_index)
	continue;
      if (0 == ip46_address_cmp (&rpath->frp_addr, gateway))
	{
	  held = true;
	  break;
	}
    }
  vec_free (ctx.rpaths);

  return held;
}

/*
 * Drop one record and, unless something still needs it, the attached host
 * prefix it installed. The caller decides whether the prefix outlives the
 * record: the routes that go before the FIB has the new paths consult the
 * records, the one that goes after consults the FIB.
 */
static void
lcp_router_table_onlink_remove (lcp_router_table_t *nlt, lcp_router_onlink_route_t *entry,
				const fib_prefix_t *host, fib_protocol_t proto, bool keep_host)
{
  if (!keep_host)
    fib_table_entry_path_remove (nlt->nlt_fib_index, host, lcp_rt_fib_src_onlink,
				 fib_proto_to_dpo (proto), &host->fp_addr, entry->lcor_sw_if_index,
				 ~0, 1, FIB_ROUTE_PATH_FLAG_NONE);

  vec_del1 (nlt->nlt_onlink_routes, entry - nlt->nlt_onlink_routes);
  lcp_router_table_unlock (nlt);
}

/*
 * Install, or refresh, the attached host prefix for a gateway the kernel
 * marked RTNH_F_ONLINK. The path is shaped like the adj-fib that
 * ip_neighbor_adj_fib_add() installs: attached, with the address itself as the
 * next hop, so that arp_reply() accepts the reply the gateway sends and the
 * neighbour is learned. The source is the plugin's own, which the route
 * synchronization neither marks nor sweeps.
 */
static void
lcp_router_table_onlink_add (lcp_router_table_t *nlt, const fib_prefix_t *route,
			     const ip46_address_t *gateway, u32 sw_if_index, fib_protocol_t proto)
{
  lcp_router_onlink_route_t *entry;

  if (NULL != lcp_router_table_onlink_find (nlt, route, gateway, sw_if_index))
    return;

  /*
   * One attached host prefix serves every route naming the gateway, so it is
   * installed only when no record holds it yet, and it goes when the last
   * record does.
   */
  if (!lcp_router_table_onlink_gateway_held (nlt, NULL, gateway, sw_if_index))
    {
      fib_prefix_t host = {
	.fp_proto = proto,
	.fp_len = fib_prefix_get_host_length (proto),
	.fp_addr = *gateway,
      };

      fib_table_entry_path_add (nlt->nlt_fib_index, &host, lcp_rt_fib_src_onlink,
				FIB_ENTRY_FLAG_ATTACHED, fib_proto_to_dpo (proto), &host.fp_addr,
				sw_if_index, ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
    }

  vec_add2 (nlt->nlt_onlink_routes, entry, 1);
  entry->lcor_route = *route;
  entry->lcor_gateway = *gateway;
  entry->lcor_sw_if_index = sw_if_index;
  nlt->nlt_refs++;
}

/*
 * Give up the gateways of this route that no path in the FIB resolves through
 * any more, and keep the ones it still does. The FIB is the judge, not the
 * message: the kernel keys routes by prefix alone, so a prefix can hold a
 * unicast route and a blackhole route at once, and one source can hold what
 * another of the plugin's sources does not, so both of those sources are
 * asked. Only what is left in the FIB says which gateways are still in use.
 * The record follows its paths, so the last one to go gives the attached host
 * prefix up.
 */
static void
lcp_router_table_onlink_sync_paths (lcp_router_table_t *nlt, const fib_prefix_t *route,
				    fib_protocol_t proto)
{
  u32 ii = 0;

  nlt->nlt_refs++;
  while (ii < vec_len (nlt->nlt_onlink_routes))
    {
      lcp_router_onlink_route_t *entry = vec_elt_at_index (nlt->nlt_onlink_routes, ii);

      if (fib_prefix_cmp (&entry->lcor_route, route) ||
	  lcp_router_table_onlink_path_held (nlt, route, lcp_rt_fib_src, &entry->lcor_gateway,
					     entry->lcor_sw_if_index) ||
	  lcp_router_table_onlink_path_held (nlt, route, lcp_rt_fib_src_dynamic,
					     &entry->lcor_gateway, entry->lcor_sw_if_index))
	{
	  ii++;
	  continue;
	}

      /* The record is removed in place, so the next one to look at is at the
       * same index. */
      {
	fib_prefix_t host = {
	  .fp_proto = proto,
	  .fp_len = fib_prefix_get_host_length (proto),
	  .fp_addr = entry->lcor_gateway,
	};
	lcp_router_table_onlink_remove (
	  nlt, entry, &host, proto,
	  lcp_router_table_onlink_gateway_held (nlt, entry, &entry->lcor_gateway,
						entry->lcor_sw_if_index));
      }
    }
  lcp_router_table_unlock (nlt);
}

/*
 * Give up the gateways of a route the plugin no longer holds in this table.
 * A route can go without a netlink delete: the interface going down flushes
 * its routes in the kernel without a message, and the synchronization sweeps
 * what the kernel did not replay. The record follows the route, so a route
 * that no longer sources the table gives its gateway up.
 */
static void
lcp_router_table_onlink_prune (lcp_router_table_t *nlt)
{
  u32 ii = 0;

  /* As in the release, the reference keeps the table alive while the last
   * record of the last route removes the last of them. */
  nlt->nlt_refs++;
  while (ii < vec_len (nlt->nlt_onlink_routes))
    {
      lcp_router_onlink_route_t *entry = vec_elt_at_index (nlt->nlt_onlink_routes, ii);
      fib_node_index_t fei;

      fei = fib_table_lookup_exact_match (nlt->nlt_fib_index, &entry->lcor_route);
      if ((FIB_NODE_INDEX_INVALID != fei) && (fib_entry_is_sourced (fei, lcp_rt_fib_src) ||
					      fib_entry_is_sourced (fei, lcp_rt_fib_src_dynamic)))
	{
	  ii++;
	  continue;
	}

      /* The record is removed in place, so the next one to look at is at the
       * same index. The route is gone, so only another record can still need
       * the gateway. */
      {
	fib_prefix_t host = {
	  .fp_proto = nlt->nlt_proto,
	  .fp_len = fib_prefix_get_host_length (nlt->nlt_proto),
	  .fp_addr = entry->lcor_gateway,
	};
	lcp_router_table_onlink_remove (
	  nlt, entry, &host, nlt->nlt_proto,
	  lcp_router_table_onlink_gateway_held (nlt, entry, &entry->lcor_gateway,
						entry->lcor_sw_if_index));
      }
    }
  lcp_router_table_unlock (nlt);
}

/*
 * Find the recorded entry that covers the same group, and source when the
 * prefix names one. The list holds the routes of one table only and is kept
 * small by the synchronization removing what the kernel dropped, so a scan
 * is enough.
 */
static lcp_router_mcast_entry_t *
lcp_router_table_mcast_find (lcp_router_table_t *nlt, const mfib_prefix_t *prefix)
{
  lcp_router_mcast_entry_t *entry;

  vec_foreach (entry, nlt->nlt_mcast_entries)
    {
      if (entry->lcme_prefix.fp_proto != prefix->fp_proto ||
	  entry->lcme_prefix.fp_len != prefix->fp_len)
	continue;
      if (0 != clib_memcmp (&entry->lcme_prefix.fp_grp_addr, &prefix->fp_grp_addr,
			    sizeof (prefix->fp_grp_addr)))
	continue;
      /* (*,G) stops here; (S,G) also has to name the same source */
      if (mfib_prefix_is_host (&entry->lcme_prefix) &&
	  0 != clib_memcmp (&entry->lcme_prefix.fp_src_addr, &prefix->fp_src_addr,
			    sizeof (prefix->fp_src_addr)))
	continue;
      return entry;
    }

  return NULL;
}

/*
 * Take the reference a multicast route the plugin installs in this table
 * holds. A route the kernel replays was installed already and holds its
 * reference still, which is what keeps a repeated synchronization from
 * leaking one per pass.
 */
static void
lcp_router_table_mcast_record (lcp_router_table_t *nlt, const mfib_prefix_t *prefix)
{
  lcp_router_mcast_entry_t *entry = lcp_router_table_mcast_find (nlt, prefix);

  if (NULL == entry)
    {
      vec_add2 (nlt->nlt_mcast_entries, entry, 1);
      entry->lcme_prefix = *prefix;
      nlt->nlt_refs++;
    }
  entry->lcme_replayed = 1;
}

/*
 * Give back what one route holds: its reference, and nothing that belongs to
 * the other routes of the table. The entry is removed before the last
 * reference can go, so the caller's pointer stays valid.
 */
static void
lcp_router_table_mcast_forget (lcp_router_table_t *nlt, lcp_router_mcast_entry_t *entry)
{
  lcp_router_mcast_entry_t *last = vec_end (nlt->nlt_mcast_entries) - 1;

  /* Moving the last route into the hole leaves the order alone; the
   * synchronization walks the list by index, hence the swap. */
  if (entry != last)
    *entry = *last;
  vec_dec_len (nlt->nlt_mcast_entries, 1);
  lcp_router_table_unlock (nlt);
}

/*
 * The synchronization in progress reached this table, so it can tell at its
 * end which of the routes recorded for it the kernel still has. A table the
 * dump does not reach is not entered, and keeps every route it holds.
 */
static void
lcp_router_table_mcast_sync_begin (lcp_router_table_t *nlt)
{
  lcp_router_mcast_entry_t *entry;

  vec_foreach (entry, nlt->nlt_mcast_entries)
    entry->lcme_replayed = 0;
}

/*
 * Remove the multicast routes of a table the dump of the synchronization
 * that just ended replayed no route for, and the ones of a table the dump
 * did not reach at all. Only the routes the plugin recorded for the table
 * are considered: another source can have installed multicast routes in the
 * same MFIB table, and those are none of the plugin's business.
 */
static void
lcp_router_table_mcast_sync_end (lcp_router_table_t *nlt)
{
  lcp_router_mcast_entry_t *entry;
  u32 ii = 0;

  while (ii < vec_len (nlt->nlt_mcast_entries))
    {
      entry = vec_elt_at_index (nlt->nlt_mcast_entries, ii);
      if (entry->lcme_replayed)
	{
	  entry->lcme_replayed = 0;
	  ii++;
	  continue;
	}

      /* Nothing but a netlink delete or a replace that names no nexthop takes
       * a route away, and both forget the record as they go. So the MFIB can
       * hold no entry here only for a prefix whose paths went another way;
       * removing what is not there would only warn. */
      if (FIB_NODE_INDEX_INVALID !=
	  mfib_table_lookup_exact_match (nlt->nlt_mfib_index, &entry->lcme_prefix))
	mfib_table_entry_delete (nlt->nlt_mfib_index, &entry->lcme_prefix, MFIB_SOURCE_PLUGIN_LOW);
      /* The route at this index is the one moved into its place, or the list
       * has shortened; either way the next one to look at is at the same
       * index. */
      lcp_router_table_mcast_forget (nlt, entry);
    }
}

static u32
lcp_router_table_source_count (const lcp_router_table_t *nlt, fib_source_t source)
{
  const fib_table_t *table = fib_table_get_or_null (nlt->nlt_fib_index, nlt->nlt_proto);

  if (NULL == table || source >= vec_len (table->ft_src_route_counts))
    return 0;

  return table->ft_src_route_counts[source];
}

static void
lcp_router_table_reconcile (lcp_router_table_t *nlt, fib_source_t source, u32 before)
{
  u32 after = lcp_router_table_source_count (nlt, source);

  /* Each learned prefix/source owns one reference, including each MPLS EOS
   * variant. The caller holds a temporary reference until reconciliation ends. */
  if (after >= before)
    nlt->nlt_refs += after - before;
  else
    {
      ASSERT (nlt->nlt_refs > before - after);
      nlt->nlt_refs -= before - after;
    }
  lcp_router_table_unlock (nlt);
}

int
lcp_router_table_state (u32 table_id, fib_protocol_t proto, lcp_router_table_state_t *state)
{
  const lcp_router_table_t *nlt = lcp_router_table_find (table_id, proto);

  if (!nlt)
    return 0;
  *state = (lcp_router_table_state_t) {
    .refs = nlt->nlt_refs,
    .fib_index = nlt->nlt_fib_index,
    .mfib_index = nlt->nlt_mfib_index,
    .sources = { lcp_rt_fib_src, lcp_rt_fib_src_dynamic, lcp_rt_fib_src_special },
    .mcast_routes = vec_len (nlt->nlt_mcast_entries),
  };
  return 1;
}

u32
lcp_router_cross_fib_nexthop_count (void)
{
  return lcp_router_cross_fib_reports;
}

/*
 * Build the fib_prefix_t for the destination of a netlink route. The
 * destination is only as long as the netlink attribute that carried it, so a
 * malformed message can hand over more bytes than the address family holds.
 * Reject such a record rather than copying past the field, or leaving fp_len
 * at 0 which would hijack 0.0.0.0/0 or ::/0.
 */
static int
lcp_router_route_mk_prefix (struct rtnl_route *r, fib_prefix_t *p)
{
  const struct nl_addr *addr = rtnl_route_get_dst (r);
  uint32_t family = nl_addr_get_family (addr);
  u32 *baddr = nl_addr_get_binary_addr (addr);
  u32 blen = nl_addr_get_len (addr);
  ip46_address_t *paddr = &p->fp_addr;
  u32 entry;

  ip46_address_reset (paddr);
  p->fp_proto = lcp_router_proto_k2f (family);

  switch (p->fp_proto)
    {
    case FIB_PROTOCOL_MPLS:
      /* The address is only as long as the netlink attribute that carried
       * it; read the label only when all four bytes are present. */
      if (blen < sizeof (entry))
	{
	  LCP_ROUTER_ERROR ("ignore mpls route with a %u byte dst address",
			    blen);
	  return -1;
	}
      entry = ntohl (*baddr);
      p->fp_label = (entry & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT;
      p->fp_len = 21;
      p->fp_eos = MPLS_NON_EOS;
      return 0;
    case FIB_PROTOCOL_IP4:
      if (PREDICT_FALSE (blen > sizeof (paddr->ip4)))
	return -1;
      memcpy (&paddr->ip4, baddr, blen);
      break;
    case FIB_PROTOCOL_IP6:
      if (PREDICT_FALSE (blen > sizeof (paddr->ip6)))
	return -1;
      memcpy (&paddr->ip6, baddr, blen);
      break;
    default:
      /* lcp_router_proto_k2f() reports FIB_PROTOCOL_NONE for a family with no
       * FIB protocol; such a prefix has no table to live in. */
      LCP_ROUTER_ERROR ("ignore route with a %u dst address family", family);
      return -1;
    }

  p->fp_len = nl_addr_get_prefixlen (addr);

  return 0;
}

/*
 * Build the mfib_prefix_t for a multicast netlink route. Either the group or
 * the source address is rejected when the netlink attribute is longer than
 * its ip46_address_t field can hold.
 *
 * An MFIB prefix is keyed by the length it is stored under: the table keeps a
 * hash per length, ip4_mfib_table_entry_insert() indexes it with fp_len, and
 * ip4_mfib_table_lookup_exact_match() reads it back the same way. A (S,G)
 * entry is the host length of both addresses, 64 for IPv4 and 256 for IPv6,
 * which is what ip4_mfib_table_lookup() and mfib_prefix_is_host() expect; a
 * (*,G) entry keeps the group's own length. The destination's prefix length is
 * the group mask, so using it for a route that names a source files the entry
 * in the group's bucket, where nothing looks for it and where it collides with
 * the (*,G) entry for the same group.
 *
 * A source is what makes a route (S,G): netlink can carry the attribute with
 * an all-zero address, which names no source, and IP4_MFIB_MK_KEY() then folds
 * nothing into the key. Such a route is the (*,G) entry and keeps the group's
 * length; keying it at the host length would store it where the (S,G) lookup
 * has a different key and where the group fallback of ip4_mfib_table_lookup()
 * does not look, so nothing would find it.
 */
static int
lcp_router_route_mk_mprefix (struct rtnl_route *r, mfib_prefix_t *p)
{
  const struct nl_addr *addr;
  fib_protocol_t fproto;

  addr = rtnl_route_get_dst (r);

  p->fp_len = nl_addr_get_prefixlen (addr);
  if (lcp_router_mk_addr46 (addr, &p->fp_grp_addr, &fproto))
    return -1;
  p->fp_proto = fproto;

  addr = rtnl_route_get_src (r);
  if (addr)
    {
      if (lcp_router_mk_addr46 (addr, &p->fp_src_addr, &fproto))
	return -1;
      p->fp_proto = fproto;
      if (!ip46_address_is_zero (&p->fp_src_addr))
	p->fp_len = 2 * fib_prefix_get_host_length (fproto);
    }

  return 0;
}

static int
lcp_router_mpls_nladdr_to_path (fib_route_path_t *path, struct nl_addr *addr)
{
  if (!addr)
    return 0;

  struct mpls_label *stack = nl_addr_get_binary_addr (addr);
  u32 entry, label;
  u8 exp, ttl;
  int label_count = 0;

  while (1)
    {
      entry = ntohl (stack[label_count++].entry);
      label = (entry & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT;
      exp = (entry & MPLS_LS_TC_MASK) >> MPLS_LS_TC_SHIFT;
      ttl = (entry & MPLS_LS_TTL_MASK) >> MPLS_LS_TTL_SHIFT;

      fib_mpls_label_t fml = {
	.fml_value = label,
	.fml_exp = exp,
	.fml_ttl = ttl,
      };
      vec_add1 (path->frp_label_stack, fml);

      if (entry & MPLS_LS_S_MASK)
	break;
    }
  return label_count;
}

typedef struct
{
  ip46_address_t lcor_gateway;
  u32 lcor_sw_if_index;
} lcp_router_onlink_nexthop_t;

typedef struct lcp_router_route_path_parse_t_
{
  fib_route_path_t *paths;
  fib_protocol_t route_proto;
  bool is_mcast;
  bool invalid;
  fib_route_path_flags_t type_flags;
  u8 preference;
  /* whether the caller installs the gateways; a delete asks the FIB instead,
   * because the message does not say which paths it took away */
  bool collect_onlink;
  /* gateways the kernel marked RTNH_F_ONLINK, one entry each */
  lcp_router_onlink_nexthop_t *onlink;
} lcp_router_route_path_parse_t;

static void
lcp_router_route_path_parse (struct rtnl_nexthop *rnh, void *arg)
{
  lcp_router_route_path_parse_t *ctx = arg;
  fib_route_path_t *path;
  u32 sw_if_index;
  int label_count = 0;

  if (ctx->invalid)
    return;

  sw_if_index = lcp_router_intf_h2p (rtnl_route_nh_get_ifindex (rnh));

  /*
   * The pair lookup is a hash lookup plus a pool index; it does not tell us
   * whether the interface still exists.  A route notification can name an
   * interface that has already been removed, which happens routinely while
   * the netlink state is being replayed after a socket error: the link dump
   * deletes LCP pairs before the route dump is read.  Dropping the nexthop
   * here keeps a stale sw_if_index out of the FIB, where it would later be
   * turned into an out-of-range fib_index.
   */
  if (~0 != sw_if_index &&
      NULL == vnet_get_sw_interface_or_null (vnet_get_main (), sw_if_index))
    {
      LCP_ROUTER_DBG (" skipping nexthop on dead sw_if_index %u", sw_if_index);
      sw_if_index = ~0;
    }

  if (~0 != sw_if_index)
    {
      fib_protocol_t fproto;
      struct nl_addr *addr;

      vec_add2 (ctx->paths, path, 1);

      path->frp_flags = FIB_ROUTE_PATH_FLAG_NONE | ctx->type_flags;
      path->frp_sw_if_index = sw_if_index;
      path->frp_preference = ctx->preference;

      /*
       * FIB Path Weight of 0 is meaningless and replaced with 1 further along.
       * See fib_path_create. fib_path_cmp_w_route_path would fail to match
       * such a fib_route_path_t with any fib_path_t, because a fib_path_t's
       * fp_weight can never be 0.
       */
      path->frp_weight = clib_max (1, rtnl_route_nh_get_weight (rnh));

      addr = rtnl_route_nh_get_gateway (rnh);
      if (!addr)
	addr = rtnl_route_nh_get_via (rnh);

      if (addr)
	{
	  if (lcp_router_mk_addr46 (addr, &path->frp_addr, &fproto))
	    {
	      /* Reject the whole route: installing the remaining paths would
	       * leave a partial path set in the FIB. Drop the path that was just
	       * added and let the caller release the rest. */
	      LCP_ROUTER_ERROR ("invalid nexthop address");
	      ctx->invalid = true;
	      vec_dec_len (ctx->paths, 1);
	      return;
	    }
	}
      else
	fproto = ctx->route_proto;

      path->frp_proto = fib_proto_to_dpo (fproto);

      /*
       * The kernel lets a route name a gateway no connected prefix covers
       * when the nexthop carries RTNH_F_ONLINK. The FIB has no path flag for
       * that, and the gateway's neighbour is never learned until an attached
       * entry covers it, so the caller installs one per gateway. MPLS and
       * multicast routes are left alone: neither resolves an IPv4 neighbour
       * through an attached prefix.
       */
      if (ctx->collect_onlink && (RTNH_F_ONLINK & rtnl_route_nh_get_flags (rnh)) &&
	  !ctx->is_mcast && FIB_PROTOCOL_IP4 == fproto && !ip46_address_is_zero (&path->frp_addr))
	{
	  lcp_router_onlink_nexthop_t *entry;

	  vec_add2 (ctx->onlink, entry, 1);
	  entry->lcor_gateway = path->frp_addr;
	  entry->lcor_sw_if_index = sw_if_index;
	  LCP_ROUTER_DBG (" onlink gateway %U", format_ip46_address, &path->frp_addr,
			  IP46_TYPE_ANY);
	}

      if (ctx->route_proto == FIB_PROTOCOL_MPLS)
	{
	  addr = rtnl_route_nh_get_newdst (rnh);
	  label_count = lcp_router_mpls_nladdr_to_path (path, addr);
	  if (label_count)
	    {
	      LCP_ROUTER_DBG (" is label swap to %u",
			      path->frp_label_stack[0].fml_value);
	    }
	  else
	    {
	      fib_mpls_label_t fml = {
		.fml_value = MPLS_LABEL_POP,
	      };
	      vec_add1 (path->frp_label_stack, fml);
	      LCP_ROUTER_DBG (" is label pop");
	    }
	}

#ifdef NL_CAPABILITY_VERSION_3_6_0
      addr = rtnl_route_nh_get_encap_mpls_dst (rnh);
      label_count = lcp_router_mpls_nladdr_to_path (path, addr);
      if (label_count)
	LCP_ROUTER_DBG (" has encap mpls, %d labels", label_count);
#endif

      if (ctx->is_mcast)
	path->frp_mitf_flags = MFIB_ITF_FLAG_FORWARD;

      LCP_ROUTER_DBG (" path:[%U]", format_fib_route_path, path);
    }
}

/* Rejected paths have not transferred label ownership to the FIB. */
static void
lcp_router_route_paths_discard (fib_route_path_t *paths)
{
  fib_route_path_t *path;

  vec_foreach (path, paths)
    vec_free (path->frp_label_stack);
  vec_free (paths);
}

/*
 * blackhole, unreachable, prohibit will not have a next hop in an
 * RTM_NEWROUTE. Add a path for them.
 */
static void
lcp_router_route_path_add_special (struct rtnl_route *rr,
				   lcp_router_route_path_parse_t *ctx)
{
  fib_route_path_t *path;

  if (rtnl_route_get_type (rr) < RTN_BLACKHOLE)
    return;

  /* if it already has a path, it does not need us to add one */
  if (vec_len (ctx->paths) > 0)
    return;

  vec_add2 (ctx->paths, path, 1);

  path->frp_flags = FIB_ROUTE_PATH_FLAG_NONE | ctx->type_flags;
  path->frp_sw_if_index = ~0;
  path->frp_proto = fib_proto_to_dpo (ctx->route_proto);
  path->frp_preference = ctx->preference;

  LCP_ROUTER_DBG (" path:[%U]", format_fib_route_path, path);
}

/*
 * Map of supported route types. Some types are omitted:
 * RTN_LOCAL - interface address addition creates these automatically
 * RTN_BROADCAST - same as RTN_LOCAL
 * RTN_UNSPEC, RTN_ANYCAST, RTN_THROW, RTN_NAT, RTN_XRESOLVE -
 *   There's not a VPP equivalent for these currently.
 */
static const u8 lcp_router_route_type_valid[__RTN_MAX] = {
  [RTN_UNICAST] = 1,	 [RTN_MULTICAST] = 1, [RTN_BLACKHOLE] = 1,
  [RTN_UNREACHABLE] = 1, [RTN_PROHIBIT] = 1,
};

/* Map of fib entry flags by route type */
static const fib_entry_flag_t lcp_router_route_type_feflags[__RTN_MAX] = {
  [RTN_LOCAL] = FIB_ENTRY_FLAG_LOCAL | FIB_ENTRY_FLAG_CONNECTED,
  [RTN_BROADCAST] = FIB_ENTRY_FLAG_DROP | FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT,
  [RTN_BLACKHOLE] = FIB_ENTRY_FLAG_DROP,
};

/* Map of fib route path flags by route type */
static const fib_route_path_flags_t
  lcp_router_route_type_frpflags[__RTN_MAX] = {
    [RTN_UNREACHABLE] = FIB_ROUTE_PATH_ICMP_UNREACH,
    [RTN_PROHIBIT] = FIB_ROUTE_PATH_ICMP_PROHIBIT,
    [RTN_BLACKHOLE] = FIB_ROUTE_PATH_DROP,
  };

static inline fib_source_t
lcp_router_proto_fib_source (u8 rt_proto)
{
  return (rt_proto <= RTPROT_STATIC) ? lcp_rt_fib_src : lcp_rt_fib_src_dynamic;
}

static fib_entry_flag_t
lcp_router_route_mk_entry_flags (uint8_t rtype, int table_id, uint8_t rproto)
{
  fib_entry_flag_t fef = FIB_ENTRY_FLAG_NONE;

  fef |= lcp_router_route_type_feflags[rtype];
  if ((rproto == RTPROT_KERNEL) || PREDICT_FALSE (255 == table_id))
    /* kernel proto is interface prefixes, 255 is linux's 'local' table */
    fef |= FIB_ENTRY_FLAG_ATTACHED | FIB_ENTRY_FLAG_CONNECTED;

  return (fef);
}

/*
 * Remove what a multicast route added: the entry of the plugin's source and
 * the paths it carried, both in the MFIB table, which is where
 * lcp_router_route_add installs a multicast route; the unicast table of the
 * same table id never holds it.
 *
 * The paths go after the entry, which drops the source together with its
 * entry flags and the paths it carries. What the call then takes out are the
 * paths MFIB left behind for another source that keeps the entry alive; it
 * leaves untouched a path the source no longer has.
 *
 * The table is taken for the call and released again, so a caller that holds
 * no reference of its own can drop a route too.
 */
static void
lcp_router_route_mcast_del (u32 table_id, fib_protocol_t proto, const mfib_prefix_t *prefix)
{
  lcp_router_mcast_entry_t *entry;
  lcp_router_table_t *nlt;

  nlt = lcp_router_table_find (lcp_router_table_k2f (table_id), proto);
  if (NULL == nlt)
    return;

  /* The kernel can send a delete for a route it never announced, and can
   * repeat one; the plugin holds nothing for it in either case. */
  entry = lcp_router_table_mcast_find (nlt, prefix);
  if (NULL == entry)
    {
      LCP_ROUTER_DBG ("route del: multicast route %U not held", format_mfib_prefix, prefix);
      return;
    }

  nlt->nlt_refs++;
  lcp_router_table_mcast_route_release (nlt, prefix);
  lcp_router_table_mcast_forget (nlt, entry);
  lcp_router_table_unlock (nlt);
}

static void
lcp_router_route_del (struct rtnl_route *rr)
{
  fib_entry_flag_t entry_flags;
  uint32_t table_id;
  fib_prefix_t pfx;
  lcp_router_table_t *nlt;
  uint8_t rtype, rproto;

  rtype = rtnl_route_get_type (rr);
  table_id = rtnl_route_get_table (rr);
  rproto = rtnl_route_get_protocol (rr);

  /* skip unsupported route types and local table */
  if (!lcp_router_route_type_valid[rtype] || (table_id == 255))
    return;

  if (lcp_router_route_mk_prefix (rr, &pfx))
    {
      LCP_ROUTER_ERROR ("route del: invalid destination");
      return;
    }
  entry_flags = lcp_router_route_mk_entry_flags (rtype, table_id, rproto);

  /* Skip any kernel routes and IPv6 LL or multicast routes */
  if (rproto == RTPROT_KERNEL ||
      (FIB_PROTOCOL_IP6 == pfx.fp_proto && (ip6_address_is_multicast (&pfx.fp_addr.ip6) ||
					    ip6_address_is_link_local_unicast (&pfx.fp_addr.ip6))))
    {
      LCP_ROUTER_DBG ("route del skip: %d:%U %U", rtnl_route_get_table (rr), format_fib_prefix,
		      &pfx, format_fib_entry_flags, entry_flags);
      return;
    }

  nlt = lcp_router_table_find (lcp_router_table_k2f (table_id), pfx.fp_proto);

  LCP_ROUTER_DBG ("route del: %d:%U %U", rtnl_route_get_table (rr),
		  format_fib_prefix, &pfx, format_fib_entry_flags,
		  entry_flags);

  if (NULL == nlt)
    return;

  lcp_router_route_path_parse_t np = {
    .route_proto = pfx.fp_proto,
    .type_flags = lcp_router_route_type_frpflags[rtype],
  };

  rtnl_route_foreach_nexthop (rr, lcp_router_route_path_parse, &np);
  if (np.invalid)
    {
      vec_free (np.onlink);
      lcp_router_route_paths_discard (np.paths);
      return;
    }
  lcp_router_route_path_add_special (rr, &np);

  /*
   * The reference keeps the table alive for the rest of the delete: a table
   * that holds nothing but the gateway records goes when the last of them is
   * released, and still has a route to take away below.
   */
  nlt->nlt_refs++;

  if (0 != vec_len (np.paths))
    {
      if (rtype == RTN_MULTICAST)
	{
	  mfib_prefix_t mpfx = {};

	  if (lcp_router_route_mk_mprefix (rr, &mpfx) || mpfx.fp_proto != pfx.fp_proto)
	    {
	      LCP_ROUTER_ERROR ("route del: invalid mcast prefix");
	      vec_free (np.onlink);
	      vec_free (np.paths);
	      lcp_router_table_unlock (nlt);
	      return;
	    }
	  /* The route's own reference goes with the call, and the copy of the
	   * table taken above is released after it, as on the unicast side. */
	  nlt->nlt_refs++;
	  lcp_router_route_mcast_del (table_id, pfx.fp_proto, &mpfx);
	  lcp_router_table_unlock (nlt);
	}
      else
	{
	  fib_source_t fib_src;

	  fib_src = lcp_router_proto_fib_source (rproto);
	  u32 before = lcp_router_table_source_count (nlt, fib_src);
	  nlt->nlt_refs++;

	  switch (pfx.fp_proto)
	    {
	    case FIB_PROTOCOL_IP6:
	      fib_table_entry_delete (nlt->nlt_fib_index, &pfx, fib_src);
	      break;
	    case FIB_PROTOCOL_MPLS:
	      fib_table_entry_path_remove2 (nlt->nlt_fib_index, &pfx, fib_src, np.paths);
	      /* delete the EOS route in addition to NEOS - fallthrough */
	      pfx.fp_eos = MPLS_EOS;
	    default:
	      fib_table_entry_path_remove2 (nlt->nlt_fib_index, &pfx, fib_src, np.paths);
	    }

	  lcp_router_table_reconcile (nlt, fib_src, before);
	}
    }

  /*
   * What the message named does not decide which gateways go: the kernel keys
   * routes by prefix, so the delete of a blackhole route carries no nexthop
   * and the unicast route of the same prefix stays, and one of the plugin's
   * sources can hold what the other does not. The paths are away by now, so
   * the FIB says which records are stale. A delete that took nothing away
   * leaves every path in place and so every record too.
   */
  if (rtype != RTN_MULTICAST && FIB_PROTOCOL_IP4 == pfx.fp_proto)
    lcp_router_table_onlink_sync_paths (nlt, &pfx, pfx.fp_proto);

  vec_free (np.onlink);
  vec_free (np.paths);
  lcp_router_table_unlock (nlt);
}

static fib_route_path_t *
lcp_router_fib_route_path_dup (fib_route_path_t *old)
{
  int idx;
  fib_route_path_t *p;

  fib_route_path_t *new = vec_dup (old);
  if (!new)
    return NULL;

  for (idx = 0; idx < vec_len (new); idx++)
    {
      p = &new[idx];
      if (p->frp_label_stack)
	p->frp_label_stack = vec_dup (p->frp_label_stack);
    }

  return new;
}

static void
lcp_router_cross_fib_db_free (void)
{
  hash_pair_t *p;

  if (NULL == lcp_router_cross_fib_db)
    return;

  hash_foreach_pair (p, lcp_router_cross_fib_db,
		     ({ clib_mem_free (uword_to_pointer (p->key, void *)); }));
  hash_free (lcp_router_cross_fib_db);
  lcp_router_cross_fib_db = NULL;
}

/*
 * Report a path whose nexthop device lives in a different FIB table than the
 * route being installed.  The path is left in the route: the kernel route is
 * the authority for the table it belongs to, and a path like this does forward
 * when the source address the route's table selects is local in the nexthop's
 * table.  Only the first report for a given path is emitted.
 */
static void
lcp_router_route_cross_fib_report (const fib_route_path_t *rpath, const fib_prefix_t *pfx,
				   const lcp_router_table_t *nlt, u32 kernel_table_id)
{
  lcp_router_cross_fib_key_t key;
  u32 nexthop_fib_index;

  if (~0 == rpath->frp_sw_if_index)
    return;

  nexthop_fib_index = fib_table_get_index_for_sw_if_index (nlt->nlt_proto, rpath->frp_sw_if_index);
  if (nexthop_fib_index == nlt->nlt_fib_index)
    return;

  /*
   * An interface that is not yet bound to any table has no FIB to compare
   * against; its binding is a separate condition and reporting ~0 as the
   * nexthop's FIB index would only mislead.
   */
  if (~0 == nexthop_fib_index)
    {
      LCP_ROUTER_DBG ("skip cross fib check for unbound sw_if_index %u", rpath->frp_sw_if_index);
      return;
    }

  if (hash_elts (lcp_router_cross_fib_db) >= LCP_ROUTER_CROSS_FIB_MAX_KEYS)
    lcp_router_cross_fib_db_free ();
  if (NULL == lcp_router_cross_fib_db)
    lcp_router_cross_fib_db = hash_create_mem (0, sizeof (key), sizeof (uword));

  clib_memset (&key, 0, sizeof (key));
  key.lcf_key_table_id = kernel_table_id;
  key.lcf_sw_if_index = rpath->frp_sw_if_index;
  key.lcf_fib_index = nlt->nlt_fib_index;
  key.lcf_nexthop_fib_index = nexthop_fib_index;
  key.lcf_addr = pfx->fp_addr;
  key.lcf_prefix_len = pfx->fp_len;
  key.lcf_proto = pfx->fp_proto;

  if (hash_get_mem (lcp_router_cross_fib_db, &key))
    return;

  hash_set_mem_alloc (&lcp_router_cross_fib_db, &key, 1);
  lcp_router_cross_fib_reports++;

  LCP_ROUTER_ERROR ("route %d:%U nexthop sw_if_index %u is in fib %u, not in fib %u",
		    kernel_table_id, format_fib_prefix, pfx, rpath->frp_sw_if_index,
		    nexthop_fib_index, nlt->nlt_fib_index);
}

/*
 * Multicast and MPLS paths reuse frp_sw_if_index with different FIB semantics,
 * so the unicast table lookup above does not apply to them.
 */
static void
lcp_router_route_paths_cross_fib_report (const fib_route_path_t *paths, const fib_prefix_t *pfx,
					 u8 rtype, const lcp_router_table_t *nlt,
					 u32 kernel_table_id)
{
  const fib_route_path_t *rpath;

  if (RTN_MULTICAST == rtype || FIB_PROTOCOL_MPLS == pfx->fp_proto)
    return;

  vec_foreach (rpath, paths)
    lcp_router_route_cross_fib_report (rpath, pfx, nlt, kernel_table_id);
}

static void
lcp_router_route_add (struct rtnl_route *rr, int is_replace)
{
  fib_entry_flag_t entry_flags;
  uint32_t table_id;
  fib_prefix_t pfx;
  mfib_prefix_t mpfx = {};
  lcp_router_table_t *nlt;
  uint8_t rtype, rproto;

  rtype = rtnl_route_get_type (rr);
  table_id = rtnl_route_get_table (rr);
  rproto = rtnl_route_get_protocol (rr);

  /* skip unsupported route types and local table */
  if (!lcp_router_route_type_valid[rtype] || (table_id == 255))
    return;

  if (lcp_router_route_mk_prefix (rr, &pfx))
    {
      LCP_ROUTER_ERROR ("route add: invalid destination");
      return;
    }
  entry_flags = lcp_router_route_mk_entry_flags (rtype, table_id, rproto);

  /* Skip any kernel routes and IPv6 LL or multicast routes */
  if (rproto == RTPROT_KERNEL ||
      (FIB_PROTOCOL_IP6 == pfx.fp_proto &&
       (ip6_address_is_multicast (&pfx.fp_addr.ip6) ||
	ip6_address_is_link_local_unicast (&pfx.fp_addr.ip6))))
    {
      LCP_ROUTER_DBG ("route add skip: %d:%U %U", rtnl_route_get_table (rr), format_fib_prefix,
		      &pfx, format_fib_entry_flags, entry_flags);
      return;
    }
  LCP_ROUTER_DBG ("route %s: %d:%U %U", is_replace ? "replace" : "add",
		  rtnl_route_get_table (rr), format_fib_prefix, &pfx,
		  format_fib_entry_flags, entry_flags);

  /* Reject a malformed multicast prefix before the table reference is taken,
   * so the early return leaves no lock behind. */
  if (rtype == RTN_MULTICAST && lcp_router_route_mk_mprefix (rr, &mpfx))
    {
      LCP_ROUTER_ERROR ("route add: invalid mcast prefix");
      return;
    }

  lcp_router_route_path_parse_t np = {
    .route_proto = pfx.fp_proto,
    .is_mcast = (rtype == RTN_MULTICAST),
    .type_flags = lcp_router_route_type_frpflags[rtype],
    .preference = (u8) rtnl_route_get_priority (rr),
    .collect_onlink = true,
  };

  rtnl_route_foreach_nexthop (rr, lcp_router_route_path_parse, &np);
  if (np.invalid)
    {
      vec_free (np.onlink);
      lcp_router_route_paths_discard (np.paths);
      return;
    }
  lcp_router_route_path_add_special (rr, &np);

  if (0 != vec_len (np.paths))
    {
      nlt = lcp_router_table_add_or_lock (table_id, pfx.fp_proto);

      lcp_router_route_paths_cross_fib_report (np.paths, &pfx, rtype, nlt, table_id);

      if (rtype != RTN_MULTICAST && FIB_PROTOCOL_IP4 == pfx.fp_proto)
	{
	  lcp_router_onlink_nexthop_t *onlink;

	  /* The new gateways arrive before the route itself, so that the
	   * attached prefix is in place when the route first resolves. A
	   * replace then gives up only the gateways it no longer names: one
	   * the route keeps finds its record already there, and keeps the
	   * attached prefix and the neighbour state hanging off it. */
	  vec_foreach (onlink, np.onlink)
	    lcp_router_table_onlink_add (nlt, &pfx, &onlink->lcor_gateway, onlink->lcor_sw_if_index,
					 pfx.fp_proto);
	}

      if (rtype == RTN_MULTICAST)
	{
	  /* it's not clear to me how linux expresses the RPF paramters
	   * so we'll allow from all interfaces and hope for the best.
	   *
	   * The entry flags are set in the same call that installs the paths.
	   * Setting them in a call of their own feeds MFIB_ENTRY_FLAG_NONE to
	   * a source that keeps its paths, and the source then reads as one
	   * with nothing left, so a later delete of that source takes the
	   * entry away with it. */
	  mfib_table_entry_paths_update (nlt->nlt_mfib_index, &mpfx, MFIB_SOURCE_PLUGIN_LOW,
					 MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF, np.paths);
	  /* The record now holds what the route needs: its entry in the list of
	   * the table's routes and the reference that goes with it. The
	   * reference taken for this call is given back here, as the unicast
	   * arm gives back its own below, so a route that comes and goes leaves
	   * the table's count as it found it. */
	  lcp_router_table_mcast_record (nlt, &mpfx);
	  lcp_router_table_unlock (nlt);
	}
      else
	{
	  fib_source_t fib_src;
	  const fib_route_path_t *rpath;

	  vec_foreach (rpath, np.paths)
	    {
	      if (fib_route_path_is_attached (rpath))
		{
		  entry_flags |= FIB_ENTRY_FLAG_ATTACHED;
		  break;
		}
	    }

	  fib_src = lcp_router_proto_fib_source (rproto);
	  u32 before = lcp_router_table_source_count (nlt, fib_src);

	  if (pfx.fp_proto == FIB_PROTOCOL_MPLS)
	    {
	      /* in order to avoid double-frees, we duplicate the paths. */
	      fib_route_path_t *pathdup =
		lcp_router_fib_route_path_dup (np.paths);
	      if (is_replace)
		fib_table_entry_update (nlt->nlt_fib_index, &pfx, fib_src,
					entry_flags, pathdup);
	      else
		fib_table_entry_path_add2 (nlt->nlt_fib_index, &pfx, fib_src,
					   entry_flags, pathdup);
	      vec_free (pathdup);

	      /* install EOS route in addition to NEOS */
	      pfx.fp_eos = MPLS_EOS;
	      pfx.fp_payload_proto = np.paths[0].frp_proto;
	    }

	  if (is_replace)
	    fib_table_entry_update (nlt->nlt_fib_index, &pfx, fib_src,
				    entry_flags, np.paths);
	  else
	    fib_table_entry_path_add2 (nlt->nlt_fib_index, &pfx, fib_src,
				       entry_flags, np.paths);

	  /* A replace may name fewer gateways than the route it replaces. The
	   * FIB has the new paths now, so it says which records are stale. */
	  if (is_replace && rtype != RTN_MULTICAST && FIB_PROTOCOL_IP4 == pfx.fp_proto)
	    lcp_router_table_onlink_sync_paths (nlt, &pfx, pfx.fp_proto);

	  lcp_router_table_reconcile (nlt, fib_src, before);
	}
    }
  else
    {
      LCP_ROUTER_DBG ("no paths for route: %d:%U %U",
		      rtnl_route_get_table (rr), format_fib_prefix, &pfx,
		      format_fib_entry_flags, entry_flags);

      /* The kernel can replace a route with one that names no nexthop. An
       * MFIB entry whose paths are all gone loses its source, so a record
       * left behind would hold a reference for a route the MFIB no longer
       * has; the route goes as a delete would take it.
       *
       * Only a replace can do that. The kernel also sends an add with no
       * nexthop, for a route it dropped itself; nothing was installed for
       * one, and the prefix may be one another source owns, such as the
       * table's own (*,224.0.0.1) and (*,224.0.0.2). */
      if (RTN_MULTICAST == rtype && is_replace)
	lcp_router_route_mcast_del (table_id, pfx.fp_proto, &mpfx);
      /* A replace that names no nexthop no longer holds the gateways of the
       * route it replaces. Nothing was taken out of the FIB, so what it
       * still holds decides: a prefix another message left in place keeps
       * its gateways, and the ones whose paths the FIB no longer has go. */
      else if (RTN_MULTICAST != rtype && is_replace && FIB_PROTOCOL_IP4 == pfx.fp_proto)
	{
	  nlt = lcp_router_table_add_or_lock (table_id, pfx.fp_proto);
	  lcp_router_table_onlink_sync_paths (nlt, &pfx, pfx.fp_proto);
	  lcp_router_table_unlock (nlt);
	}
    }
  vec_free (np.onlink);
  vec_free (np.paths);
}

static void
lcp_router_route_sync_begin (void)
{
  lcp_router_table_t *nlt;

  pool_foreach (nlt, lcp_router_table_pool)
    {
      fib_table_mark (nlt->nlt_fib_index, nlt->nlt_proto, lcp_rt_fib_src);
      fib_table_mark (nlt->nlt_fib_index, nlt->nlt_proto,
		      lcp_rt_fib_src_dynamic);
      lcp_router_table_mcast_sync_begin (nlt);

      LCP_ROUTER_INFO ("Begin synchronization of %U routes in table %u",
		       format_fib_protocol, nlt->nlt_proto,
		       nlt->nlt_fib_index);
    }
}

static void
lcp_router_route_sync_end (void)
{
  lcp_router_table_t *nlt;
  u32 *indices = NULL, *index;

  pool_foreach (nlt, lcp_router_table_pool)
    vec_add1 (indices, nlt - lcp_router_table_pool);

  vec_foreach (index, indices)
    {
      nlt = pool_elt_at_index (lcp_router_table_pool, *index);
      /* The reference keeps the table alive while its routes go. It has to be
       * taken before the walk below, not after: every recorded route holds one
       * reference of its own, and a table whose only references are those
       * routes loses the last of them to the last route removed. The removal
       * then frees the record, and the sweep below would read a freed one. */
      nlt->nlt_refs++;

      lcp_router_table_mcast_sync_end (nlt);

      u32 before = lcp_router_table_source_count (nlt, lcp_rt_fib_src) +
		   lcp_router_table_source_count (nlt, lcp_rt_fib_src_dynamic);
      fib_table_sweep (nlt->nlt_fib_index, nlt->nlt_proto, lcp_rt_fib_src);
      fib_table_sweep (nlt->nlt_fib_index, nlt->nlt_proto, lcp_rt_fib_src_dynamic);
      /* The sweep took away the routes the kernel no longer has; their
       * gateways go with them. This releases table references of its own,
       * which the reference taken above keeps safe. */
      lcp_router_table_onlink_prune (nlt);

      LCP_ROUTER_INFO ("End synchronization of %U routes in table %u",
		       format_fib_protocol, nlt->nlt_proto,
		       nlt->nlt_fib_index);
      u32 after = lcp_router_table_source_count (nlt, lcp_rt_fib_src) +
		  lcp_router_table_source_count (nlt, lcp_rt_fib_src_dynamic);
      ASSERT (before >= after && nlt->nlt_refs > before - after);
      nlt->nlt_refs -= before - after;
      lcp_router_table_unlock (nlt);
    }
  vec_free (indices);
}

typedef struct lcp_router_table_flush_entry_t
{
  fib_prefix_t lrtfe_pfx;
  fib_node_index_t lrtfe_fib_entry_index;
  fib_route_path_t *rpaths;
} lcp_router_table_flush_entry_t;

typedef struct lcp_router_table_flush_ctx_t_
{
  lcp_router_table_flush_entry_t *lrtf_entries;
  u32 *lrtf_sw_if_index_to_bool;
  fib_source_t lrtf_source;
  fib_path_encode_ctx_t path_ctx;
} lcp_router_table_flush_ctx_t;

fib_path_list_walk_rc_t
lcp_router_path_filter_and_encode (fib_node_index_t path_list_index,
				   fib_node_index_t path_index, void *arg)
{
  lcp_router_table_flush_ctx_t *ctx = arg;
  u32 sw_if_index;

  sw_if_index = fib_path_get_resolving_interface (path_index);

  if (~0 != sw_if_index &&
      sw_if_index < vec_len (ctx->lrtf_sw_if_index_to_bool) &&
      ctx->lrtf_sw_if_index_to_bool[sw_if_index])
    {
      return fib_path_encode (path_list_index, path_index, NULL,
			      &ctx->path_ctx);
    }

  return (FIB_PATH_LIST_WALK_CONTINUE);
}

static fib_table_walk_rc_t
lcp_router_table_flush_cb (fib_node_index_t fib_entry_index, void *arg)
{
  lcp_router_table_flush_ctx_t *ctx = arg;
  fib_entry_t *fib_entry;
  fib_entry_src_t *esrc;

  ctx->path_ctx.rpaths = NULL;

  fib_entry = fib_entry_get (fib_entry_index);

  esrc = fib_entry_src_find (fib_entry, ctx->lrtf_source);

  if (NULL == esrc || FIB_NODE_INDEX_INVALID == esrc->fes_pl)
    {
      return (FIB_TABLE_WALK_CONTINUE);
    }

  fib_path_list_walk (esrc->fes_pl, lcp_router_path_filter_and_encode, ctx);

  if (0 != vec_len (ctx->path_ctx.rpaths))
    {
      lcp_router_table_flush_entry_t *lrtfe;
      vec_add2 (ctx->lrtf_entries, lrtfe, 1);
      lrtfe->lrtfe_pfx = *fib_entry_get_prefix (fib_entry_index);
      lrtfe->lrtfe_fib_entry_index = fib_entry_index;
      lrtfe->rpaths = ctx->path_ctx.rpaths;
      fib_node_lock (&fib_entry->fe_node);
    }

  return (FIB_TABLE_WALK_CONTINUE);
}

static void
lcp_router_table_flush (lcp_router_table_t *nlt, u32 *sw_if_index_to_bool,
			fib_source_t source)
{
  lcp_router_table_flush_ctx_t ctx = {
    .lrtf_entries = NULL,
    .lrtf_sw_if_index_to_bool = sw_if_index_to_bool,
    .lrtf_source = source,
  };
  lcp_router_table_flush_entry_t *lrtfe;

  LCP_ROUTER_DBG (
    "Flush table: proto %U, fib-index %u, max sw_if_index %u, source %U",
    format_fib_protocol, nlt->nlt_proto, nlt->nlt_fib_index,
    vec_len (sw_if_index_to_bool) - 1, format_fib_source, source);

  fib_table_walk (nlt->nlt_fib_index, nlt->nlt_proto,
		  lcp_router_table_flush_cb, &ctx);

  LCP_ROUTER_DBG ("Flush table: entries number to delete %u",
		  vec_len (ctx.lrtf_entries));

  /* A flush of the plugin's own sources can take a route away without a
   * netlink delete, so the gateways it held are released here. The reference
   * keeps the table alive while the routes go, the same way the loop below
   * relies on; it is released once at the end. */
  nlt->nlt_refs++;
  vec_foreach (lrtfe, ctx.lrtf_entries)
    {
      int is_sourced;

      fib_table_entry_path_remove2 (nlt->nlt_fib_index, &lrtfe->lrtfe_pfx, source, lrtfe->rpaths);
      is_sourced = fib_entry_is_sourced (lrtfe->lrtfe_fib_entry_index, source);
      fib_node_unlock (&fib_entry_get (lrtfe->lrtfe_fib_entry_index)->fe_node);
      vec_free (lrtfe->rpaths);
      if (!is_sourced)
	lcp_router_table_unlock (nlt);
    }
  if (lcp_rt_fib_src == source || lcp_rt_fib_src_dynamic == source)
    lcp_router_table_onlink_prune (nlt);
  lcp_router_table_unlock (nlt);

  vec_free (ctx.lrtf_entries);
}

__clib_export const nl_vft_t lcp_router_vft = {
  .nvl_rt_link_add = { .is_mp_safe = 0, .cb = lcp_router_link_add },
  .nvl_rt_link_del = { .is_mp_safe = 0, .cb = lcp_router_link_del },
  .nvl_rt_link_sync_begin = { .is_mp_safe = 0, .cb = lcp_router_link_sync_begin },
  .nvl_rt_link_sync_end = { .is_mp_safe = 0, .cb = lcp_router_link_sync_end },
  .nvl_rt_addr_add = { .is_mp_safe = 0, .cb = lcp_router_link_addr_add },
  .nvl_rt_addr_del = { .is_mp_safe = 0, .cb = lcp_router_link_addr_del },
  .nvl_rt_addr_sync_begin = { .is_mp_safe = 0, .cb = lcp_router_link_addr_sync_begin },
  .nvl_rt_addr_sync_end = { .is_mp_safe = 0, .cb = lcp_router_link_addr_sync_end },
  .nvl_rt_neigh_add = { .is_mp_safe = 0, .cb = lcp_router_neigh_add },
  .nvl_rt_neigh_del = { .is_mp_safe = 0, .cb = lcp_router_neigh_del },
  .nvl_rt_neigh_sync_begin = { .is_mp_safe = 0, .cb = lcp_router_neigh_sync_begin },
  .nvl_rt_neigh_sync_end = { .is_mp_safe = 0, .cb = lcp_router_neigh_sync_end },
  .nvl_rt_route_add = { .is_mp_safe = 1, .cb = lcp_router_route_add },
  .nvl_rt_route_del = { .is_mp_safe = 1, .cb = lcp_router_route_del },
  .nvl_rt_route_sync_begin = { .is_mp_safe = 0, .cb = lcp_router_route_sync_begin },
  .nvl_rt_route_sync_end = { .is_mp_safe = 0, .cb = lcp_router_route_sync_end },
};

static void
lcp_router_interface_add_cb (lcp_itf_pair_t *lip)
{
  u32 table_id;
  fib_protocol_t proto;

  FOR_EACH_FIB_IP_PROTOCOL (proto)
  {
    table_id = fib_table_get_table_id_for_sw_if_index (proto, lip->lip_phy_sw_if_index);
    if (table_id != ~0)
      lcp_router_table_add_or_lock (table_id, proto);
  }
}

static void
lcp_router_interface_del_cb (lcp_itf_pair_t *lip)
{
  u32 table_id;
  u32 *sw_if_index_to_bool = NULL;
  fib_protocol_t proto;
  lcp_router_table_t *nlt;

  lcp_router_ip4_mroutes_add_del (lip->lip_phy_sw_if_index, 0);
  lcp_router_ip6_mroutes_add_del (lip->lip_phy_sw_if_index, 0);

  lcp_router_neigh_static_flush_if (lip->lip_phy_sw_if_index);

  vec_validate_init_empty (sw_if_index_to_bool, lip->lip_phy_sw_if_index, false);
  sw_if_index_to_bool[lip->lip_phy_sw_if_index] = true;

  FOR_EACH_FIB_IP_PROTOCOL (proto)
  {
    table_id = fib_table_get_table_id_for_sw_if_index (proto, lip->lip_phy_sw_if_index);
    nlt = lcp_router_table_find (table_id, proto);
    if (nlt)
      {
	lcp_router_table_flush (nlt, sw_if_index_to_bool, lcp_rt_fib_src);
	lcp_router_table_flush (nlt, sw_if_index_to_bool, lcp_rt_fib_src_dynamic);
	lcp_router_table_unlock (nlt);
      }
  }

  vec_free (sw_if_index_to_bool);
}

static void
lcp_router_table_bind (u32 sw_if_index, fib_protocol_t fproto, u32 new_fib_index, u32 old_fib_index)
{
  u32 new_table_id, old_table_id;
  lcp_router_table_t *nlt;

  if (INDEX_INVALID == lcp_itf_pair_find_by_phy (sw_if_index))
    return;

  if (new_fib_index == old_fib_index)
    return;

  new_table_id = fib_table_get_table_id (new_fib_index, fproto);
  if (new_table_id != ~0)
    {
      lcp_router_table_add_or_lock (new_table_id, fproto);
    }

  old_table_id = fib_table_get_table_id (old_fib_index, fproto);
  if (old_table_id != ~0)
    {
      nlt = lcp_router_table_find (old_table_id, fproto);
      if (nlt)
	lcp_router_table_unlock (nlt);
    }
}

static void
lcp_router_table_bind_v4 (ip4_main_t *im, uword opaque, u32 sw_if_index, u32 new_fib_index,
			  u32 old_fib_index)
{
  lcp_router_table_bind (sw_if_index, FIB_PROTOCOL_IP4, new_fib_index, old_fib_index);
}

static void
lcp_router_table_bind_v6 (ip6_main_t *im, uword opaque, u32 sw_if_index, u32 new_fib_index,
			  u32 old_fib_index)
{
  lcp_router_table_bind (sw_if_index, FIB_PROTOCOL_IP6, new_fib_index, old_fib_index);
}

static clib_error_t *
lcp_router_init (vlib_main_t *vm)
{
  lcp_router_logger = vlib_log_register_class ("linux-cp", "router");

  nl_register_vft (&lcp_router_vft);

  lcp_itf_pair_vft_t lcp_router_interface_pair_vft = {
    .pair_add_fn = lcp_router_interface_add_cb,
    .pair_del_fn = lcp_router_interface_del_cb,
  };

  lcp_itf_pair_register_vft (&lcp_router_interface_pair_vft);

  VNET_SW_INTERFACE_TABLE_BIND_V4_CB (lcp_router_table_bind_v4);
  VNET_SW_INTERFACE_TABLE_BIND_V6_CB (lcp_router_table_bind_v6);

  /*
   * Allocate separate learned and permanent sources. The low priority source is for
   * dynamic routes. If a dynamic route daemon (FRR) tries to remove its
   * route, it will use the low priority source to ensure it will not
   * remove static routes which were added with the higher priority source.
   */
  lcp_rt_fib_src =
    fib_source_allocate ("lcp-rt", FIB_SOURCE_PRIORITY_HI, FIB_SOURCE_BH_API);

  lcp_rt_fib_src_dynamic = fib_source_allocate (
    "lcp-rt-dynamic", FIB_SOURCE_PRIORITY_HI + 1, FIB_SOURCE_BH_API);

  lcp_rt_fib_src_special =
    fib_source_allocate ("lcp-rt-special", FIB_SOURCE_PRIORITY_HI, FIB_SOURCE_BH_API);

  lcp_rt_fib_src_onlink =
    fib_source_allocate ("lcp-rt-onlink", FIB_SOURCE_PRIORITY_HI, FIB_SOURCE_BH_API);

  /*
   * Publish the neighbour synchronization's outcomes where an operator can
   * see them without the lcp logger. Each is a cumulative count for the
   * lifetime of the process, like the netlink synchronization counters.
   */
  lcp_router_neigh_refused_stat = vlib_stats_add_gauge ("/lcp/neighbor/refused");
  lcp_router_neigh_replaced_stat = vlib_stats_add_gauge ("/lcp/neighbor/replaced");
  lcp_router_neigh_stale_skipped_stat = vlib_stats_add_gauge ("/lcp/neighbor/stale-skipped");

  lcp_router_neigh_stat_publish (lcp_router_neigh_refused_stat, 0);
  lcp_router_neigh_stat_publish (lcp_router_neigh_replaced_stat, 0);
  lcp_router_neigh_stat_publish (lcp_router_neigh_stale_skipped_stat, 0);

  return (NULL);
}

VLIB_INIT_FUNCTION (lcp_router_init) = {
  .runs_before = VLIB_INITS ("lcp_nl_init"),
};
