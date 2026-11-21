/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Intel and/or its affiliates.
 */

#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/init.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/dpo/interface_tx_dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <ppp/packet.h>
#include <pppoe/pppoe.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/adj/adj_mcast.h>

#include <vppinfra/hash.h>
#include <vppinfra/bihash_template.c>

pppoe_main_t pppoe_main;

static fib_source_t pppoe_fib_src;

u8 *
format_pppoe_session (u8 *s, va_list *args)
{
  pppoe_session_t *t = va_arg (*args, pppoe_session_t *);
  pppoe_main_t *pem = &pppoe_main;

  s = format (s, "[%d] sw-if-index %d session-id %d client-ip %U ", t - pem->sessions,
	      t->sw_if_index, t->session_id, format_ip46_address, &t->client_ip, IP46_TYPE_ANY);

  if (!ip46_address_is_zero (&t->client_ip6))
    s = format (s, "client-ip6 %U ", format_ip46_address, &t->client_ip6, IP46_TYPE_IP6);

  s = format (s, "encap-if-index %d decap-fib-index %d\n", t->encap_if_index, t->decap_fib_index);

  s = format (s, "    local-mac %U  client-mac %U", format_ethernet_address, t->local_mac,
	      format_ethernet_address, t->client_mac);

  return s;
}

static u8 *
format_pppoe_name (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "pppoe_session%d", dev_instance);
}

static clib_error_t *
pppoe_interface_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return /* no error */ 0;
}

VNET_DEVICE_CLASS (pppoe_device_class, static) = {
  .name = "PPPoE",
  .format_device_name = format_pppoe_name,
  .admin_up_down_function = pppoe_interface_admin_up_down,
};

static u8 *
format_pppoe_header_with_length (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

static u8 *
pppoe_build_rewrite (vnet_main_t *vnm, u32 sw_if_index, vnet_link_t link_type,
		     const void *dst_address)
{
  pppoe_session_t *t;
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *si;
  pppoe_header_t *pppoe;
  u8 *rw = 0;

  t = pppoe_session_find_by_sw_if_index (sw_if_index);
  if (!t)
    return 0;

  int len = sizeof (pppoe_header_t) + sizeof (ethernet_header_t);
  si = vnet_get_sw_interface (vnm, t->encap_if_index);
  if (si->type == VNET_SW_INTERFACE_TYPE_SUB)
    {
      if (si->sub.eth.flags.one_tag == 1)
	{
	  len += sizeof (ethernet_vlan_header_t);
	}
    }

  vec_validate_aligned (rw, len - 1, CLIB_CACHE_LINE_BYTES);

  ethernet_header_t *eth_hdr = (ethernet_header_t *) rw;
  eth_hdr->type = clib_host_to_net_u16 (ETHERNET_TYPE_PPPOE_SESSION);
  pppoe = (pppoe_header_t *) (eth_hdr + 1);

  if (si->type == VNET_SW_INTERFACE_TYPE_SUB)
    {
      if (si->sub.eth.flags.one_tag == 1)
	{
	  eth_hdr->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
	  ethernet_vlan_header_t *vlan = (ethernet_vlan_header_t *) (eth_hdr + 1);
	  vlan->type = clib_host_to_net_u16 (ETHERNET_TYPE_PPPOE_SESSION);
	  vlan->priority_cfi_and_id = clib_host_to_net_u16 (si->sub.eth.outer_vlan_id);
	  pppoe = (pppoe_header_t *) (vlan + 1);
	}
      si = vnet_get_sw_interface (vnm, si->sup_sw_if_index);
    }

  // set the right mac addresses
  hi = vnet_get_hw_interface (vnm, si->hw_if_index);
  clib_memcpy (eth_hdr->src_address, hi->hw_address, 6);
  clib_memcpy (eth_hdr->dst_address, t->client_mac, 6);

  pppoe->ver_type = PPPOE_VER_TYPE;
  pppoe->code = 0;
  pppoe->session_id = clib_host_to_net_u16 (t->session_id);
  pppoe->length = 0; /* To be filled in at run-time */

  switch (link_type)
    {
    case VNET_LINK_IP4:
      pppoe->ppp_proto = clib_host_to_net_u16 (PPP_PROTOCOL_ip4);
      break;
    case VNET_LINK_IP6:
      pppoe->ppp_proto = clib_host_to_net_u16 (PPP_PROTOCOL_ip6);
      break;
    default:
      break;
    }

  return rw;
}

/**
 * @brief Fixup the adj rewrite post encap. Insert the packet's length
 */
static void
pppoe_fixup (vlib_main_t *vm, const ip_adjacency_t *adj, vlib_buffer_t *b0, const void *data)
{
  // const pppoe_session_t *t;
  pppoe_header_t *pppoe0;
  uword len = (uword) data;

  /* update the rewrite string */
  pppoe0 = vlib_buffer_get_current (b0) + len;

  pppoe0->length =
    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) - sizeof (pppoe_header_t) +
			  sizeof (pppoe0->ppp_proto) - len);
}

static void
pppoe_update_adj (vnet_main_t *vnm, u32 sw_if_index, adj_index_t ai)
{
  dpo_id_t dpo = DPO_INVALID;
  ip_adjacency_t *adj;
  pppoe_session_t *t;
  vnet_sw_interface_t *si;

  ASSERT (ADJ_INDEX_INVALID != ai);

  adj = adj_get (ai);
  t = pppoe_session_find_by_sw_if_index (sw_if_index);
  if (!t)
    return;

  uword len = sizeof (ethernet_header_t);

  si = vnet_get_sw_interface (vnm, t->encap_if_index);
  if (si->type == VNET_SW_INTERFACE_TYPE_SUB)
    {
      if (si->sub.eth.flags.one_tag == 1)
	{
	  len += sizeof (ethernet_vlan_header_t);
	}
    }

  switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_ARP:
    case IP_LOOKUP_NEXT_GLEAN:
    case IP_LOOKUP_NEXT_BCAST:
      adj_nbr_midchain_update_rewrite (ai, pppoe_fixup, (void *) len, ADJ_FLAG_NONE,
				       pppoe_build_rewrite (vnm, sw_if_index, adj->ia_link, NULL));
      break;
    case IP_LOOKUP_NEXT_MCAST:
      /*
       * Construct a partial rewrite from the known ethernet mcast dest MAC
       * There's no MAC fixup, so the last 2 parameters are 0
       */
      adj_mcast_midchain_update_rewrite (ai, pppoe_fixup, (void *) len, ADJ_FLAG_NONE,
					 pppoe_build_rewrite (vnm, sw_if_index, adj->ia_link, NULL),
					 0, 0);
      break;

    case IP_LOOKUP_NEXT_DROP:
    case IP_LOOKUP_NEXT_PUNT:
    case IP_LOOKUP_NEXT_LOCAL:
    case IP_LOOKUP_NEXT_REWRITE:
    case IP_LOOKUP_NEXT_MIDCHAIN:
    case IP_LOOKUP_NEXT_MCAST_MIDCHAIN:
    case IP_LOOKUP_NEXT_ICMP_ERROR:
    case IP_LOOKUP_N_NEXT:
      ASSERT (0);
      break;
    }

  interface_tx_dpo_add_or_lock (vnet_link_to_dpo_proto (adj->ia_link), t->encap_if_index, &dpo);

  adj_nbr_midchain_stack (ai, &dpo);

  dpo_reset (&dpo);
}

VNET_HW_INTERFACE_CLASS (pppoe_hw_class) = {
  .name = "PPPoE",
  .format_header = format_pppoe_header_with_length,
  .build_rewrite = pppoe_build_rewrite,
  .update_adjacency = pppoe_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};

#define foreach_copy_field                                                                         \
  _ (session_id)                                                                                   \
  _ (encap_if_index)                                                                               \
  _ (decap_fib_index)

static bool
pppoe_decap_next_is_valid (pppoe_main_t *pem, u32 is_ip6, u32 decap_fib_index)
{
  vlib_main_t *vm = pem->vlib_main;
  u32 input_idx = (!is_ip6) ? ip4_input_node.index : ip6_input_node.index;
  vlib_node_runtime_t *r = vlib_node_get_runtime (vm, input_idx);

  return decap_fib_index < r->n_next_nodes;
}

/* A path is added while the address is held and removed with it, so a route
 * that never reached the table is never removed from it either. */
static void
pppoe_client_fib_path_add (u32 fib_index, fib_protocol_t proto, const ip46_address_t *addr,
			   u32 sw_if_index)
{
  fib_prefix_t pfx = { 0 };

  if (fib_index == ~0)
    return;

  clib_memcpy (&pfx.fp_addr, addr, sizeof (pfx.fp_addr));
  pfx.fp_len = (proto == FIB_PROTOCOL_IP4) ? 32 : 128;
  pfx.fp_proto = proto;

  fib_table_entry_path_add (fib_index, &pfx, pppoe_fib_src, FIB_ENTRY_FLAG_NONE,
			    fib_proto_to_dpo (proto), &pfx.fp_addr, sw_if_index, ~0, 1, NULL,
			    FIB_ROUTE_PATH_FLAG_NONE);
}

static void
pppoe_client_fib_path_remove (u32 fib_index, fib_protocol_t proto, const ip46_address_t *addr,
			      u32 sw_if_index)
{
  fib_prefix_t pfx = { 0 };

  if (fib_index == ~0)
    return;

  clib_memcpy (&pfx.fp_addr, addr, sizeof (pfx.fp_addr));
  pfx.fp_len = (proto == FIB_PROTOCOL_IP4) ? 32 : 128;
  pfx.fp_proto = proto;

  fib_table_entry_path_remove (fib_index, &pfx, pppoe_fib_src, fib_proto_to_dpo (proto),
			       &pfx.fp_addr, sw_if_index, ~0, 1, FIB_ROUTE_PATH_FLAG_NONE);
}

/* The control plane hands out IPv6 addresses in the default table, and does so
 * when it runs, which may be before anyone configured IPv6. */
static u32
pppoe_ip6_fib_index (void)
{
  return fib_table_find (FIB_PROTOCOL_IP6, 0);
}

static void
pppoe_session_ip4_route_add (pppoe_session_t *t)
{
  pppoe_client_fib_path_add (
    t->decap_fib_index, ip46_address_is_ip4 (&t->client_ip) ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6,
    &t->client_ip, t->sw_if_index);
}

static void
pppoe_session_ip4_route_remove (pppoe_session_t *t)
{
  pppoe_client_fib_path_remove (
    t->decap_fib_index, ip46_address_is_ip4 (&t->client_ip) ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6,
    &t->client_ip, t->sw_if_index);
}

static void
pppoe_session_ip6_route_add (pppoe_session_t *t)
{
  u32 fib_index = pppoe_ip6_fib_index ();

  if (fib_index == ~0)
    return;

  pppoe_client_fib_path_add (fib_index, FIB_PROTOCOL_IP6, &t->client_ip6, t->sw_if_index);
}

static void
pppoe_session_ip6_route_remove (pppoe_session_t *t)
{
  u32 fib_index = pppoe_ip6_fib_index ();

  if (fib_index == ~0)
    return;

  pppoe_client_fib_path_remove (fib_index, FIB_PROTOCOL_IP6, &t->client_ip6, t->sw_if_index);
}

static void
pppoe_session_ip6_address_set (pppoe_session_t *t, const ip6_address_t *a6)
{
  if (t->client_ip6_set)
    pppoe_session_ip6_route_remove (t);

  ip6_address_copy (&t->client_ip6.ip6, a6);
  t->client_ip6_set = !ip6_address_is_unspecified (a6);

  if (t->client_ip6_set)
    pppoe_session_ip6_route_add (t);
}

static void
pppoe_session_ip4_address_set (pppoe_session_t *t, const ip46_address_t *addr4)
{
  if (t->client_ip4_set)
    pppoe_session_ip4_route_remove (t);

  ip46_address_copy (&t->client_ip, addr4);
  t->client_ip4_set = !ip46_address_is_zero (addr4);

  if (t->client_ip4_set)
    pppoe_session_ip4_route_add (t);
}

/* The interface identifier takes the low half of the address, and the bits of
 * the prefix the identifier does not cover come from the prefix. */
static void
pppoe_ip6_prefix_complete (ip6_address_t *addr6, const ip6_address_t *prefix, u8 prefix_len,
			   u64 ip6_ident)
{
  ip6_address_copy (addr6, prefix);
  clib_memcpy (addr6->as_u8 + 8, &ip6_ident, sizeof (ip6_ident));

  if (prefix_len < 128)
    addr6->as_u8[prefix_len / 8] &= (u8) (0xff << (8 - prefix_len % 8));
  if (prefix_len < 64)
    clib_memset (addr6->as_u8 + (prefix_len + 7) / 8, 0, (64 - (prefix_len + 7) / 8));
}

/*
 * The IPv6CP interface identifier is the low half of the client's link-local
 * address, so the client is reachable over the session from the moment the
 * identifier is known. The global prefix a router advertisement carries
 * completes that address, and replaces the link-local one.
 */
void
vnet_pppoe_ip6_ident_cb (void *arg)
{
  pppoe_ip6_ident_update_t update;
  pppoe_session_t *t;
  ip6_address_t addr6;
  ip6_address_t link_local_prefix = {
    .as_u64 = { clib_host_to_net_u64 (0xfe80ULL << 48), 0 },
  };

  clib_memcpy (&update, arg, sizeof (update));

  t = pppoe_session_find_by_hw_if_index (update.hw_if_index, update.session_id, update.generation);
  if (!t)
    return;

  t->ip6_ident = update.ip6_ident;
  t->ip6_ident_set = 1;

  /* fe80::/64 completed with the identifier */
  pppoe_ip6_prefix_complete (&addr6, &link_local_prefix, 64, t->ip6_ident);
  pppoe_session_ip6_address_set (t, &addr6);
}

/* A router advertisement carries the global prefix the control plane handed
 * to the client. */
void
vnet_pppoe_ip6_prefix_cb (void *arg)
{
  pppoe_ip6_prefix_t update;
  pppoe_session_t *t;
  ip6_address_t addr6;

  clib_memcpy (&update, arg, sizeof (update));

  t = pppoe_session_find_by_hw_if_index (update.hw_if_index, update.session_id, update.generation);
  if (!t)
    return;

  /* the advertisement completes what IPv6CP negotiated on this session */
  if (!t->ip6_ident_set)
    return;

  pppoe_ip6_prefix_complete (&addr6, &update.prefix, update.prefix_len, t->ip6_ident);
  pppoe_session_ip6_address_set (t, &addr6);
}

/* The client addresses outlive the session they were learned for: the
 * interface is reused without the route that pointed at it being removed, so
 * a reused interface gets the route back. */
static void
pppoe_session_fib_attach (pppoe_session_t *t)
{
  if (t->client_ip4_set)
    pppoe_session_ip4_route_add (t);

  if (t->client_ip6_set)
    pppoe_session_ip6_route_add (t);
}

/*
 * is_admin_up is the session's own view of whether it is up, written only by
 * the main thread and read by the data plane; the interface flag it mirrors
 * belongs to the interface, which outlives the session.
 */
static void
pppoe_session_attach (pppoe_main_t *pem, pppoe_session_t *t)
{
  vnet_main_t *vnm = pem->vnet_main;
  vnet_sw_interface_t *si;

  si = vnet_get_sw_interface (vnm, t->sw_if_index);
  si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
  vnet_sw_interface_set_flags (vnm, t->sw_if_index, VNET_SW_INTERFACE_FLAG_ADMIN_UP);
  vnet_set_interface_l3_output_node (vnm->vlib_main, t->sw_if_index, (u8 *) "tunnel-output");

  /* the routes belong to the addresses; a session created before its address
   * is negotiated has none yet, and the address installs its own */
  if (t->client_ip4_set || t->client_ip6_set)
    pppoe_session_fib_attach (t);

  /* a slot outlives the session that used it, so the echo ledger starts over
   * with the session, and the observations queued for the last one are told
   * apart by the stamp */
  t->generation++;
  t->lcp_echo_request_epoch = 0;
  t->lcp_echo_acked_epoch = 0;
  t->lcp_echo_outstanding = 0;
  t->lcp_echo_ended = 0;

  t->is_admin_up = 1;
}

/*
 * The addresses the session interface holds, walked along the per-interface
 * list rather than through foreach_ip_interface_address, which would follow an
 * unnumbered interface to another interface's addresses.
 *
 * The head is only this interface's own list while the interface is numbered.
 * vnet_sw_interface_update_unnumbered copies the head of the numbered
 * interface into the unnumbered one's slot, so an unnumbered session is handed
 * the addresses of the interface it borrows from. Those name a different
 * sw_if_index, and ip_interface_address_del refuses them without unlinking
 * anything, so a walk that only stopped on an empty head would delete the same
 * entry forever and leak an error per attempt until the heap ran out. The walk
 * therefore advances along the link it saved before the delete, rather than
 * re-reading a head the delete may have refused to move.
 */
static void
pppoe_ip4_addresses_clear (vnet_main_t *vnm, u32 sw_if_index)
{
  ip_lookup_main_t *lm = &ip4_main.lookup_main;
  ip_interface_address_t *ia;
  clib_error_t *error;
  u32 ia_index, next;

  if (sw_if_index >= vec_len (lm->if_address_pool_index_by_sw_if_index))
    return;

  ia_index = lm->if_address_pool_index_by_sw_if_index[sw_if_index];

  while (ia_index != ~0)
    {
      if (pool_is_free_index (lm->if_address_pool, ia_index))
	break;

      ia = pool_elt_at_index (lm->if_address_pool, ia_index);

      /* the list an unnumbered interface was handed belongs to another one */
      if (ia->sw_if_index != sw_if_index)
	break;

      /* the element goes away under the delete, so the link is read first */
      next = ia->next_this_sw_interface;

      error = ip4_add_del_interface_address (vnm->vlib_main, sw_if_index,
					     ip_interface_address_get_address (lm, ia),
					     ia->address_length, 1 /* is_del */);
      if (error)
	{
	  /* an address that cannot be removed is left where it is: the
	   * session is torn down either way, and repeating the call cannot
	   * make it removable */
	  clib_error_report (error);
	  break;
	}

      ia_index = next;
    }
}

static void
pppoe_ip6_addresses_clear (vnet_main_t *vnm, u32 sw_if_index)
{
  ip_lookup_main_t *lm = &ip6_main.lookup_main;
  ip_interface_address_t *ia;
  clib_error_t *error;
  u32 ia_index, next;

  if (sw_if_index >= vec_len (lm->if_address_pool_index_by_sw_if_index))
    return;

  ia_index = lm->if_address_pool_index_by_sw_if_index[sw_if_index];

  while (ia_index != ~0)
    {
      if (pool_is_free_index (lm->if_address_pool, ia_index))
	break;

      ia = pool_elt_at_index (lm->if_address_pool, ia_index);

      if (ia->sw_if_index != sw_if_index)
	break;

      next = ia->next_this_sw_interface;

      error = ip6_add_del_interface_address (vnm->vlib_main, sw_if_index,
					     ip_interface_address_get_address (lm, ia),
					     ia->address_length, 1 /* is_del */);
      if (error)
	{
	  clib_error_report (error);
	  break;
	}

      ia_index = next;
    }
}

/* A session interface is never deleted, only brought down and reused, so the
 * teardown stops at releasing what the session held and at putting back what
 * a new session must not inherit. */
static void
pppoe_session_detach (pppoe_main_t *pem, pppoe_session_t *t)
{
  vnet_main_t *vnm = pem->vnet_main;
  vnet_sw_interface_t *si;

  if (t->client_ip4_set)
    pppoe_session_ip4_route_remove (t);

  if (t->client_ip6_set)
    pppoe_session_ip6_route_remove (t);

  vnet_reset_interface_l3_output_node (vnm->vlib_main, t->sw_if_index);

  /*
   * An unnumbered interface reads the address list of the interface it
   * borrows from, and the teardown must not reach into that list: the
   * addresses there belong to the numbered interface, which outlives this
   * session. Unbind first, so the walk below sees the session's own list
   * rather than the one it was handed.
   */
  si = vnet_get_sw_interface (vnm, t->sw_if_index);
  if (si->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED)
    vnet_sw_interface_update_unnumbered (t->sw_if_index, ~0, 0 /* enable */);

  pppoe_ip4_addresses_clear (vnm, t->sw_if_index);
  pppoe_ip6_addresses_clear (vnm, t->sw_if_index);

  /*
   * The address belongs to the session, not to the slot it was held in: a
   * session released here leaves nothing of itself behind, and the next one
   * starts without an address and gets its own when one is negotiated. The
   * routes that name the address are gone by now, so the fields can go with
   * them.
   */
  clib_memset (&t->client_ip, 0, sizeof (t->client_ip));
  clib_memset (&t->client_ip6, 0, sizeof (t->client_ip6));
  t->client_ip4_set = 0;
  t->client_ip6_set = 0;

  /* the clears can grow the interface pools, so the interface is read again */
  si = vnet_get_sw_interface (vnm, t->sw_if_index);
  si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;
  vnet_sw_interface_set_flags (vnm, t->sw_if_index, 0 /* down */);

  t->is_admin_up = 0;
  t->ip6_ident_set = 0;
}

static u32
pppoe_session_alloc (pppoe_main_t *pem, vnet_pppoe_add_del_session_args_t *a,
		     vnet_hw_interface_t *encap_hi)
{
  vnet_main_t *vnm = pem->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  pppoe_session_t *t;
  vnet_hw_interface_t *hi;
  u32 hw_if_index, sw_if_index;

  pool_get_aligned (pem->sessions, t, CLIB_CACHE_LINE_BYTES);
  clib_memset (t, 0, sizeof (*t));

  /* copy from arg structure */
#define _(x) t->x = a->x;
  foreach_copy_field;
#undef _

  /* the slot counts its own sessions: the count in the argument names the
   * session an observation was made for, not the one being built here */
  t->generation = 0;

  clib_memcpy (t->local_mac, encap_hi->hw_address, 6);
  clib_memcpy (t->client_mac, a->client_mac, 6);

  if (vec_len (pem->free_pppoe_session_hw_if_indices) > 0)
    {
      hw_if_index =
	pem->free_pppoe_session_hw_if_indices[vec_len (pem->free_pppoe_session_hw_if_indices) - 1];
      vec_dec_len (pem->free_pppoe_session_hw_if_indices, 1);

      hi = vnet_get_hw_interface (vnm, hw_if_index);
      hi->dev_instance = t - pem->sessions;
      hi->hw_instance = hi->dev_instance;

      /* clear old stats of freed session before reuse */
      sw_if_index = hi->sw_if_index;
      vnet_interface_counter_lock (im);
      vlib_zero_combined_counter (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_TX],
				  sw_if_index);
      vlib_zero_combined_counter (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_RX],
				  sw_if_index);
      vlib_zero_simple_counter (&im->sw_if_counters[VNET_INTERFACE_COUNTER_DROP], sw_if_index);
      vnet_interface_counter_unlock (im);
    }
  else
    {
      hw_if_index = vnet_register_interface (vnm, pppoe_device_class.index, t - pem->sessions,
					     pppoe_hw_class.index, t - pem->sessions);
      hi = vnet_get_hw_interface (vnm, hw_if_index);
      sw_if_index = hi->sw_if_index;
    }

  t->hw_if_index = hw_if_index;
  t->sw_if_index = sw_if_index;

  vec_validate_init_empty (pem->session_index_by_sw_if_index, sw_if_index, ~0);
  pem->session_index_by_sw_if_index[sw_if_index] = t - pem->sessions;

  return sw_if_index;
}

/*
 * Releases a session and leaves its key in the table naming no session.
 * Removing the key would leave it absent while the interface it was on is
 * being handed to the next session, and a client that reconnects would then
 * find neither its old entry nor a new one; kept as ~0, the add that builds
 * the new session writes it back.
 *
 * A worker that looked the session up by interface is still holding the index
 * it read, so the slot is released only after the index no longer points at
 * it: once it is free, the next session to take it is a different client, and
 * the interface cannot be made to name that one.
 */
static void
pppoe_session_release (pppoe_main_t *pem, pppoe_session_t *t)
{
  pppoe_entry_key_t key;
  pppoe_entry_result_t result;
  u32 bucket;

  pppoe_session_detach (pem, t);

  result.raw = 0;
  result.fields.session_index = ~0;
  pppoe_update_1 (&pem->session_table, t->client_mac, clib_host_to_net_u16 (t->session_id), &key,
		  &bucket, &result);

  pem->session_index_by_sw_if_index[t->sw_if_index] = ~0;
  vec_add1 (pem->free_pppoe_session_hw_if_indices, t->hw_if_index);
  pool_put (pem->sessions, t);
}

int
vnet_pppoe_add_del_session (vnet_pppoe_add_del_session_args_t *a, u32 *sw_if_indexp)
{
  pppoe_main_t *pem = &pppoe_main;
  pppoe_session_t *t = 0;
  vnet_main_t *vnm = pem->vnet_main;
  u32 sw_if_index = ~0;
  u32 is_ip6 = a->is_ip6;
  u32 session_index;
  pppoe_entry_key_t cached_key;
  pppoe_entry_result_t cached_result;
  u32 bucket;
  pppoe_entry_key_t key;
  pppoe_entry_result_t result;
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *si;

  cached_key.raw = ~0;
  cached_result.raw = ~0; /* warning be gone */

  /*
   * The caller may name the data plane port the client is reached on; the
   * control plane does, because its session is created from a negotiation
   * frame rather than from a data frame, so the link table has nothing to say
   * about the client yet. The link table keeps moving with the client's
   * frames, so this is decided before a delete learns the frames' port, and a
   * delete of a session that is still there takes the port the session was
   * created on.
   */
  if (!a->is_add)
    {
      pppoe_lookup_1 (&pem->session_table, &cached_key, &cached_result, a->client_mac,
		      clib_host_to_net_u16 (a->session_id), &key, &bucket, &result);

      /* a key outlives the session it named, so it can lead to a free slot */
      if (result.fields.session_index != ~0 &&
	  !pool_is_free_index (pem->sessions, result.fields.session_index) &&
	  a->encap_if_index == ~0)
	{
	  t = pool_elt_at_index (pem->sessions, result.fields.session_index);
	  a->encap_if_index = t->encap_if_index;
	}
    }

  if (a->session_id == 0)
    return VNET_API_ERROR_INVALID_ARGUMENT;

  if (a->encap_if_index == ~0)
    {
      pppoe_lookup_1 (&pem->link_table, &cached_key, &cached_result, a->client_mac, 0, &key,
		      &bucket, &result);
      a->encap_if_index = result.fields.sw_if_index;
    }

  if (a->encap_if_index == ~0)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  si = vnet_get_sw_interface (vnm, a->encap_if_index);
  hi = vnet_get_hw_interface (vnm, si->hw_if_index);

  /* lookup session_table */
  pppoe_lookup_1 (&pem->session_table, &cached_key, &cached_result, a->client_mac,
		  clib_host_to_net_u16 (a->session_id), &key, &bucket, &result);

  /* the session the client already has, which learning must not decide */
  session_index = result.fields.session_index;

  /* learn client session */
  pppoe_learn_process (&pem->session_table, a->encap_if_index, &key, &cached_key, &bucket, &result);

  if (a->is_add)
    {
      /*
       * A session is built around a client address. IPCP and IPv6CP hand the
       * address over after the session exists, so an add that names both an
       * existing session and an address is the address arriving, not a second
       * session: it is applied to the session the client already has.
       */
      if (session_index != ~0)
	{
	  if (ip46_address_is_zero (&a->client_ip) && ip46_address_is_zero (&a->client_ip6))
	    return VNET_API_ERROR_TUNNEL_EXIST;

	  t = pool_elt_at_index (pem->sessions, session_index);

	  /*
	   * A queued observation names the session it was made for. The slot the
	   * client's key leads to may have been released and handed to the
	   * client's next connection since, and the count the slot keeps is what
	   * tells the two apart; applying the address to the next session would
	   * be reading a frame for one connection into another.
	   */
	  if (a->generation != ~0 && t->generation != a->generation)
	    return VNET_API_ERROR_NO_SUCH_ENTRY;

	  sw_if_index = t->sw_if_index;
	  goto address;
	}

      if (ip46_address_is_zero (&a->client_ip) && ip46_address_is_zero (&a->client_ip6))
	return VNET_API_ERROR_INVALID_ARGUMENT;

      /*if not set explicitly, default to ip4 */
      if (!pppoe_decap_next_is_valid (pem, is_ip6, a->decap_fib_index))
	return VNET_API_ERROR_INVALID_DECAP_NEXT;

      sw_if_index = pppoe_session_alloc (pem, a, hi);
      t = pppoe_session_find_by_sw_if_index (sw_if_index);

      /* the key can already be there with no session behind it, kept by the
       * delete of an earlier session, so the index of the session that took
       * the slot is written back whenever one is built */
      result.fields.session_index = t - pem->sessions;
      pppoe_update_1 (&pem->session_table, a->client_mac, clib_host_to_net_u16 (a->session_id),
		      &key, &bucket, &result);

      pppoe_session_attach (pem, t);

    address:
      if (!ip46_address_is_zero (&a->client_ip))
	pppoe_session_ip4_address_set (t, &a->client_ip);

      if (!ip46_address_is_zero (&a->client_ip6))
	pppoe_session_ip6_address_set (t, &a->client_ip6.ip6);

      /* a disabled fib leaves the route of the address to whoever owns it,
       * but the address itself still belongs to the session */
      if (a->disable_fib)
	{
	  if (t->client_ip4_set)
	    pppoe_session_ip4_route_remove (t);

	  if (t->client_ip6_set)
	    pppoe_session_ip6_route_remove (t);
	}
    }
  else
    {
      /*
       * A key that names no session is a client the table knows from its
       * control plane frames and whose session is already gone, either because
       * this branch released it earlier or because it never had one. Deleting
       * it again is what the caller asked for, not an error.
       */
      if (session_index == ~0 || pool_is_free_index (pem->sessions, session_index))
	return 0;

      t = pool_elt_at_index (pem->sessions, session_index);

      /*
       * A caller that named a count meant one session of that slot. The slot
       * the client's key leads to can have been released and handed to the
       * client's next connection since the caller read it, and the release
       * belongs to the session that was asked for, not to the one that took
       * its place; that session is already gone, which is what a second
       * delete of it answers.
       *
       * No caller in this tree can reach the mismatch: the only one that
       * names a count, pppoe_delete_collect_cb, reads the count under the
       * barrier the release is made under, and nothing releases a session
       * between the read and this comparison. The test is kept so that a
       * delete queued before the workers were parked cannot release the
       * client's next connection.
       */
      if (a->generation != ~0 && t->generation != a->generation)
	return 0;

      sw_if_index = t->sw_if_index;

      pppoe_session_release (pem, t);
    }

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  return 0;
}

/* A data plane node hands what it saw to the main thread, which changes the
 * session table and the interface database under the barrier. */
void
vnet_pppoe_add_del_session_cb (void *arg)
{
  vnet_pppoe_add_del_session_args_t a;

  clib_memcpy (&a, arg, sizeof (a));

  int rv = vnet_pppoe_add_del_session (&a, NULL);
  if (rv)
    clib_warning ("PPPoE session %u for client %U: %U", a.session_id, format_ethernet_address,
		  a.client_mac, format_vnet_api_errno, rv);
}

/* A session that can no longer carry traffic is torn down the way a delete
 * tears it down. Only the threads that are parked may change the table, so the
 * frame that brings the session down marks it down and a callback tears it
 * down once the workers are parked. */
void
vnet_pppoe_session_teardown (pppoe_session_t *t)
{
  pppoe_main_t *pem = &pppoe_main;
  pppoe_session_teardown_t teardown = {
    .hw_if_index = t->hw_if_index,
    .session_id = t->session_id,
    /* the teardown names the session it was decided for, so it does not land
     * on the next session the interface is handed to */
    .generation = t->generation,
  };

  vnet_sw_interface_set_flags (pem->vnet_main, t->sw_if_index, 0 /* down */);
  t->is_admin_up = 0;

  if (vlib_worker_thread_barrier_held ())
    vnet_pppoe_padt_cb (&teardown);
  else
    vlib_rpc_call_main_thread (vnet_pppoe_padt_cb, (u8 *) &teardown, sizeof (teardown));
}

/*
 * The ledger counts requests the client has not answered: it is the number of
 * requests since the last one answered, so it is the distance between the
 * requests seen and the last one a reply named.
 *
 * A reply is credited by the epoch it names, which is the request the data
 * plane last saw counted when it queued the frame, so the reply to request k is
 * credited to request k whether it is drained before or after request k+1.
 *
 * What the credit cannot do is arrive after the request that judges the
 * session. With PPPOE_LCP_ECHO_MISSES requests allowed to go unanswered, a
 * client is only torn down once that many requests have been sent and no reply
 * for any of them has been drained, so a client that answers every request but
 * whose replies trail the requests by more than the limit's worth is still torn
 * down. The limit bounds how long a session outlives the concentrator, and only
 * within it is the outcome independent of drain order.
 */
void
vnet_pppoe_lcp_echo_cb (void *arg)
{
  pppoe_lcp_echo_t echo;
  pppoe_session_t *t;
  u32 request_epoch;

  clib_memcpy (&echo, arg, sizeof (echo));

  t = pppoe_session_find_by_hw_if_index (echo.hw_if_index, echo.session_id, echo.generation);
  if (!t || !t->is_admin_up)
    return;

  /* a reply answers the request it names, and only that one: replies are
   * queued in the order the concentrator sent them, so the epoch says which
   * request is answered */
  if (!echo.is_request)
    {
      /* the ledger is judged at the request, so a reply that would only lower
       * it cannot save a session the last request ended */
      if (t->lcp_echo_ended)
	return;

      request_epoch = clib_atomic_load_acq_n (&t->lcp_echo_request_epoch);

      if (echo.request_epoch != t->lcp_echo_acked_epoch && echo.request_epoch <= request_epoch)
	t->lcp_echo_acked_epoch = echo.request_epoch;

      t->lcp_echo_outstanding =
	clib_min (request_epoch - t->lcp_echo_acked_epoch, (u32) PPPOE_LCP_ECHO_MISSES);
      return;
    }

  if (t->lcp_echo_ended)
    return;

  request_epoch = ++t->lcp_echo_request_epoch;

  /* the data plane reads this to name the request its reply answers, so it is
   * published after the count is in place */
  clib_atomic_store_rel_n (&t->lcp_echo_request_epoch, request_epoch);

  t->lcp_echo_outstanding =
    clib_min (request_epoch - t->lcp_echo_acked_epoch, (u32) PPPOE_LCP_ECHO_MISSES);

  /* a session that stops answering the echo of the access concentrator is
   * gone once the requests the client left unanswered reach the limit; the
   * reply to this request may still be queued, which is what the limit is
   * for */
  if (t->lcp_echo_outstanding >= PPPOE_LCP_ECHO_MISSES)
    {
      t->lcp_echo_ended = 1;
      vnet_pppoe_session_teardown (t);
    }
}

/* A PADT ends the session it names, whether the control plane asked for it or
 * the access concentrator did. It also applies the teardown a data plane node
 * asked for, once the session the request named is confirmed to be the one
 * still on that interface. */
void
vnet_pppoe_padt_cb (void *arg)
{
  pppoe_session_teardown_t teardown;
  pppoe_session_t *t;

  clib_memcpy (&teardown, arg, sizeof (teardown));

  t = pppoe_session_find_by_hw_if_index (teardown.hw_if_index, teardown.session_id,
					 teardown.generation);
  if (!t)
    return;

  pppoe_session_release (&pppoe_main, t);
}

typedef struct
{
  /* the sessions a table walk found, deleted once the walk is over */
  vnet_pppoe_add_del_session_args_t *sessions;

  u32 deleted;
  u32 failed;
} pppoe_delete_walk_ctx_t;

/* Deleting a session rewrites the session table, so the walk only collects and
 * the deletions happen once it has finished. */
static int
pppoe_delete_collect_cb (BVT (clib_bihash_kv) * kvp, void *arg)
{
  pppoe_main_t *pem = &pppoe_main;
  pppoe_delete_walk_ctx_t *ctx = arg;
  pppoe_entry_key_t key;
  pppoe_entry_result_t result;
  pppoe_session_t *t;

  key.raw = kvp->key;
  result.raw = kvp->value;

  if (result.fields.session_index == ~0 ||
      pool_is_free_index (pem->sessions, result.fields.session_index))
    return BIHASH_WALK_CONTINUE;

  t = pool_elt_at_index (pem->sessions, result.fields.session_index);

  vnet_pppoe_add_del_session_args_t a = {
    .is_add = 0,
    .session_id = t->session_id,
    .encap_if_index = t->encap_if_index,
    .decap_fib_index = t->decap_fib_index,
    .client_ip = t->client_ip,
    /* the delete names the session this walk read, count included, so the
     * slot the client's key leads to is not released when it is no longer
     * that session */
    .generation = t->generation,
  };
  clib_memcpy (a.client_mac, key.fields.mac, 6);

  vec_add1 (ctx->sessions, a);

  return BIHASH_WALK_CONTINUE;
}

static void
pppoe_delete_all_sessions (void)
{
  pppoe_main_t *pem = &pppoe_main;
  pppoe_delete_walk_ctx_t ctx = { 0 };
  vnet_pppoe_add_del_session_args_t *a;

  /*
   * A worker reads a session index and then the slot it names, and one of the
   * deletions below can release that slot between the two reads, so the walk and
   * the deletions run with the workers parked. The barrier is held around them
   * rather than taken by one deletion: a worker blocked on the barrier is not
   * making the first read.
   *
   * Taking the barrier requires the main thread, and the barrier sync asserts
   * that rather than checking it, so this runs only on the thread the CLI
   * process runs on; a caller on any other thread has to queue the work the way
   * vnet_pppoe_session_teardown does.
   */
  vlib_worker_thread_barrier_sync (vlib_get_main ());

  BV (clib_bihash_foreach_key_value_pair)
  (&pem->session_table, pppoe_delete_collect_cb, &ctx);

  vec_foreach (a, ctx.sessions)
    {
      if (vnet_pppoe_add_del_session (a, NULL))
	ctx.failed++;
      else
	ctx.deleted++;
    }

  vlib_worker_thread_barrier_release (vlib_get_main ());

  if (ctx.failed)
    clib_warning ("%u of %u PPPoE sessions could not be deleted", ctx.failed,
		  ctx.deleted + ctx.failed);

  vec_free (ctx.sessions);
}

static clib_error_t *
pppoe_add_del_session_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u16 session_id = 0;
  ip46_address_t client_ip;
  u8 is_add = 1;
  u8 client_ip_set = 0;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  u8 disable_fib = 0;
  /* the command names the client, not the port: the port is resolved through
   * the link table, the way master resolved every add */
  u32 encap_if_index = ~0;
  u32 decap_fib_index = 0;
  u8 client_mac[6] = { 0 };
  u8 client_mac_set = 0;
  int rv;
  u32 tmp;
  vnet_pppoe_add_del_session_args_t _a, *a = &_a;
  u32 session_sw_if_index;
  clib_error_t *error = NULL;

  /* Cant "universally zero init" (={0}) due to GCC bug 53119 */
  clib_memset (&client_ip, 0, sizeof client_ip);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (line_input, "disable-fib"))
	{
	  disable_fib = 1;
	}
      else if (unformat (line_input, "session-id %d", &session_id))
	;
      else if (unformat (line_input, "client-ip %U", unformat_ip4_address, &client_ip.ip4))
	{
	  client_ip_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "client-ip %U", unformat_ip6_address, &client_ip.ip6))
	{
	  client_ip_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "decap-vrf-id %d", &tmp))
	{
	  if (ipv6_set)
	    decap_fib_index = fib_table_find (FIB_PROTOCOL_IP6, tmp);
	  else
	    decap_fib_index = fib_table_find (FIB_PROTOCOL_IP4, tmp);

	  if (decap_fib_index == ~0)
	    {
	      error = clib_error_return (0, "nonexistent decap fib id %d", tmp);
	      goto done;
	    }
	}
      else if (unformat (line_input, "client-mac %U", unformat_ethernet_address, client_mac))
	client_mac_set = 1;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'", format_unformat_error, line_input);
	  goto done;
	}
    }

  if (client_ip_set == 0)
    {
      error = clib_error_return (0, "session client ip address not specified");
      goto done;
    }

  if (ipv4_set && ipv6_set)
    {
      error = clib_error_return (0, "both IPv4 and IPv6 addresses specified");
      goto done;
    }

  if (client_mac_set == 0)
    {
      error = clib_error_return (0, "session client mac not specified");
      goto done;
    }

  clib_memset (a, 0, sizeof (*a));

  a->generation = ~0;
  a->is_add = is_add;
  a->is_ip6 = ipv6_set;
  a->disable_fib = disable_fib;

#define _(x) a->x = x;
  foreach_copy_field;
#undef _

  clib_memcpy (a->client_mac, client_mac, 6);

  if (ipv6_set)
    ip46_address_copy (&a->client_ip6, &client_ip);
  else
    ip46_address_copy (&a->client_ip, &client_ip);

  rv = vnet_pppoe_add_del_session (a, &session_sw_if_index);

  switch (rv)
    {
    case 0:
      if (is_add)
	vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main (),
			 session_sw_if_index);
      break;

    case VNET_API_ERROR_TUNNEL_EXIST:
      error = clib_error_return (0, "session already exists...");
      goto done;

    default:
      error = clib_error_return (0, "vnet_pppoe_add_del_session returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * Add or delete a PPPoE Session.
 *
 * @cliexpar
 * Example of how to create a PPPoE Session:
 * @cliexcmd{create pppoe session client-ip 10.0.3.1 session-id 13
 *             client-mac 00:01:02:03:04:05 }
 * Example of how to delete a PPPoE Session:
 * @cliexcmd{create pppoe session client-ip 10.0.3.1 session-id 13
 *             client-mac 00:01:02:03:04:05 del }
 ?*/
VLIB_CLI_COMMAND (create_pppoe_session_command, static) = {
  .path = "create pppoe session",
  .short_help = "create pppoe session client-ip <client-ip> session-id <nn>"
		" client-mac <client-mac> [decap-vrf-id <nn>] [del] [disable-fib]",
  .function = pppoe_add_del_session_command_fn,
};

static clib_error_t *
delete_all_pppoe_sessions_command_fn (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *cmd)
{
  pppoe_delete_all_sessions ();

  return 0;
}

/*?
 * Delete every PPPoE session.
 *
 * @cliexpar
 * Example of how to delete all PPPoE sessions:
 * @cliexcmd{delete pppoe sessions}
 ?*/
VLIB_CLI_COMMAND (delete_all_pppoe_sessions_command, static) = {
  .path = "delete pppoe sessions",
  .short_help = "delete every pppoe session, with the workers parked",
  .function = delete_all_pppoe_sessions_command_fn,
};

static clib_error_t *
show_pppoe_session_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  pppoe_main_t *pem = &pppoe_main;
  pppoe_session_t *t;

  if (pool_elts (pem->sessions) == 0)
    {
      vlib_cli_output (vm, "No pppoe sessions configured...");
      return 0;
    }

  pool_foreach (t, pem->sessions)
    {
      vlib_cli_output (vm, "%U", format_pppoe_session, t);
    }

  return 0;
}

/*?
 * Display all the PPPoE Session entries.
 *
 * @cliexpar
 * Example of how to display the PPPoE Session entries:
 * @cliexstart{show pppoe session}
 * [0] sw-if-index 5 session-id 13 client-ip 10.0.3.1 encap-if-index 0
 *     decap-fib-index 13
 *     local-mac a0:b0:c0:d0:e0:f0  client-mac 00:01:02:03:04:05
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (show_pppoe_session_command, static) = {
  .path = "show pppoe session",
  .short_help = "show pppoe session",
  .function = show_pppoe_session_command_fn,
};

typedef struct pppoe_show_walk_ctx_t_
{
  vlib_main_t *vm;
  u32 total_entries;
} pppoe_show_walk_ctx_t;

static int
pppoe_show_walk_cb (BVT (clib_bihash_kv) * kvp, void *arg)
{
  pppoe_show_walk_ctx_t *ctx = arg;
  pppoe_entry_result_t result;
  pppoe_entry_key_t key;

  key.raw = kvp->key;
  result.raw = kvp->value;

  if (ctx->total_entries == 0)
    vlib_cli_output (ctx->vm, "  %=19s%=12s%=13s%=14s", "Mac-Address", "session_id", "sw_if_index",
		     "session_index");

  vlib_cli_output (ctx->vm, "  %=19U%=12d%=13d%=14d", format_ethernet_address, key.fields.mac,
		   clib_net_to_host_u16 (key.fields.session_id),
		   result.fields.sw_if_index == ~0 ? -1 : result.fields.sw_if_index,
		   result.fields.session_index == ~0 ? -1 : result.fields.session_index);
  ctx->total_entries++;

  return (BIHASH_WALK_CONTINUE);
}

static void
pppoe_show_table (vlib_main_t *vm, char *title, BVT (clib_bihash) * table)
{
  pppoe_show_walk_ctx_t ctx = {
    .vm = vm,
  };

  vlib_cli_output (vm, "%s", title);
  BV (clib_bihash_foreach_key_value_pair) (table, pppoe_show_walk_cb, &ctx);

  if (ctx.total_entries == 0)
    vlib_cli_output (vm, "  no entries");
}

/** Display the contents of the PPPoE Fib. */
static clib_error_t *
show_pppoe_fib_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  pppoe_main_t *pem = &pppoe_main;

  pppoe_show_table (vm, "pppoe session table", &pem->session_table);

  return 0;
}

/*?
 * This command displays the MAC Address entries of the PPPoE FIB table.
 * Output can be filtered to just get the number of MAC Addresses or display
 * each MAC Address.
 *
 * @cliexpar
 * Example of how to display the number of MAC Address entries in the PPPoE
 * FIB table:
 * @cliexstart{show pppoe fib}
 *    Mac Address    session_id    Interface         sw_if_index session_index
 * 52:54:00:53:18:33   1        GigabitEthernet0/8/0      2          0
 * 52:54:00:53:18:55   2        GigabitEthernet0/8/1      3          1
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_pppoe_fib_command, static) = {
  .path = "show pppoe fib",
  .short_help = "show pppoe fib",
  .function = show_pppoe_fib_command_fn,
};

/*?
 * Display the control plane and data plane mapping of the PPPoE FIB: the link
 * table maps a client MAC address to the interface it was seen on, the session
 * table maps a client MAC address and session ID to the session built for it.
 *
 * @cliexpar
 * Example of how to display the PPPoE mappings:
 * @cliexstart{show pppoe map}
 * pppoe link table
 *   Mac-Address    session_id    sw_if_index    session_index
 * 52:54:00:53:18:33   0         2              -1
 * pppoe session table
 *   Mac-Address    session_id    sw_if_index    session_index
 * 52:54:00:53:18:33   1         2              0
 * @cliexend
 ?*/
static clib_error_t *
show_pppoe_map_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  pppoe_main_t *pem = &pppoe_main;

  pppoe_show_table (vm, "pppoe link table", &pem->link_table);
  pppoe_show_table (vm, "pppoe session table", &pem->session_table);

  return 0;
}

VLIB_CLI_COMMAND (show_pppoe_map_command, static) = {
  .path = "show pppoe map",
  .short_help = "show pppoe map",
  .function = show_pppoe_map_command_fn,
};

static clib_error_t *
pppoe_config (vlib_main_t *vm, unformat_input_t *input)
{
  pppoe_main_t *pem = &pppoe_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable-auto-discovery"))
	pem->is_auto_discovery = 1;
      else
	return clib_error_return (0, "invalid pppoe option: '%U'", format_unformat_error, input);
    }

  return 0;
}

VLIB_CONFIG_FUNCTION (pppoe_config, "pppoe");

clib_error_t *
pppoe_init (vlib_main_t *vm)
{
  pppoe_main_t *pem = &pppoe_main;

  pem->vnet_main = vnet_get_main ();
  pem->vlib_main = vm;

  /* Create the hash table  */
  BV (clib_bihash_init) (&pem->link_table, "pppoe link table", PPPOE_NUM_BUCKETS,
			 PPPOE_MEMORY_SIZE);

  BV (clib_bihash_init) (&pem->session_table, "pppoe session table", PPPOE_NUM_BUCKETS,
			 PPPOE_MEMORY_SIZE);

  ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_SESSION, pppoe_input_node.index);

  ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_DISCOVERY, pppoe_cp_dispatch_node.index);

  pppoe_fib_src = fib_source_allocate ("pppoe", FIB_SOURCE_PRIORITY_HI, FIB_SOURCE_BH_API);

  return 0;
}

VLIB_INIT_FUNCTION (pppoe_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "PPP over Ethernet (PPPoE)",
};
