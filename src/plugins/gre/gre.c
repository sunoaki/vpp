/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2012 Cisco and/or its affiliates.
 */

/* gre.c: gre */

#include <vnet/vnet.h>
#include <gre/gre.h>
#include <vnet/adj/adj_delegate.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/fib/fib_types.h>
#include <vnet/tunnel/tunnel_dp.h>
#include <vpp/app/version.h>
#include <vnet/plugin/plugin.h>

extern gre_main_t gre_main;

#ifndef CLIB_MARCH_VARIANT
gre_main_t gre_main;

typedef struct
{
  union
  {
    ip4_and_gre_header_t ip4_and_gre;
    u64 as_u64[3];
  };
} ip4_and_gre_union_t;

typedef struct
{
  union
  {
    ip6_and_gre_header_t ip6_and_gre;
    u64 as_u64[3];
  };
} ip6_and_gre_union_t;
#endif /* CLIB_MARCH_VARIANT */

/* Packet trace structure */
typedef struct
{
  /* Tunnel-id / index in tunnel vector */
  u32 tunnel_id;

  /* pkt length */
  u32 length;

  /* tunnel ip addresses */
  ip46_address_t src;
  ip46_address_t dst;
} gre_tx_trace_t;

extern u8 *format_gre_tx_trace (u8 *s, va_list *args);

#ifndef CLIB_MARCH_VARIANT
u8 *
format_gre_tx_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gre_tx_trace_t *t = va_arg (*args, gre_tx_trace_t *);

  s = format (s, "GRE: tunnel %d len %d src %U dst %U", t->tunnel_id,
	      t->length, format_ip46_address, &t->src, IP46_TYPE_ANY,
	      format_ip46_address, &t->dst, IP46_TYPE_ANY);
  return s;
}

u8 *
format_gre_protocol (u8 *s, va_list *args)
{
  gre_protocol_t p = va_arg (*args, u32);
  gre_main_t *gm = &gre_main;
  gre_protocol_info_t *pi = gre_get_protocol_info (gm, p);

  if (pi)
    s = format (s, "%s", pi->name);
  else
    s = format (s, "0x%04x", p);

  return s;
}

u8 *
format_gre_header_with_length (u8 *s, va_list *args)
{
  gre_main_t *gm = &gre_main;
  gre_header_t *h = va_arg (*args, gre_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  gre_protocol_t p = clib_net_to_host_u16 (h->protocol);
  u32 indent, header_bytes;

  header_bytes = sizeof (h[0]);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "gre header truncated");

  indent = format_get_indent (s);

  s = format (s, "GRE %U", format_gre_protocol, p);

  if (max_header_bytes != 0 && header_bytes < max_header_bytes)
    {
      gre_protocol_info_t *pi = gre_get_protocol_info (gm, p);
      vlib_node_t *node = vlib_get_node (gm->vlib_main, pi->node_index);
      if (node->format_buffer)
	s =
	  format (s, "\n%U%U", format_white_space, indent, node->format_buffer,
		  (void *) (h + 1), max_header_bytes - header_bytes);
    }

  return s;
}

u8 *
format_gre_header (u8 *s, va_list *args)
{
  gre_header_t *h = va_arg (*args, gre_header_t *);
  return format (s, "%U", format_gre_header_with_length, h, 0);
}

/* Returns gre protocol as an int in host byte order. */
uword
unformat_gre_protocol_host_byte_order (unformat_input_t *input, va_list *args)
{
  u16 *result = va_arg (*args, u16 *);
  gre_main_t *gm = &gre_main;
  int i;

  /* Named type. */
  if (unformat_user (input, unformat_vlib_number_by_name,
		     gm->protocol_info_by_name, &i))
    {
      gre_protocol_info_t *pi = vec_elt_at_index (gm->protocol_infos, i);
      *result = pi->protocol;
      return 1;
    }

  return 0;
}

uword
unformat_gre_protocol_net_byte_order (unformat_input_t *input, va_list *args)
{
  u16 *result = va_arg (*args, u16 *);
  if (!unformat_user (input, unformat_gre_protocol_host_byte_order, result))
    return 0;
  *result = clib_host_to_net_u16 ((u16) *result);
  return 1;
}

uword
unformat_gre_header (unformat_input_t *input, va_list *args)
{
  u8 **result = va_arg (*args, u8 **);
  gre_header_t _h, *h = &_h;
  u16 p;

  if (!unformat (input, "%U", unformat_gre_protocol_host_byte_order, &p))
    return 0;

  h->protocol = clib_host_to_net_u16 (p);

  /* Add header to result. */
  {
    void *p;
    u32 n_bytes = sizeof (h[0]);

    vec_add2 (*result, p, n_bytes);
    clib_memcpy (p, h, n_bytes);
  }

  return 1;
}

static int
gre_proto_from_vnet_link (vnet_link_t link)
{
  switch (link)
    {
    case VNET_LINK_IP4:
      return (GRE_PROTOCOL_ip4);
    case VNET_LINK_IP6:
      return (GRE_PROTOCOL_ip6);
    case VNET_LINK_MPLS:
      return (GRE_PROTOCOL_mpls_unicast);
    case VNET_LINK_ETHERNET:
      return (GRE_PROTOCOL_teb);
    case VNET_LINK_ARP:
      return (GRE_PROTOCOL_arp);
    case VNET_LINK_NSH:
      ASSERT (0);
      break;
    }
  ASSERT (0);
  return (GRE_PROTOCOL_ip4);
}

/*
 * The mapping holds an entry for the tunnel's own interface only, so a
 * sub-interface of a tunnel is not one of ours; indexing the vector with such
 * an index reads past its end and has to be rejected first.
 */
static gre_tunnel_t *
gre_tunnel_find_by_sw_if_index (u32 sw_if_index)
{
  gre_main_t *gm = &gre_main;
  u32 ti;

  if (vec_len (gm->tunnel_index_by_sw_if_index) <= sw_if_index)
    return (0);

  ti = gm->tunnel_index_by_sw_if_index[sw_if_index];

  if (~0 == ti)
    /* not one of ours */
    return (0);

  if (pool_is_free_index (gm->tunnels, ti))
    return (0);

  return (pool_elt_at_index (gm->tunnels, ti));
}

static u8 *
gre_build_rewrite (vnet_main_t *vnm, u32 sw_if_index, vnet_link_t link_type,
		   const void *dst_address)
{
  const ip46_address_t *dst;
  ip4_and_gre_header_t *h4;
  ip6_and_gre_header_t *h6;
  gre_header_t *gre;
  u8 *rewrite = NULL;
  gre_tunnel_t *t;
  u8 is_ipv6;

  dst = dst_address;
  t = gre_tunnel_find_by_sw_if_index (sw_if_index);

  if (0 == t)
    /* not one of ours */
    return (0);

  is_ipv6 = t->tunnel_dst.fp_proto == FIB_PROTOCOL_IP6 ? 1 : 0;

  if (!is_ipv6)
    {
      /* Allocate space for maximum header size including key */
      if (gre_key_is_valid (t->gre_key))
	vec_validate (rewrite, sizeof (*h4) + sizeof (gre_key_t) - 1);
      else
	vec_validate (rewrite, sizeof (*h4) - 1);
      h4 = (ip4_and_gre_header_t *) rewrite;
      gre = &h4->gre;
      h4->ip4.ip_version_and_header_length = 0x45;
      h4->ip4.ttl = 254;
      h4->ip4.protocol = IP_PROTOCOL_GRE;
      /* fixup ip4 header length and checksum after-the-fact */
      h4->ip4.src_address.as_u32 = t->tunnel_src.ip4.as_u32;
      h4->ip4.dst_address.as_u32 = dst->ip4.as_u32;
      h4->ip4.checksum = ip4_header_checksum (&h4->ip4);
    }
  else
    {
      /* Allocate space for maximum header size including key */
      if (gre_key_is_valid (t->gre_key))
	vec_validate (rewrite, sizeof (*h6) + sizeof (gre_key_t) - 1);
      else
	vec_validate (rewrite, sizeof (*h6) - 1);
      h6 = (ip6_and_gre_header_t *) rewrite;
      gre = &h6->gre;
      h6->ip6.ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (6 << 28);
      h6->ip6.hop_limit = 255;
      h6->ip6.protocol = IP_PROTOCOL_GRE;
      /* fixup ip6 header length and checksum after-the-fact */
      h6->ip6.src_address.as_u64[0] = t->tunnel_src.ip6.as_u64[0];
      h6->ip6.src_address.as_u64[1] = t->tunnel_src.ip6.as_u64[1];
      h6->ip6.dst_address.as_u64[0] = dst->ip6.as_u64[0];
      h6->ip6.dst_address.as_u64[1] = dst->ip6.as_u64[1];
    }

  if (PREDICT_FALSE (t->type == GRE_TUNNEL_TYPE_ERSPAN))
    {
      gre->protocol = clib_host_to_net_u16 (GRE_PROTOCOL_erspan);
      gre->flags_and_version = clib_host_to_net_u16 (GRE_FLAGS_SEQUENCE);
    }
  else
    {
      gre->protocol =
	clib_host_to_net_u16 (gre_proto_from_vnet_link (link_type));
      gre->flags_and_version = 0; // Clear flags first
      /* Add key only for non-ERSPAN tunnels */
      if (gre_key_is_valid (t->gre_key))
	{
	  gre_header_with_key_t *grek = (gre_header_with_key_t *) gre;
	  grek->flags_and_version = clib_host_to_net_u16 (GRE_FLAGS_KEY);
	  grek->key = clib_host_to_net_u32 (t->gre_key);
	}
    }
  return (rewrite);
}

static void
gre44_fixup (vlib_main_t *vm, const ip_adjacency_t *adj, vlib_buffer_t *b0,
	     const void *data)
{
  tunnel_encap_decap_flags_t flags;
  ip4_and_gre_header_t *ip0;

  ip0 = vlib_buffer_get_current (b0);
  flags = pointer_to_uword (data);

  /* Fixup the checksum and len fields in the GRE tunnel encap
   * that was applied at the midchain node */
  ip0->ip4.length =
    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
  tunnel_encap_fixup_4o4 (flags, (ip4_header_t *) ((u8 *) ip0 + adj->rewrite_header.data_bytes),
			  &ip0->ip4);
  ip0->ip4.checksum = ip4_header_checksum (&ip0->ip4);
}

static void
gre64_fixup (vlib_main_t *vm, const ip_adjacency_t *adj, vlib_buffer_t *b0,
	     const void *data)
{
  tunnel_encap_decap_flags_t flags;
  ip4_and_gre_header_t *ip0;

  ip0 = vlib_buffer_get_current (b0);
  flags = pointer_to_uword (data);

  /* Fixup the checksum and len fields in the GRE tunnel encap
   * that was applied at the midchain node */
  ip0->ip4.length =
    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
  tunnel_encap_fixup_6o4 (flags, (ip6_header_t *) ((u8 *) ip0 + adj->rewrite_header.data_bytes),
			  &ip0->ip4);
  ip0->ip4.checksum = ip4_header_checksum (&ip0->ip4);
}

static void
grex4_fixup (vlib_main_t *vm, const ip_adjacency_t *adj, vlib_buffer_t *b0,
	     const void *data)
{
  ip4_header_t *ip0;

  ip0 = vlib_buffer_get_current (b0);

  /* Fixup the checksum and len fields in the GRE tunnel encap
   * that was applied at the midchain node */
  ip0->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
  ip0->checksum = ip4_header_checksum (ip0);
}

static void
gre46_fixup (vlib_main_t *vm, const ip_adjacency_t *adj, vlib_buffer_t *b0,
	     const void *data)
{
  tunnel_encap_decap_flags_t flags;
  ip6_and_gre_header_t *ip0;

  ip0 = vlib_buffer_get_current (b0);
  flags = pointer_to_uword (data);

  /* Fixup the payload length field in the GRE tunnel encap that was applied
   * at the midchain node */
  ip0->ip6.payload_length = clib_host_to_net_u16 (
    vlib_buffer_length_in_chain (vm, b0) - sizeof (ip0->ip6));
  tunnel_encap_fixup_4o6 (flags, b0, (ip4_header_t *) ((u8 *) ip0 + adj->rewrite_header.data_bytes),
			  &ip0->ip6);
}

static void
gre66_fixup (vlib_main_t *vm, const ip_adjacency_t *adj, vlib_buffer_t *b0,
	     const void *data)
{
  tunnel_encap_decap_flags_t flags;
  ip6_and_gre_header_t *ip0;

  ip0 = vlib_buffer_get_current (b0);
  flags = pointer_to_uword (data);

  /* Fixup the payload length field in the GRE tunnel encap that was applied
   * at the midchain node */
  ip0->ip6.payload_length = clib_host_to_net_u16 (
    vlib_buffer_length_in_chain (vm, b0) - sizeof (ip0->ip6));
  tunnel_encap_fixup_6o6 (flags, (ip6_header_t *) ((u8 *) ip0 + adj->rewrite_header.data_bytes),
			  &ip0->ip6);
}

static void
grex6_fixup (vlib_main_t *vm, const ip_adjacency_t *adj, vlib_buffer_t *b0,
	     const void *data)
{
  ip6_and_gre_header_t *ip0;

  ip0 = vlib_buffer_get_current (b0);

  /* Fixup the payload length field in the GRE tunnel encap that was applied
   * at the midchain node */
  ip0->ip6.payload_length = clib_host_to_net_u16 (
    vlib_buffer_length_in_chain (vm, b0) - sizeof (ip0->ip6));
}

/**
 * return the appropriate fixup function given the overlay (link-type) and
 * underlay (fproto) combination
 */
static adj_midchain_fixup_t
gre_get_fixup (fib_protocol_t fproto, vnet_link_t lt)
{
  if (fproto == FIB_PROTOCOL_IP6 && lt == VNET_LINK_IP6)
    return (gre66_fixup);
  if (fproto == FIB_PROTOCOL_IP6 && lt == VNET_LINK_IP4)
    return (gre46_fixup);
  if (fproto == FIB_PROTOCOL_IP4 && lt == VNET_LINK_IP6)
    return (gre64_fixup);
  if (fproto == FIB_PROTOCOL_IP4 && lt == VNET_LINK_IP4)
    return (gre44_fixup);
  if (fproto == FIB_PROTOCOL_IP6)
    return (grex6_fixup);
  if (fproto == FIB_PROTOCOL_IP4)
    return (grex4_fixup);

  ASSERT (0);
  return (gre44_fixup);
}

/*
 * The rewrite of an adjacency of a tunnel is the tunnel's outer header. Its
 * length is fixed by the outer protocol and by whether the tunnel carries a
 * key.
 */
static u32
gre_rewrite_len (const gre_tunnel_t *t)
{
  u32 len;

  if (t->tunnel_dst.fp_proto == FIB_PROTOCOL_IP6)
    len = sizeof (ip6_and_gre_header_t);
  else
    len = sizeof (ip4_and_gre_header_t);

  if (gre_key_is_valid (t->gre_key))
    len += sizeof (gre_key_t);

  return (len);
}

/*
 * An L3 tunnel carries IP or MPLS behind its outer header. A non-L3 tunnel
 * carries the ethernet header of its link type. An adjacency of the other
 * kind would be given a GRE protocol it does not transport.
 */
static u8
gre_link_type_matches (const gre_tunnel_t *t, vnet_link_t link_type)
{
  if (GRE_TUNNEL_TYPE_L3 == t->type)
    return (VNET_LINK_ETHERNET != link_type);

  return (VNET_LINK_ETHERNET == link_type);
}

/*
 * Build the rewrite that stacks an adjacency's payload behind the tunnel's
 * outer header. The length is fixed by the outer protocol and the key alone,
 * so a rewrite of a different length, or one built for a link type the tunnel
 * does not carry, does not belong to this tunnel. Both cases warn once and
 * return NULL, leaving the adjacency without a rewrite; its caller stacks it
 * on the drop, so no packet leaves behind a header of the wrong kind or size.
 */
static u8 *
gre_build_midchain_rewrite (vnet_main_t *vnm, u32 sw_if_index, gre_tunnel_t *t,
			    vnet_link_t link_type, const ip46_address_t *dst)
{
  u8 *rewrite;

  rewrite = NULL;

  if (gre_link_type_matches (t, link_type))
    rewrite = gre_build_rewrite (vnm, sw_if_index, link_type, dst);

  if ((NULL != rewrite) && (vec_len (rewrite) == gre_rewrite_len (t)))
    return (rewrite);

  if (!t->rewrite_warned)
    {
      t->rewrite_warned = 1;
      vlib_log_warn (gre_main.log_class,
		     "%U: a %U adjacency got a %d byte rewrite where the "
		     "tunnel's outer header is %d bytes; dropping its traffic",
		     format_vnet_sw_if_index_name, vnet_get_main (), t->sw_if_index,
		     format_vnet_link, link_type, NULL == rewrite ? 0 : vec_len (rewrite),
		     gre_rewrite_len (t));
    }

  vec_free (rewrite);

  return (NULL);
}

/*
 * A subsystem other than the tunnel can rewrite one of its adjacencies, an
 * ethernet neighbour added on the tunnel's interface for instance, replacing
 * the tunnel's outer header with one of a different length. Check that the
 * adjacency still holds the tunnel's outer header and restore it when it does
 * not.
 */
static void
gre_adj_rewrite_check (gre_tunnel_t *t, adj_index_t ai)
{
  ip_adjacency_t *adj;

  adj = adj_get (ai);

  /* a tunnel with no path leaves its adjacencies without a rewrite */
  if (0 == adj->rewrite_header.data_bytes)
    return;

  if ((IP_LOOKUP_NEXT_MIDCHAIN == adj->lookup_next_index) &&
      (gre_rewrite_len (t) == adj->rewrite_header.data_bytes))
    return;

  if (!t->rewrite_warned)
    {
      t->rewrite_warned = 1;
      vlib_log_warn (gre_main.log_class,
		     "%U: adjacency %d holds a %d byte rewrite where the "
		     "tunnel's outer header is %d bytes; restoring it",
		     format_vnet_sw_if_index_name, vnet_get_main (), t->sw_if_index, ai,
		     adj->rewrite_header.data_bytes, gre_rewrite_len (t));
    }

  if (TUNNEL_MODE_MP == t->mode)
    mgre_update_adj (vnet_get_main (), t->sw_if_index, ai);
  else
    gre_update_adj (vnet_get_main (), t->sw_if_index, ai);
}

static adj_delegate_type_t gre_adj_delegate_type;

static void
gre_adj_delegate_adj_modified (adj_delegate_t *aed)
{
  gre_tunnel_t *t;

  if (pool_is_free_index (gre_main.tunnels, aed->ad_index))
    return;

  t = pool_elt_at_index (gre_main.tunnels, aed->ad_index);

  gre_adj_rewrite_check (t, aed->ad_adj_index);
}

static const adj_delegate_vft_t gre_adj_delegate_vft = {
  .adv_adj_modified = gre_adj_delegate_adj_modified,
};

static clib_error_t *
gre_adj_delegate_init (vlib_main_t *vm)
{
  gre_adj_delegate_type = adj_delegate_register_new_type (&gre_adj_delegate_vft);

  return (0);
}

VLIB_INIT_FUNCTION (gre_adj_delegate_init);

/*
 * Track the tunnel on its adjacency so an external rewrite of the adjacency is
 * noticed. The delegate is added once; a second add returns -1.
 */
static void
gre_adj_delegate_track (adj_index_t ai, gre_tunnel_t *t)
{
  (void) adj_delegate_add (adj_get (ai), gre_adj_delegate_type, t - gre_main.tunnels);
}

/*
 * Install the tunnel's outer header as the rewrite of an adjacency. A rewrite
 * the builder rejects leaves the adjacency without one, and the caller stacks
 * the midchain on the drop instead of on the tunnel path, so packets are
 * discarded rather than sent behind a header of the wrong kind or size.
 * Returns whether a rewrite was installed.
 */
static u8
gre_install_adj_rewrite (adj_index_t ai, gre_tunnel_t *t, vnet_main_t *vnm,
			 const ip46_address_t *dst)
{
  vnet_link_t link_type;
  adj_flags_t af;
  u8 *rewrite;
  u8 installed;

  link_type = adj_get_link_type (ai);

  af = ADJ_FLAG_NONE;

  /*
   * the user has not requested that the load-balancing be based on
   * a flow hash of the inner packet. so use the stacking to choose
   * a path.
   */
  if (!(t->flags & TUNNEL_ENCAP_DECAP_FLAG_ENCAP_INNER_HASH))
    af |= ADJ_FLAG_MIDCHAIN_IP_STACK;

  rewrite = gre_build_midchain_rewrite (vnm, t->sw_if_index, t, link_type, dst);

  installed = (NULL != rewrite);

  adj_nbr_midchain_update_rewrite (ai, gre_get_fixup (t->tunnel_dst.fp_proto, link_type),
				   uword_to_pointer (t->flags, void *), af, rewrite);

  gre_adj_delegate_track (ai, t);

  return (installed);
}

void
gre_update_adj (vnet_main_t *vnm, u32 sw_if_index, adj_index_t ai)
{
  gre_tunnel_t *t;

  t = gre_tunnel_find_by_sw_if_index (sw_if_index);

  if (0 == t)
    return;

  if (gre_install_adj_rewrite (ai, t, vnm, &t->tunnel_dst.fp_addr))
    gre_tunnel_stack (ai);
  else
    adj_midchain_delegate_unstack (ai);
}

adj_walk_rc_t
mgre_mk_complete_walk (adj_index_t ai, void *data)
{
  mgre_walk_ctx_t *ctx = data;

  if (gre_install_adj_rewrite (ai, ctx->t, vnet_get_main (), &teib_entry_get_nh (ctx->ne)->fp_addr))
    teib_entry_adj_stack (ctx->ne, ai);
  else
    adj_midchain_delegate_unstack (ai);

  return (ADJ_WALK_RC_CONTINUE);
}

adj_walk_rc_t
mgre_mk_incomplete_walk (adj_index_t ai, void *data)
{
  gre_tunnel_t *t = data;

  adj_nbr_midchain_update_rewrite (
    ai, gre_get_fixup (t->tunnel_dst.fp_proto, adj_get_link_type (ai)), NULL,
    ADJ_FLAG_NONE, NULL);

  adj_midchain_delegate_unstack (ai);

  return (ADJ_WALK_RC_CONTINUE);
}

void
mgre_update_adj (vnet_main_t *vnm, u32 sw_if_index, adj_index_t ai)
{
  ip_adjacency_t *adj;
  teib_entry_t *ne;
  gre_tunnel_t *t;

  t = gre_tunnel_find_by_sw_if_index (sw_if_index);

  if (0 == t)
    return;

  adj = adj_get (ai);

  ne = teib_entry_find_46 (sw_if_index, adj->ia_nh_proto,
			   &adj->sub_type.nbr.next_hop);

  if (NULL == ne)
    {
      // no TEIB entry to provide the next-hop
      adj_nbr_midchain_update_rewrite (
	ai, gre_get_fixup (t->tunnel_dst.fp_proto, adj_get_link_type (ai)),
	uword_to_pointer (t->flags, void *), ADJ_FLAG_NONE, NULL);
      gre_adj_delegate_track (ai, t);
      return;
    }

  mgre_walk_ctx_t ctx = { .t = t, .ne = ne };
  adj_nbr_walk_nh (sw_if_index, adj->ia_nh_proto, &adj->sub_type.nbr.next_hop,
		   mgre_mk_complete_walk, &ctx);
}
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  GRE_ENCAP_NEXT_L2_MIDCHAIN,
  GRE_ENCAP_N_NEXT,
} gre_encap_next_t;

/**
 * @brief TX function. Only called for L2 payload including TEB or ERSPAN.
 *        L3 traffic uses the adj-midchains.
 */
static_always_inline u32
gre_encap_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		  vlib_frame_t *frame, gre_tunnel_type_t type)
{
  gre_main_t *gm = &gre_main;
  u32 *from, n_left_from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 sw_if_index[2] = { ~0, ~0 };
  const gre_tunnel_t *gt[2] = { 0 };
  adj_index_t adj_index[2] = { ADJ_INDEX_INVALID, ADJ_INDEX_INVALID };

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  while (n_left_from >= 2)
    {

      if (PREDICT_FALSE (sw_if_index[0] !=
			 vnet_buffer (b[0])->sw_if_index[VLIB_TX]))
	{
	  const vnet_hw_interface_t *hi;
	  sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	  hi = vnet_get_sup_hw_interface (gm->vnet_main, sw_if_index[0]);
	  gt[0] = &gm->tunnels[hi->dev_instance];
	  adj_index[0] = gt[0]->l2_adj_index;
	}
      if (PREDICT_FALSE (sw_if_index[1] !=
			 vnet_buffer (b[1])->sw_if_index[VLIB_TX]))
	{
	  const vnet_hw_interface_t *hi;
	  sw_if_index[1] = vnet_buffer (b[1])->sw_if_index[VLIB_TX];
	  hi = vnet_get_sup_hw_interface (gm->vnet_main, sw_if_index[1]);
	  gt[1] = &gm->tunnels[hi->dev_instance];
	  adj_index[1] = gt[1]->l2_adj_index;
	}

      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = adj_index[0];
      vnet_buffer (b[1])->ip.adj_index[VLIB_TX] = adj_index[1];

      if (type == GRE_TUNNEL_TYPE_ERSPAN)
	{
	  /* Encap GRE seq# and ERSPAN type II header */
	  erspan_t2_t *h0;
	  u32 seq_num;
	  u64 hdr;
	  vlib_buffer_advance (b[0], -sizeof (erspan_t2_t));
	  h0 = vlib_buffer_get_current (b[0]);
	  seq_num = clib_atomic_fetch_add (&gt[0]->gre_sn->seq_num, 1);
	  hdr = clib_host_to_net_u64 (ERSPAN_HDR2);
	  h0->seq_num = clib_host_to_net_u32 (seq_num);
	  h0->t2_u64 = hdr;
	  h0->t2.cos_en_t_session |= clib_host_to_net_u16 (gt[0]->session_id);
	}
      if (type == GRE_TUNNEL_TYPE_ERSPAN)
	{
	  /* Encap GRE seq# and ERSPAN type II header */
	  erspan_t2_t *h0;
	  u32 seq_num;
	  u64 hdr;
	  vlib_buffer_advance (b[1], -sizeof (erspan_t2_t));
	  h0 = vlib_buffer_get_current (b[1]);
	  seq_num = clib_atomic_fetch_add (&gt[1]->gre_sn->seq_num, 1);
	  hdr = clib_host_to_net_u64 (ERSPAN_HDR2);
	  h0->seq_num = clib_host_to_net_u32 (seq_num);
	  h0->t2_u64 = hdr;
	  h0->t2.cos_en_t_session |= clib_host_to_net_u16 (gt[1]->session_id);
	}

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  gre_tx_trace_t *tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  tr->tunnel_id = gt[0] - gm->tunnels;
	  tr->src = gt[0]->tunnel_src;
	  tr->dst = gt[0]->tunnel_dst.fp_addr;
	  tr->length = vlib_buffer_length_in_chain (vm, b[0]);
	}
      if (PREDICT_FALSE (b[1]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  gre_tx_trace_t *tr = vlib_add_trace (vm, node, b[1], sizeof (*tr));
	  tr->tunnel_id = gt[1] - gm->tunnels;
	  tr->src = gt[1]->tunnel_src;
	  tr->dst = gt[1]->tunnel_dst.fp_addr;
	  tr->length = vlib_buffer_length_in_chain (vm, b[1]);
	}

      b += 2;
      n_left_from -= 2;
    }

  while (n_left_from >= 1)
    {

      if (PREDICT_FALSE (sw_if_index[0] !=
			 vnet_buffer (b[0])->sw_if_index[VLIB_TX]))
	{
	  const vnet_hw_interface_t *hi;
	  sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	  hi = vnet_get_sup_hw_interface (gm->vnet_main, sw_if_index[0]);
	  gt[0] = &gm->tunnels[hi->dev_instance];
	  adj_index[0] = gt[0]->l2_adj_index;
	}

      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = adj_index[0];

      if (type == GRE_TUNNEL_TYPE_ERSPAN)
	{
	  /* Encap GRE seq# and ERSPAN type II header */
	  erspan_t2_t *h0;
	  u32 seq_num;
	  u64 hdr;
	  ASSERT (gt[0]->type == GRE_TUNNEL_TYPE_ERSPAN);
	  vlib_buffer_advance (b[0], -sizeof (erspan_t2_t));
	  h0 = vlib_buffer_get_current (b[0]);
	  seq_num = clib_atomic_fetch_add (&gt[0]->gre_sn->seq_num, 1);
	  hdr = clib_host_to_net_u64 (ERSPAN_HDR2);
	  h0->seq_num = clib_host_to_net_u32 (seq_num);
	  h0->t2_u64 = hdr;
	  h0->t2.cos_en_t_session |= clib_host_to_net_u16 (gt[0]->session_id);
	}

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  gre_tx_trace_t *tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  tr->tunnel_id = gt[0] - gm->tunnels;
	  tr->src = gt[0]->tunnel_src;
	  tr->dst = gt[0]->tunnel_dst.fp_addr;
	  tr->length = vlib_buffer_length_in_chain (vm, b[0]);
	}

      b += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_single_next (
    vm, node, from, GRE_ENCAP_NEXT_L2_MIDCHAIN, frame->n_vectors);

  vlib_node_increment_counter (vm, node->node_index, GRE_ERROR_PKTS_ENCAP,
			       frame->n_vectors);

  return frame->n_vectors;
}

static char *gre_error_strings[] = {
#define gre_error(n, s) s,
#include "error.def"
#undef gre_error
};

VLIB_NODE_FN (gre_teb_encap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return (gre_encap_inline (vm, node, frame, GRE_TUNNEL_TYPE_TEB));
}

VLIB_NODE_FN (gre_erspan_encap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return (gre_encap_inline (vm, node, frame, GRE_TUNNEL_TYPE_ERSPAN));
}

VLIB_REGISTER_NODE (gre_teb_encap_node) =
{
  .name = "gre-teb-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_gre_tx_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = GRE_N_ERROR,
  .error_strings = gre_error_strings,
  .n_next_nodes = GRE_ENCAP_N_NEXT,
  .next_nodes = {
    [GRE_ENCAP_NEXT_L2_MIDCHAIN] = "adj-l2-midchain",
  },
};
VLIB_REGISTER_NODE (gre_erspan_encap_node) =
{
  .name = "gre-erspan-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_gre_tx_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = GRE_N_ERROR,
  .error_strings = gre_error_strings,
  .n_next_nodes = GRE_ENCAP_N_NEXT,
  .next_nodes = {
    [GRE_ENCAP_NEXT_L2_MIDCHAIN] = "adj-l2-midchain",
  },
};

#ifndef CLIB_MARCH_VARIANT
static u8 *
format_gre_tunnel_name (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  gre_main_t *gm = &gre_main;
  gre_tunnel_t *t;

  if (dev_instance >= vec_len (gm->tunnels))
    return format (s, "<improperly-referenced>");

  t = pool_elt_at_index (gm->tunnels, dev_instance);
  return format (s, "gre%d", t->user_instance);
}

static u8 *
format_gre_device (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);

  s = format (s, "GRE tunnel: id %d\n", dev_instance);
  return s;
}

static int
gre_tunnel_desc (u32 sw_if_index, ip46_address_t *src, ip46_address_t *dst,
		 u8 *is_l2)
{
  gre_tunnel_t *t;

  t = gre_tunnel_find_by_sw_if_index (sw_if_index);

  if (0 == t)
    /* not one of ours */
    return -1;

  *src = t->tunnel_src;
  *dst = t->tunnel_dst.fp_addr;
  *is_l2 = t->type == GRE_TUNNEL_TYPE_TEB;

  return (0);
}

VNET_DEVICE_CLASS (gre_device_class) = {
  .name = "GRE tunnel device",
  .format_device_name = format_gre_tunnel_name,
  .format_device = format_gre_device,
  .format_tx_trace = format_gre_tx_trace,
  .admin_up_down_function = gre_interface_admin_up_down,
  .ip_tun_desc = gre_tunnel_desc,
#ifdef SOON
  .clear counter = 0;
#endif
}
;

VNET_HW_INTERFACE_CLASS (gre_hw_interface_class) = {
  .name = "GRE",
  .format_header = format_gre_header_with_length,
  .unformat_header = unformat_gre_header,
  .build_rewrite = gre_build_rewrite,
  .update_adjacency = gre_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};

VNET_HW_INTERFACE_CLASS (mgre_hw_interface_class) = {
  .name = "mGRE",
  .format_header = format_gre_header_with_length,
  .unformat_header = unformat_gre_header,
  .build_rewrite = gre_build_rewrite,
  .update_adjacency = mgre_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_NBMA,
};
#endif /* CLIB_MARCH_VARIANT */

static void
add_protocol (gre_main_t *gm, gre_protocol_t protocol, char *protocol_name)
{
  gre_protocol_info_t *pi;
  u32 i;

  vec_add2 (gm->protocol_infos, pi, 1);
  i = pi - gm->protocol_infos;

  pi->name = protocol_name;
  pi->protocol = protocol;
  pi->next_index = pi->node_index = ~0;

  hash_set (gm->protocol_info_by_protocol, protocol, i);
  hash_set_mem (gm->protocol_info_by_name, pi->name, i);
}

static clib_error_t *
gre_init (vlib_main_t *vm)
{
  gre_main_t *gm = &gre_main;
  clib_error_t *error;
  ip_main_t *im = &ip_main;
  ip_protocol_info_t *pi;

  clib_memset (gm, 0, sizeof (gm[0]));
  gm->vlib_main = vm;
  gm->vnet_main = vnet_get_main ();
  gm->log_class = vlib_log_register_class ("gre", 0);

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip4_lookup_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip6_lookup_init)))
    return error;

  /* Set up the ip packet generator */
  pi = ip_get_protocol_info (im, IP_PROTOCOL_GRE);
  pi->format_header = format_gre_header;
  pi->unformat_pg_edit = unformat_pg_gre_header;

  gm->protocol_info_by_name = hash_create_string (0, sizeof (uword));
  gm->protocol_info_by_protocol = hash_create (0, sizeof (uword));
  gm->tunnel_by_key4 =
    hash_create_mem (0, sizeof (gre_tunnel_key4_t), sizeof (uword));
  gm->tunnel_by_key6 =
    hash_create_mem (0, sizeof (gre_tunnel_key6_t), sizeof (uword));
  gm->seq_num_by_key =
    hash_create_mem (0, sizeof (gre_sn_key_t), sizeof (uword));

#define _(n, s) add_protocol (gm, GRE_PROTOCOL_##s, #s);
  foreach_gre_protocol
#undef _
    return vlib_call_init_function (vm, gre_input_init);
}

VLIB_INIT_FUNCTION (gre_init);
