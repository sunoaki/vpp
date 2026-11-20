/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

/* det44.h - deterministic NAT definitions */

/**
 * @file
 * @brief Deterministic NAT (CGN) definitions
 */

#ifndef __included_det44_h__
#define __included_det44_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/api_errno.h>
#include <vnet/fib/fib_source.h>
#include <vppinfra/dlist.h>
#include <vppinfra/error.h>
#include <vlibapi/api.h>
#include <vlib/log.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/ip/reass/ip4_sv_reass.h>

#include <nat/lib/lib.h>
#include <nat/lib/ipfix_logging.h>
#include <nat/lib/nat_proto.h>

/* Session state */
#define foreach_det44_session_state        \
  _(0, UNKNOWN, "unknown")                 \
  _(1, UDP_ACTIVE, "udp-active")           \
  _(2, TCP_SYN_SENT, "tcp-syn-sent")       \
  _(3, TCP_ESTABLISHED, "tcp-established") \
  _(4, TCP_FIN_WAIT, "tcp-fin-wait")       \
  _(5, TCP_CLOSE_WAIT, "tcp-close-wait")   \
  _(6, TCP_CLOSING, "tcp-closing")         \
  _(7, TCP_LAST_ACK, "tcp-last-ack")       \
  _(8, TCP_CLOSED, "tcp-closed")           \
  _(9, ICMP_ACTIVE, "icmp-active")

typedef enum
{
#define _(v, N, s) DET44_SESSION_##N = v,
  foreach_det44_session_state
#undef _
} det44_session_state_t;

#define DET44_SES_PER_USER 1000

typedef struct
{
  u16 src_port, dst_port;
} tcp_udp_header_t;

typedef struct
{
  u32 cached_sw_if_index;
  u32 cached_ip4_address;
} det44_runtime_t;

/* deterministic session outside key */
typedef struct
{
  union
  {
    struct
    {
      ip4_address_t ext_host_addr;
      u16 ext_host_port;
      u16 out_port;
    };
    u64 as_u64;
  };
} snat_det_out_key_t;

typedef struct
{
  /* Inside network port */
  u16 in_port;
  /* Outside network address and port */
  snat_det_out_key_t out;
  /* Session state */
  u8 state;
  /* IP protocol of the first packet of the session */
  u8 proto;
  /* Expire timeout */
  u32 expire;
} snat_det_session_t;

typedef struct
{
  /* inside IP address range */
  ip4_address_t in_addr;
  u8 in_plen;
  /* outside IP address range */
  ip4_address_t out_addr;
  u8 out_plen;
  /* inside IP addresses / outside IP addresses */
  u32 sharing_ratio;
  /* number of ports available to internal host */
  u16 ports_per_host;
  /* session counter */
  u32 ses_num;
  /* vector of sessions */
  snat_det_session_t *sessions;
} snat_det_map_t;

/* Deterministic NAT identity mapping */
typedef struct
{
  /* inside IP address */
  ip4_address_t addr;
  /* protocol */
  nat_protocol_t proto;
  /* inside port */
  u16 port;
  /* flags */
  u32 flags;
  /* opaque string tag */
  u8 *tag;
} det44_identity_mapping_t;

typedef struct
{
  u32 sw_if_index;
  u8 flags;
} det44_interface_t;

typedef struct
{
  u32 outside_vrf_id;
  u32 inside_vrf_id;
} det44_config_t;

typedef struct
{
  u32 fib_index;
  u32 refcount;
} det44_fib_t;

typedef struct det44_main_s
{
  det44_config_t config;

  u32 outside_fib_index;
  u32 inside_fib_index;

  /* Vector of outside fibs */
  det44_fib_t *outside_fibs;

  fib_source_t fib_src_hi;
  fib_source_t fib_src_low;

  u32 out2in_node_index;
  u32 in2out_node_index;

  /* Deterministic NAT mappings */
  snat_det_map_t *det_maps;

  /* Deterministic NAT identity mappings, kept in insertion order */
  det44_identity_mapping_t *identity_mappings;

  /* TCP MSS clamping */
  u16 mss_clamping;

  /* Protocol timeouts */
  nat_timeouts_t timeouts;

  /* Expire walk process node index */
  u32 expire_walk_node_index;

  u32 enabled;

  /* API message ID base */
  u16 msg_id_base;

  /* log class */
  vlib_log_class_t log_class;

  det44_interface_t *interfaces;

  /* convenience */
  ip4_main_t *ip4_main;
  /* required */
  vnet_main_t *vnet_main;

} det44_main_t;

extern det44_main_t det44_main;

/* logging */
#define det44_log_err(...) \
  vlib_log(VLIB_LOG_LEVEL_ERR, det44_main.log_class, __VA_ARGS__)
#define det44_log_warn(...) \
  vlib_log(VLIB_LOG_LEVEL_WARNING, det44_main.log_class, __VA_ARGS__)
#define det44_log_notice(...) \
  vlib_log(VLIB_LOG_LEVEL_NOTICE, det44_main.log_class, __VA_ARGS__)
#define det44_log_info(...) \
  vlib_log(VLIB_LOG_LEVEL_INFO, det44_main.log_class, __VA_ARGS__)
#define det44_log_debug(...)\
  vlib_log(VLIB_LOG_LEVEL_DEBUG, det44_main.log_class, __VA_ARGS__)

/* Deterministic NAT identity mapping flags */
#define DET44_FLAG_ADDR_ONLY (1 << 0)

/* Deterministic NAT interface flags */
#define DET44_INTERFACE_FLAG_IS_INSIDE 1
#define DET44_INTERFACE_FLAG_IS_OUTSIDE 2

/** \brief Check if Deterministic NAT interface is inside.
    @param i Deterministic NAT interface
    @return 1 if inside interface
*/
#define det44_interface_is_inside(i) i->flags & DET44_INTERFACE_FLAG_IS_INSIDE

/** \brief Check if Deterministic NAT interface is outside.
    @param i Deterministic NAT interface
    @return 1 if outside interface
*/
#define det44_interface_is_outside(i) i->flags & DET44_INTERFACE_FLAG_IS_OUTSIDE

static_always_inline u8
plugin_enabled ()
{
  det44_main_t *dm = &det44_main;
  return dm->enabled;
}

extern vlib_node_registration_t det44_in2out_node;
extern vlib_node_registration_t det44_out2in_node;

int det44_plugin_enable (det44_config_t);
int det44_plugin_disable ();

int det44_interface_add_del (u32 sw_if_index, u8 is_inside_flag, int is_del);

int det44_set_timeouts (nat_timeouts_t * timeouts);
nat_timeouts_t det44_get_timeouts ();
void det44_reset_timeouts ();

/* format functions */
format_function_t format_det_map_ses;

int snat_det_add_map (ip4_address_t * in_addr, u8 in_plen,
		      ip4_address_t * out_addr, u8 out_plen, int is_add);

/** Maximum stored identity mapping tag, so the API string fits. */
#define DET44_IDENTITY_TAG_LEN 63

/** Identity mapping storage outcome. */
typedef enum
{
  DET44_IDENTITY_MAPPING_ADDED,
  DET44_IDENTITY_MAPPING_DELETED,
  DET44_IDENTITY_MAPPING_NOT_FOUND,
  DET44_IDENTITY_MAPPING_ALREADY_EXISTS,
} det44_identity_mapping_result_t;

/**
 * @brief Add or delete a Deterministic NAT identity mapping.
 *
 * A tag longer than DET44_IDENTITY_TAG_LEN bytes is truncated when stored.
 *
 * @param addr   inside IPv4 address.
 * @param proto  NAT protocol.
 * @param port   inside port in network byte order.
 * @param is_add nonzero to add, zero to delete.
 * @param flags  DET44_FLAG_ADDR_ONLY for an address-only mapping.
 * @param tag    optional opaque tag, copied into the mapping.
 *
 * @return storage outcome; the caller turns it into a CLI or API error.
 */
static_always_inline det44_identity_mapping_result_t
det44_add_del_identity_mapping (ip4_address_t addr, nat_protocol_t proto, u16 port, u8 is_add,
				u32 flags, u8 *tag)
{
  det44_main_t *dm = &det44_main;
  det44_identity_mapping_t *m;
  u16 tag_len;

  vec_foreach (m, dm->identity_mappings)
    {
      if (m->addr.as_u32 != addr.as_u32 || m->flags != flags)
	continue;
      if (!(flags & DET44_FLAG_ADDR_ONLY) && (m->proto != proto || m->port != port))
	continue;
      if (is_add)
	return DET44_IDENTITY_MAPPING_ALREADY_EXISTS;
      if (m->tag)
	vec_free (m->tag);
      vec_del1 (dm->identity_mappings, m - dm->identity_mappings);
      return DET44_IDENTITY_MAPPING_DELETED;
    }

  if (!is_add)
    return DET44_IDENTITY_MAPPING_NOT_FOUND;

  vec_add2 (dm->identity_mappings, m, 1);
  clib_memset (m, 0, sizeof (*m));
  m->addr = addr;
  m->proto = proto;
  m->port = port;
  m->flags = flags;
  if (tag)
    {
      tag_len = clib_min (vec_len (tag), DET44_IDENTITY_TAG_LEN);
      m->tag = format (0, "%.*s%c", tag_len, tag, 0);
    }
  return DET44_IDENTITY_MAPPING_ADDED;
}

/**
 * @brief Apply the routing that an identity mapping match requires.
 *
 * The packet keeps its addresses and ports; it is routed by the FIB of the
 * direction it is leaving towards, so that a match does not fall into the
 * det map's inside or outside table.
 *
 * @param b0        buffer holding the packet.
 * @param fib_index outside FIB index on in2out, inside FIB index on out2in.
 */
static_always_inline void
det44_identity_mapping_bypass (vlib_buffer_t *b0, u32 fib_index)
{
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = fib_index;
}

/**
 * @brief Match a Deterministic NAT identity mapping by inside address.
 *
 * Identity mappings are searched in insertion order and the first match
 * wins. An address-only mapping therefore shadows every later mapping on
 * the same address, regardless of protocol and port; an operator who wants
 * per-port behaviour on such an address has to add the per-port mapping
 * first.
 *
 * A mapping that also falls inside a det map is one-way by design: in2out
 * bypasses the map, the outside peer answers the inside address, and there
 * is no out2in session to translate the answer back.
 *
 * @param addr  inside IPv4 address.
 * @param proto NAT protocol.
 * @param port  inside port in network byte order.
 *
 * @return matching identity mapping, otherwise NULL.
 */
static_always_inline det44_identity_mapping_t *
det44_identity_mapping_match (ip4_address_t addr, nat_protocol_t proto, u16 port)
{
  det44_main_t *dm = &det44_main;
  det44_identity_mapping_t *m;

  vec_foreach (m, dm->identity_mappings)
    {
      if (m->addr.as_u32 != addr.as_u32)
	continue;
      if (m->flags & DET44_FLAG_ADDR_ONLY)
	return m;
      if (m->proto == proto && m->port == port)
	return m;
    }
  return 0;
}

/* icmp session match functions */
u32 icmp_match_out2in_det (vlib_node_runtime_t *node, u32 thread_index, vlib_buffer_t *b0,
			   ip4_header_t *ip0, ip4_address_t *addr, u16 *port, u32 *fib_index,
			   nat_protocol_t *proto, void *d, void *e, u8 *dont_translate,
			   u8 *identity);
u32 icmp_match_in2out_det (vlib_node_runtime_t *node, u32 thread_index, vlib_buffer_t *b0,
			   ip4_header_t *ip0, ip4_address_t *addr, u16 *port, u32 *fib_index,
			   nat_protocol_t *proto, void *d, void *e, u8 *dont_translate, u8 *created,
			   ip4_address_t *created_addr, u8 *identity);
u32 det44_icmp_in2out (vlib_buffer_t *b0, ip4_header_t *ip0, icmp46_header_t *icmp0,
		       u32 sw_if_index0, u32 rx_fib_index0, vlib_node_runtime_t *node, u32 next0,
		       u32 thread_index, void *d, void *e, u8 *session_accepted,
		       ip4_address_t *created_addr, u8 *identity);
u32 det44_icmp_out2in (vlib_buffer_t * b0, ip4_header_t * ip0,
		       icmp46_header_t * icmp0, u32 sw_if_index0,
		       u32 rx_fib_index0, vlib_node_runtime_t * node,
		       u32 next0, u32 thread_index, void *d, void *e);

static_always_inline int
is_addr_in_net (ip4_address_t * addr, ip4_address_t * net, u8 plen)
{
  if (net->as_u32 == (addr->as_u32 & ip4_main.fib_masks[plen]))
    return 1;
  return 0;
}

static_always_inline snat_det_map_t *
snat_det_map_by_user (ip4_address_t * user_addr)
{
  det44_main_t *dm = &det44_main;
  snat_det_map_t *mp;
  pool_foreach (mp, dm->det_maps)
   {
    if (is_addr_in_net(user_addr, &mp->in_addr, mp->in_plen))
      return mp;
  }
  return 0;
}

static_always_inline snat_det_map_t *
snat_det_map_by_out (ip4_address_t * out_addr)
{
  det44_main_t *dm = &det44_main;
  snat_det_map_t *mp;
  pool_foreach (mp, dm->det_maps)
   {
    if (is_addr_in_net(out_addr, &mp->out_addr, mp->out_plen))
      return mp;
  }
  return 0;
}

static_always_inline void
snat_det_forward (snat_det_map_t * dm, ip4_address_t * in_addr,
		  ip4_address_t * out_addr, u16 * lo_port)
{
  u32 in_offset, out_offset;

  in_offset = clib_net_to_host_u32 (in_addr->as_u32) -
    clib_net_to_host_u32 (dm->in_addr.as_u32);
  out_offset = in_offset / dm->sharing_ratio;
  out_addr->as_u32 =
    clib_host_to_net_u32 (clib_net_to_host_u32 (dm->out_addr.as_u32) +
			  out_offset);
  *lo_port = 1024 + dm->ports_per_host * (in_offset % dm->sharing_ratio);
}

static_always_inline void
snat_det_reverse (snat_det_map_t * dm, ip4_address_t * out_addr, u16 out_port,
		  ip4_address_t * in_addr)
{
  u32 in_offset1, in_offset2, out_offset;

  out_offset = clib_net_to_host_u32 (out_addr->as_u32) -
    clib_net_to_host_u32 (dm->out_addr.as_u32);
  in_offset1 = out_offset * dm->sharing_ratio;
  in_offset2 = (out_port - 1024) / dm->ports_per_host;
  in_addr->as_u32 =
    clib_host_to_net_u32 (clib_net_to_host_u32 (dm->in_addr.as_u32) +
			  in_offset1 + in_offset2);
}

static_always_inline u32
snat_det_user_ses_offset (ip4_address_t * addr, u8 plen)
{
  return (clib_net_to_host_u32 (addr->as_u32) & pow2_mask (32 - plen)) *
    DET44_SES_PER_USER;
}

static_always_inline snat_det_session_t *
snat_det_get_ses_by_out (snat_det_map_t * dm, ip4_address_t * in_addr,
			 u64 out_key)
{
  u32 user_offset;
  u16 i;

  user_offset = snat_det_user_ses_offset (in_addr, dm->in_plen);
  for (i = 0; i < DET44_SES_PER_USER; i++)
    {
      if (dm->sessions[i + user_offset].out.as_u64 == out_key)
	return &dm->sessions[i + user_offset];
    }

  return 0;
}

static_always_inline snat_det_session_t *
snat_det_find_ses_by_in (snat_det_map_t * dm, ip4_address_t * in_addr,
			 u16 in_port, snat_det_out_key_t out_key)
{
  snat_det_session_t *ses;
  u32 user_offset;
  u16 i;

  user_offset = snat_det_user_ses_offset (in_addr, dm->in_plen);
  for (i = 0; i < DET44_SES_PER_USER; i++)
    {
      ses = &dm->sessions[i + user_offset];
      if (ses->in_port == in_port &&
	  ses->out.ext_host_addr.as_u32 == out_key.ext_host_addr.as_u32 &&
	  ses->out.ext_host_port == out_key.ext_host_port)
	return &dm->sessions[i + user_offset];
    }

  return 0;
}

static_always_inline void
snat_det_session_addresses (snat_det_map_t *dm, snat_det_session_t *ses, ip4_address_t *in_addr,
			    ip4_address_t *out_addr)
{
  u32 user_index = (ses - dm->sessions) / DET44_SES_PER_USER;
  u32 in_offset, out_offset;

  in_addr->as_u32 = clib_host_to_net_u32 (clib_net_to_host_u32 (dm->in_addr.as_u32) + user_index);
  in_offset = clib_net_to_host_u32 (in_addr->as_u32) - clib_net_to_host_u32 (dm->in_addr.as_u32);
  out_offset = in_offset / dm->sharing_ratio;
  out_addr->as_u32 = clib_host_to_net_u32 (clib_net_to_host_u32 (dm->out_addr.as_u32) + out_offset);
}

/*
 * The state alone does not identify the protocol because a TCP and a UDP
 * session both hold the state of a fresh session before a packet sets it.
 * Record it from the first packet instead.
 */
static_always_inline snat_det_session_t *
snat_det_ses_create (u32 thread_index, snat_det_map_t *dm, ip4_address_t *in_addr,
		     ip_protocol_t proto, u16 in_port, snat_det_out_key_t *out)
{
  u32 user_offset;
  u16 i;

  user_offset = snat_det_user_ses_offset (in_addr, dm->in_plen);

  for (i = 0; i < DET44_SES_PER_USER; i++)
    {
      if (!dm->sessions[i + user_offset].in_port)
	{
	  if (clib_atomic_bool_cmp_and_swap
	      (&dm->sessions[i + user_offset].in_port, 0, in_port))
	    {
	      dm->sessions[i + user_offset].out.as_u64 = out->as_u64;
	      dm->sessions[i + user_offset].state = DET44_SESSION_UNKNOWN;
	      dm->sessions[i + user_offset].proto = proto;
	      dm->sessions[i + user_offset].expire = 0;
	      clib_atomic_add_fetch (&dm->ses_num, 1);
	      return &dm->sessions[i + user_offset];
	    }
	}
    }

  nat_ipfix_logging_max_entries_per_user (thread_index,
					  DET44_SES_PER_USER,
					  in_addr->as_u32);
  return 0;
}

static_always_inline void
snat_det_ses_close (u32 thread_index, snat_det_map_t *dm, snat_det_session_t *ses)
{
  det44_main_t *dmain = &det44_main;
  ip4_address_t in_addr, out_addr;
  ip_protocol_t proto;
  u16 in_port;

  if (!clib_atomic_bool_cmp_and_swap (&ses->in_port, ses->in_port, 0))
    return;

  in_port = clib_net_to_host_u16 (ses->in_port);
  proto = ses->proto;
  snat_det_session_addresses (dm, ses, &in_addr, &out_addr);
  nat_ipfix_logging_nat44_ses_delete (thread_index, in_addr.as_u32, out_addr.as_u32, proto, in_port,
				      clib_net_to_host_u16 (ses->out.out_port),
				      dmain->outside_fib_index);

  ses->out.as_u64 = 0;
  clib_atomic_add_fetch (&dm->ses_num, -1);
}

/*
 * For close requests handled on the main thread: the CLI and the API
 * handlers. The index is read rather than assumed so an event always lands
 * in the per-thread buffer of the thread that closes the session.
 */
static_always_inline void
snat_det_ses_close_local (snat_det_map_t *dm, snat_det_session_t *ses)
{
  snat_det_ses_close (vlib_get_thread_index (), dm, ses);
}

clib_error_t *det44_api_hookup (vlib_main_t * vm);

#endif /* __included_det44_h__ */
