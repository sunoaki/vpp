/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

/* ip_neighbor.h: ip neighbor generic services */

#ifndef __INCLUDE_IP_NEIGHBOR_TYPES_H__
#define __INCLUDE_IP_NEIGHBOR_TYPES_H__

#include <vnet/ip/ip_types.h>
#include <vnet/ethernet/mac_address.h>
#include <vnet/fib/fib_types.h>

/*
 * REFUSED records that the data plane learned a different MAC for this entry
 * and the entry kept the one it holds. Only a static entry can carry it:
 * a dynamic entry follows the data plane. It stays set until the control
 * plane rewrites or deletes the entry, and it is what makes an entry whose
 * device was replaced distinguishable from a healthy one in 'show ip
 * neighbors'. It is not one of the flags the binary API encodes, because it
 * describes this module's view of an entry rather than its configuration.
 *
 * STALE is deliberately not reused for this. STALE is what ip_neighbor_sweep
 * and the age process destroy entries by, so marking a static entry STALE
 * would let this module delete control-plane configuration on its own.
 */
#define foreach_ip_neighbor_flag                                                                   \
  _ (STATIC, 1 << 0, "static", "S")                                                                \
  _ (DYNAMIC, 1 << 1, "dynamic", "D")                                                              \
  _ (NO_FIB_ENTRY, 1 << 2, "no-fib-entry", "N")                                                    \
  _ (PENDING, 1 << 3, "pending", "P")                                                              \
  _ (STALE, 1 << 4, "stale", "A")                                                                  \
  _ (REFUSED, 1 << 5, "refused", "R")

typedef enum ip_neighbor_flags_t_
{
  IP_NEIGHBOR_FLAG_NONE = 0,
#define _(a,b,c,d) IP_NEIGHBOR_FLAG_##a = b,
  foreach_ip_neighbor_flag
#undef _
} __clib_packed ip_neighbor_flags_t;

typedef struct ip_neighbor_watcher_t_
{
  u32 ipw_pid;
  u32 ipw_client;
  int ipw_api_version;
} ip_neighbor_watcher_t;

extern u8 *format_ip_neighbor_watcher (u8 * s, va_list * args);

typedef struct ip_neighbor_key_t_
{
  ip_address_t ipnk_ip;
  u8 __pad[3];
  u32 ipnk_sw_if_index;
} __clib_packed ip_neighbor_key_t;

/**
 * A representation of an IP neighbour/peer
 */
typedef struct ip_neighbor_t_
{
  /**
   * The idempotent key
   */
  ip_neighbor_key_t *ipn_key;

  /**
   * The learned MAC address of the neighbour
   */
  mac_address_t ipn_mac;

  /**
   * Falgs for this object
   */
  ip_neighbor_flags_t ipn_flags;

  /**
   * Aging related data
   *  - last time the neighbour was probed
   *  - number of probes - 3 and it's dead
   */
  f64 ipn_time_last_updated;
  u8 ipn_n_probes;
  index_t ipn_elt;

  /**
   * The index of the adj fib created for this neighbour
   */
  fib_node_index_t ipn_fib_entry_index;

  /**
   * The FIB table the adj fib was added to, and whose count this neighbour
   * holds. Not the table the interface is bound to now, since that binding
   * can change while the entry stays where it was put. INDEX_INVALID for an
   * IPv6 link-local address, whose table ip6_ll_table.c owns.
   */
  u32 ipn_fib_index;
} ip_neighbor_t;

extern u8 *format_ip_neighbor_flags (u8 * s, va_list * args);
extern u8 *format_ip_neighbor_key (u8 * s, va_list * args);
extern u8 *format_ip_neighbor (u8 * s, va_list * args);

__clib_export extern ip_neighbor_t *ip_neighbor_get (index_t ipni);

typedef struct ip_neighbor_learn_t_
{
  ip_address_t ip;
  mac_address_t mac;
  u32 sw_if_index;
} ip_neighbor_learn_t;


typedef enum ip_neighbor_event_flags_t_
{
  IP_NEIGHBOR_EVENT_ADDED = (1 << 0),
  IP_NEIGHBOR_EVENT_REMOVED = (1 << 1),
} ip_neighbor_event_flags_t;

typedef struct ip_neighbor_event_t_
{
  ip_neighbor_watcher_t ipne_watch;
  ip_neighbor_event_flags_t ipne_flags;
  ip_neighbor_t ipne_nbr;
} ip_neighbor_event_t;

extern void ip_neighbor_clone (const ip_neighbor_t * ipn,
			       ip_neighbor_t * clone);

extern void ip_neighbor_free (ip_neighbor_t * ipn);

/**
 * Keep RX and TX counts per-AF
 */
#define foreach_ip_neighbor_counter_type                                      \
  _ (REPLY, "reply")                                                          \
  _ (REQUEST, "request")                                                      \
  _ (GRAT, "gratuitous")

typedef enum ip_neighbor_counter_type_t_
{
#define _(a, b) IP_NEIGHBOR_CTR_##a,
  foreach_ip_neighbor_counter_type
#undef _
} ip_neighbor_counter_type_t;

#define N_IP_NEIGHBOR_CTRS (IP_NEIGHBOR_CTR_GRAT + 1)

#define FOREACH_IP_NEIGHBOR_CTR(_type)                                        \
  for (_type = 0; _type < N_IP_NEIGHBOR_CTRS; _type++)

typedef struct ip_neighbor_counters_t_
{
  vlib_simple_counter_main_t ipnc[VLIB_N_DIR][N_IP_NEIGHBOR_CTRS];
} ip_neighbor_counters_t;

/*
 * Counted per interface, indexed by sw_if_index. These are not the RX/TX
 * protocol counters above, which are per interface and per direction.
 *
 * REFUSED: the data plane learned a MAC that differs from the MAC of a static
 *          entry on the interface, so the entry kept the MAC it holds and a
 *          packet to that neighbour still goes to the old device. The entry
 *          itself carries IP_NEIGHBOR_FLAG_REFUSED until the control plane
 *          rewrites or deletes it, so this counts the refusals and the flag
 *          says which entries are affected.
 */
#define foreach_ip_neighbor_if_counter_type _ (REFUSED, "refused-learn")

typedef enum ip_neighbor_if_counter_type_t_
{
#define _(a, b) IP_NEIGHBOR_IF_CTR_##a,
  foreach_ip_neighbor_if_counter_type
#undef _
} ip_neighbor_if_counter_type_t;

#define N_IP_NEIGHBOR_IF_CTRS (IP_NEIGHBOR_IF_CTR_REFUSED + 1)

#define FOREACH_IP_NEIGHBOR_IF_CTR(_type) for (_type = 0; _type < N_IP_NEIGHBOR_IF_CTRS; _type++)

extern vlib_simple_counter_main_t ip_neighbor_if_counters[N_IP_NEIGHBOR_IF_CTRS];

extern u8 *format_ip_neighbor_counters (u8 *s, va_list *args);
extern u8 *format_ip_neighbor_if_counters (u8 *s, va_list *args);

extern void ip_neighbor_alloc_ctr (ip_neighbor_counters_t *ctr,
				   u32 sw_if_index);

extern ip_neighbor_counters_t ip_neighbor_counters[N_AF];

#endif /* __INCLUDE_IP_NEIGHBOR_H__ */
