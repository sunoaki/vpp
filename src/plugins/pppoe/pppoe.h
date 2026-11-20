/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Intel and/or its affiliates.
 */

#ifndef _PPPOE_H
#define _PPPOE_H

#include <vnet/plugin/plugin.h>
#include <vppinfra/lock.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>
#include <vnet/fib/fib_table.h>
#include <vlib/vlib.h>
#include <vppinfra/bihash_8_8.h>

typedef struct
{
  u8 ver_type;
  u8 code;
  u16 session_id;
  u16 length;
  u16 ppp_proto;
} pppoe_header_t;

/* A PPP control protocol packet starts with a code, an identifier the peer
 * echoes back, and the length of the packet including this header. */
typedef struct
{
  u8 code;
  u8 identifier;
  u16 length;
} ppp_control_header_t;

/* IPCP and IPv6CP options are a type, a length in bytes including the two
 * option header bytes, and the data. */
typedef struct
{
  u8 type;
  u8 length;
  u8 data[];
} ppp_control_option_t;

#define PPPOE_VER_TYPE 0x11
#define PPPOE_PADS     0x65
#define PPPOE_PADT     0xa7

#define PPP_PROTOCOL_IPCP   0x8021
#define PPP_PROTOCOL_IPV6CP 0x8057

#define PPP_LCP_ECHO_REQUEST	 0x09
#define PPP_LCP_ECHO_REPLY	 0x0a
#define PPP_IPCP_CONFIGURE_NAK	 0x03
#define PPP_IPV6CP_CONFIGURE_NAK 0x03

#define PPP_IPCP_OPTION_IP_ADDRESS	       0x03
#define PPP_IPV6CP_OPTION_INTERFACE_IDENTIFIER 0x01

/* LCP echo requests that may be outstanding before the control plane ends the
 * session: a session is torn down once this many consecutive requests have no
 * reply for any of them, which is also how far behind the replies may trail
 * before a client that answers is torn down with one that does not */
#define PPPOE_LCP_ECHO_MISSES 2

typedef struct
{
  /* Required for pool_get_aligned  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* pppoe session_id in HOST byte order */
  u16 session_id;

  /* session client addresses */
  ip46_address_t client_ip;
  ip46_address_t client_ip6;
  u8 client_ip4_set;
  u8 client_ip6_set;

  /* the index of tx interface for pppoe encaped packet */
  u32 encap_if_index;

  /** FIB indices - inner IP packet lookup here */
  u32 decap_fib_index;

  u8 local_mac[6];
  u8 client_mac[6];

  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;

  /* the interface carries a session that is up, as the main thread last left it */
  u8 is_admin_up;

  /*
   * Counts the sessions this slot has held. The interface and the client's
   * session ID are the same for a client that reconnects, so an observation
   * queued for one session is told apart from the next by this stamp.
   */
  u32 generation;

  /*
   * LCP echo, by request epoch. The main thread counts a request up and
   * records the epoch it counted on; a reply names the epoch it answers, so a
   * reply is only credited to a request that came before it, and the requests
   * since the last one answered are what the session is judged by.
   *
   * The data plane writes none of these fields: it copies the epoch it sees
   * into what it queues, and the main thread decides what that means. A stale
   * copy names an epoch that is already answered, which the main thread
   * ignores.
   */
  u32 lcp_echo_request_epoch;
  u32 lcp_echo_acked_epoch;
  u32 lcp_echo_outstanding;
  /* set by the last request processed, which is the point the session is
   * judged at: a reply that arrives later does not undo the decision, and the
   * events that would only credit it are then ignored */
  u8 lcp_echo_ended;

  /* IPv6CP interface identifier the client address is built from */
  u64 ip6_ident;
  u8 ip6_ident_set;

} pppoe_session_t;

#define foreach_pppoe_input_next                                                                   \
  _ (DROP, "error-drop")                                                                           \
  _ (IP4_INPUT, "ip4-input")                                                                       \
  _ (IP6_INPUT, "ip6-input")                                                                       \
  _ (CP_INPUT, "pppoe-cp-dispatch")

typedef enum
{
#define _(s, n) PPPOE_INPUT_NEXT_##s,
  foreach_pppoe_input_next
#undef _
    PPPOE_INPUT_N_NEXT,
} pppoe_input_next_t;

typedef enum
{
#define pppoe_error(n, s) PPPOE_ERROR_##n,
#include <pppoe/pppoe_error.def>
#undef pppoe_error
  PPPOE_N_ERROR,
} pppoe_input_error_t;

extern char *pppoe_error_strings[];

#define MTU 1500
#define MTU_BUFFERS                                                                                \
  ((MTU + vlib_buffer_get_default_data_size (vm) - 1) / vlib_buffer_get_default_data_size (vm))
#define NUM_BUFFERS_TO_ALLOC 32

/*
 * The size of pppoe session table
 */
#define PPPOE_NUM_BUCKETS (64 * 1024)
#define PPPOE_MEMORY_SIZE (8 << 20)

/*
 * The PPPoE key is the mac address and session ID
 */
typedef struct
{
  union
  {
    struct
    {
      u16 session_id;
      u8 mac[6];
    } fields;
    struct
    {
      u32 w0;
      u32 w1;
    } words;
    u64 raw;
  };
} pppoe_entry_key_t;

/*
 * The PPPoE entry results
 */
typedef struct
{
  union
  {
    struct
    {
      u32 sw_if_index;

      u32 session_index;

    } fields;
    u64 raw;
  };
} pppoe_entry_result_t;

typedef struct
{
  /* Vector of encap session instances, */
  pppoe_session_t *sessions;

  /* For CP:  vector of CP path */
  BVT (clib_bihash) link_table;

  /* For DP:  vector of DP path */
  BVT (clib_bihash) session_table;

  /* Free vlib hw_if_indices */
  u32 *free_pppoe_session_hw_if_indices;

  /* Mapping from sw_if_index to session index */
  u32 *session_index_by_sw_if_index;

  /* Mapping from data plane sw_if_index to control plane sw_if_index */
  u32 *cp_if_index_by_sw_if_index;

  /* Mapping from control plane sw_if_index to data plane sw_if_index */
  u32 *dp_if_index_by_sw_if_index;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /*
   * Learn sessions and their addresses from what the control plane observes,
   * and end a session whose LCP echo goes unanswered. Turning it off leaves
   * the concentrator's frames forwarded but stops the learning and the echo
   * teardown.
   */
  u8 is_auto_discovery;

} pppoe_main_t;

extern pppoe_main_t pppoe_main;

extern vlib_node_registration_t pppoe_input_node;
extern vlib_node_registration_t pppoe_cp_dispatch_node;

typedef struct
{
  u8 is_add;
  u8 is_ip6;
  u16 session_id;
  ip46_address_t client_ip;
  ip46_address_t client_ip6;
  /*
   * The data plane port the client is reached on. A caller that names one is
   * taken at its word, which is how the control plane creates a session from a
   * negotiation frame, before the client has sent a frame the link table
   * could have learned it from. ~0 resolves it through the link table.
   */
  u32 encap_if_index;
  u32 decap_fib_index;
  /*
   * The session the caller meant to update, as the slot it read counted
   * itself when it read it; ~0 means the caller named no session and the add
   * is judged by the table alone. A control plane observation is queued, so
   * by the time it is applied the slot may hold a session built for the next
   * connection of the same client, and the count is what tells the two apart.
   */
  u32 generation;
  u8 local_mac[6];
  u8 client_mac[6];
  /* leave the reverse route for the client to whoever owns the address */
  bool disable_fib;
} vnet_pppoe_add_del_session_args_t;

int vnet_pppoe_add_del_session (vnet_pppoe_add_del_session_args_t *a, u32 *sw_if_indexp);

/*
 * What a data plane node saw, handed to the main thread so it applies it under
 * the barrier. The session is named by its interface and its session ID,
 * because the node may not hold the session index the observation belongs to
 * and because a queued observation must not land on the next session that
 * reuses the interface.
 */
typedef struct
{
  u32 hw_if_index;
  u16 session_id;
  /* the session the observation belongs to, which the interface and the
   * client's session ID cannot tell apart from the next one */
  u32 generation;
  u8 is_request;
  /* the request a reply answers, as the data plane last saw it; ignored for a
   * request, which the main thread numbers itself */
  u32 request_epoch;
} pppoe_lcp_echo_t;

typedef struct
{
  u32 hw_if_index;
  u16 session_id;
  u32 generation;
  u64 ip6_ident;
} pppoe_ip6_ident_update_t;

typedef struct
{
  u32 hw_if_index;
  u16 session_id;
  u32 generation;
  ip6_address_t prefix;
  u8 prefix_len;
} pppoe_ip6_prefix_t;

typedef struct
{
  u32 hw_if_index;
  u16 session_id;
  u32 generation;
} pppoe_session_teardown_t;

/* tear a live session down; the caller runs on the main thread */
void vnet_pppoe_session_teardown (pppoe_session_t *t);

void vnet_pppoe_add_del_session_cb (void *arg);
void vnet_pppoe_lcp_echo_cb (void *arg);
void vnet_pppoe_ip6_ident_cb (void *arg);
void vnet_pppoe_ip6_prefix_cb (void *arg);
void vnet_pppoe_padt_cb (void *arg);

typedef struct
{
  u8 is_add;
  u32 client_if_index;
  u32 cp_if_index;
} vnet_pppoe_add_del_tap_args_t;

int pppoe_add_del_cp (u32 cp_if_index, u32 dp_if_index, u8 is_add);

always_inline u64
pppoe_make_key (u8 *mac_address, u16 session_id)
{
  u64 temp;

  /*
   * The mac address in memory is A:B:C:D:E:F
   * The session_id in register is H:L
   */
#if CLIB_ARCH_IS_LITTLE_ENDIAN
  /*
   * Create the in-register key as F:E:D:C:B:A:H:L
   * In memory the key is L:H:A:B:C:D:E:F
   */
  temp = *((u64 *) (mac_address)) << 16;
  temp = (temp & ~0xffff) | (u64) (session_id);
#else
  /*
   * Create the in-register key as H:L:A:B:C:D:E:F
   * In memory the key is H:L:A:B:C:D:E:F
   */
  temp = *((u64 *) (mac_address)) >> 16;
  temp = temp | (((u64) session_id) << 48);
#endif

  return temp;
}

/**
 * Perform learning on one packet based on the mac table lookup result.
 * */
static_always_inline void
pppoe_learn_process (BVT (clib_bihash) * table, u32 sw_if_index0, pppoe_entry_key_t *key0,
		     pppoe_entry_key_t *cached_key, u32 *bucket0, pppoe_entry_result_t *result0)
{
  /* Check mac table lookup result */
  if (PREDICT_TRUE (result0->fields.sw_if_index == sw_if_index0))
    {
      /*
       * The entry was in the table, and the sw_if_index matched, the normal case
       */
      return;
    }
  else if (result0->fields.sw_if_index == ~0)
    {
      /* The entry was not in table, so add it  */
      result0->fields.sw_if_index = sw_if_index0;
      result0->fields.session_index = ~0;
      cached_key->raw = ~0; /* invalidate the cache */
    }
  else
    {
      /* The entry was in the table, but with the wrong sw_if_index mapping (mac move) */
      result0->fields.sw_if_index = sw_if_index0;
    }

  /* Update the entry */
  BVT (clib_bihash_kv) kv;
  kv.key = key0->raw;
  kv.value = result0->raw;
  BV (clib_bihash_add_del) (table, &kv, 1 /* is_add */);
}

static_always_inline void
pppoe_lookup_1 (BVT (clib_bihash) * table, pppoe_entry_key_t *cached_key,
		pppoe_entry_result_t *cached_result, u8 *mac0, u16 session_id0,
		pppoe_entry_key_t *key0, u32 *bucket0, pppoe_entry_result_t *result0)
{
  /* set up key */
  key0->raw = pppoe_make_key (mac0, session_id0);
  *bucket0 = ~0;

  if (key0->raw == cached_key->raw)
    {
      /* Hit in the one-entry cache */
      result0->raw = cached_result->raw;
    }
  else
    {
      /* Do a regular session table lookup */
      BVT (clib_bihash_kv) kv;

      kv.key = key0->raw;
      kv.value = ~0ULL;
      BV (clib_bihash_search_inline) (table, &kv);
      result0->raw = kv.value;

      /* Update one-entry cache */
      cached_key->raw = key0->raw;
      cached_result->raw = result0->raw;
    }
}

static_always_inline void
pppoe_update_1 (BVT (clib_bihash) * table, u8 *mac0, u16 session_id0, pppoe_entry_key_t *key0,
		u32 *bucket0, pppoe_entry_result_t *result0)
{
  /* set up key */
  key0->raw = pppoe_make_key (mac0, session_id0);
  *bucket0 = ~0;

  /* Update the entry */
  BVT (clib_bihash_kv) kv;
  kv.key = key0->raw;
  kv.value = result0->raw;
  BV (clib_bihash_add_del) (table, &kv, 1 /* is_add */);
}

/*
 * A control plane interface negotiates for exactly one data plane interface.
 * Both directions are sparse vectors indexed by sw_if_index; a slot that was
 * never filled, or an index past the end of the vector, has no peer and reads
 * as ~0.
 */
static_always_inline u32
pppoe_cp_if_index_by_dp (pppoe_main_t *pem, u32 dp_sw_if_index)
{
  if (dp_sw_if_index >= vec_len (pem->cp_if_index_by_sw_if_index))
    return ~0;

  return pem->cp_if_index_by_sw_if_index[dp_sw_if_index];
}

static_always_inline u32
pppoe_dp_if_index_by_cp (pppoe_main_t *pem, u32 cp_sw_if_index)
{
  if (cp_sw_if_index >= vec_len (pem->dp_if_index_by_sw_if_index))
    return ~0;

  return pem->dp_if_index_by_sw_if_index[cp_sw_if_index];
}

/* A data plane node reads the sessions of the table entries it finds, which the
 * main thread may delete between the search and the read. The free index check
 * keeps the read off a slot the main thread has already returned to the pool. */
static_always_inline pppoe_session_t *
pppoe_session_at_index (pppoe_main_t *pem, u32 session_index)
{
  if (session_index == ~0 || pool_is_free_index (pem->sessions, session_index))
    return NULL;

  return pool_elt_at_index (pem->sessions, session_index);
}

static_always_inline u32
pppoe_session_index_by_sw_if_index (u32 sw_if_index)
{
  pppoe_main_t *pem = &pppoe_main;

  if (sw_if_index >= vec_len (pem->session_index_by_sw_if_index))
    return ~0;

  return pem->session_index_by_sw_if_index[sw_if_index];
}

static_always_inline pppoe_session_t *
pppoe_session_find_by_sw_if_index (u32 sw_if_index)
{
  return pppoe_session_at_index (&pppoe_main, pppoe_session_index_by_sw_if_index (sw_if_index));
}

static_always_inline pppoe_session_t *
pppoe_session_find_by_hw_if_index (u32 hw_if_index, u16 session_id, u32 generation)
{
  vnet_main_t *vnm = vnet_get_main ();
  pppoe_session_t *t;

  if (!vnet_hw_interface_is_valid (vnm, hw_if_index))
    return NULL;

  t = pppoe_session_find_by_sw_if_index (vnet_get_hw_interface (vnm, hw_if_index)->sw_if_index);

  /* the interface persists across sessions, so the session ID decides; the
   * stamp tells apart the client that is on it now from the one an observation
   * queued for */
  if (t == NULL || t->session_id != session_id || t->generation != generation)
    return NULL;

  return t;
}

#endif /* _PPPOE_H */
