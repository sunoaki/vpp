/* SPDX-License-Identifier: Apache-2.0 */
#ifndef included_lcp_router_h
#define included_lcp_router_h

#include <vnet/fib/fib_types.h>
#include <vnet/fib/fib_source.h>

typedef struct
{
  u32 refs;
  u32 fib_index;
  u32 mfib_index;
  fib_source_t sources[3];
  /* multicast routes installed in the MFIB, reported so that a test can
   * follow what the plugin holds there */
  u32 mcast_routes;
} lcp_router_table_state_t;

__clib_export int lcp_router_table_state (u32 table_id, fib_protocol_t proto,
					  lcp_router_table_state_t *state);

/* Number of distinct cross FIB nexthop diagnostics emitted so far. */
__clib_export u32 lcp_router_cross_fib_nexthop_count (void);

/* The steps of a neighbour synchronization, for the test plugin. */
__clib_export void lcp_router_neigh_test_mark_all (void);
__clib_export void lcp_router_neigh_test_end (void);

#endif
