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
} lcp_router_table_state_t;

__clib_export int lcp_router_table_state (u32 table_id, fib_protocol_t proto,
					lcp_router_table_state_t *state);

#endif
