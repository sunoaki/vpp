/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#ifndef __LCP_ADJ_DELEGATE_H__
#define __LCP_ADJ_DELEGATE_H__

#include <vppinfra/bihash_32_8.h>

typedef struct lcp_adj_key_t_
{
  u32 sw_if_index;
  u8 rewrite[28];
} lcp_adj_key_t;

STATIC_ASSERT (sizeof (lcp_adj_key_t) == 32, "LCP ADJ Key size changed");

typedef struct lcp_adj_kv_t_
{
  union
  {
    BVT (clib_bihash_kv) kv;
    struct
    {
      lcp_adj_key_t k;
      u64 v;
    };
  };
} lcp_adj_kv_t;

STATIC_ASSERT (sizeof (lcp_adj_kv_t) == sizeof (BVT (clib_bihash_kv)),
	       "LCP ADJ Key size changed");

/**
 * The table of adjacencies indexed by the rewrite string
 */
extern BVT (clib_bihash) lcp_adj_tbl;

/*
 * Construct the key from the provided rewrite, then pad with zeros
 * to ensure the key does not have garbage bytes.
 *
 * Returns 0 when the rewrite fits the key, non-zero when it does not; in
 * that case the key is left untouched. The length is checked at runtime
 * rather than with an ASSERT because a release build compiles ASSERT out,
 * and the key is on the caller's stack, so an over-long rewrite would
 * write past the end of the key.
 */
static_always_inline int
lcp_adj_mk_key (const u8 *rewrite, u32 len, u32 sw_if_index, lcp_adj_key_t *key)
{
  if (len > sizeof (key->rewrite))
    return -1;

  clib_memcpy_fast (key->rewrite, rewrite, len);
  clib_memset (key->rewrite + len, 0, sizeof (key->rewrite) - len);
  key->sw_if_index = sw_if_index;

  return 0;
}

static_always_inline adj_index_t
lcp_adj_lkup (const u8 *rewrite, u8 len, u32 sw_if_index)
{
  lcp_adj_kv_t kv;

  /*
   * An over-long rewrite does not fit the key, so it can never have been
   * inserted into the table and is guaranteed not to match any entry.
   */
  if (lcp_adj_mk_key (rewrite, len, sw_if_index, &kv.k) != 0)
    return (ADJ_INDEX_INVALID);

  if (!BV (clib_bihash_search_inline) (&lcp_adj_tbl, &kv.kv))
    return (kv.v);

  return (ADJ_INDEX_INVALID);
}
#endif
