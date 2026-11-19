/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* error.h: drop/punt error packets */

#ifndef included_vlib_error_h
#define included_vlib_error_h

#include <vppinfra/format.h>

typedef u16 vlib_error_t;

enum vl_counter_severity_e
{
  VL_COUNTER_SEVERITY_ERROR,
  VL_COUNTER_SEVERITY_WARN,
  VL_COUNTER_SEVERITY_INFO,
};

typedef struct
{
  char *name;
  char *desc;
  enum vl_counter_severity_e severity;
  u32 stats_entry_index;
} vlib_error_desc_t;

typedef struct
{
  /* Error counters. */
  u64 *counters;

  /* Counter values as of last counter clear. */
  u64 *counters_last_clear;

  /* Counter structures in heap. Heap index
     indexes counter vector. */
  vlib_error_desc_t *counters_heap;

  /* stats segment entry index */
  u32 stats_err_entry_index;
} vlib_error_main_t;

/* Per node error registration. */
void vlib_register_errors (struct vlib_main_t *vm, u32 node_index,
			   u32 n_errors, char *error_strings[],
			   vlib_error_desc_t counters[]);
void vlib_unregister_errors (struct vlib_main_t *vm, u32 node_index);
void vlib_node_update_runtime_errors (struct vlib_main_t *vm, u32 node_index);

unformat_function_t unformat_vlib_error;

/* Initializes the locks below, once, before the first worker thread can take
 * either of them. */
void vlib_error_lock_init (void);

/* The error description lock, which also covers reading a node name, and the
 * node name lock, which vlib_node_rename exchanges a node name under. The
 * order they are taken in is documented in error.c. */
void vlib_error_desc_lock_get (void);
void vlib_error_desc_lock_put (void);

/* Takes the node name lock unless the calling thread already holds it. Returns
 * 1 when this call took it, and 0 when the thread already held it. */
u8 vlib_node_name_lock_get (void);

/* Returns 1 when this call left the node name section, and 0 when a caller of
 * the same thread is still inside it. */
u8 vlib_node_name_lock_put (void);

/* Frees the node names earlier renames retired. A rename calls it right after
 * it takes the name lock. */
void vlib_node_name_reap (void);

/* Whether a section this thread reached retired names, so its next rename
 * must leave the names waiting to be freed alone. */
u8 vlib_node_name_waiting_in_section (void);

/* Retires a node name exchanged for a new one. It is freed by a later rename
 * outside the section that retired it. */
void vlib_node_name_retire (u32 node_index, u8 *name);

/* Records that the section of this thread which retired names has ended. */
void vlib_node_name_section_ended (void);

#endif /* included_vlib_error_h */
