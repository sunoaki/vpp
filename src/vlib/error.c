/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* error.c: VLIB error handler */

#include <vlib/vlib.h>
#include <vppinfra/heap.h>
#include <vlib/stats/stats.h>

uword
vlib_error_drop_buffers (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 u32 * buffers,
			 u32 next_buffer_stride,
			 u32 n_buffers,
			 u32 next_index,
			 u32 drop_error_node, u32 drop_error_code)
{
  u32 n_left_this_frame, n_buffers_left, *args, n_args_left;
  vlib_error_t drop_error;
  vlib_node_t *n;

  n = vlib_get_node (vm, drop_error_node);
  drop_error = n->error_heap_index + drop_error_code;

  n_buffers_left = n_buffers;
  while (n_buffers_left > 0)
    {
      vlib_get_next_frame (vm, node, next_index, args, n_args_left);

      n_left_this_frame = clib_min (n_buffers_left, n_args_left);
      n_buffers_left -= n_left_this_frame;
      n_args_left -= n_left_this_frame;

      while (n_left_this_frame >= 4)
	{
	  u32 bi0, bi1, bi2, bi3;
	  vlib_buffer_t *b0, *b1, *b2, *b3;

	  args[0] = bi0 = buffers[0];
	  args[1] = bi1 = buffers[1];
	  args[2] = bi2 = buffers[2];
	  args[3] = bi3 = buffers[3];

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);

	  b0->error = drop_error;
	  b1->error = drop_error;
	  b2->error = drop_error;
	  b3->error = drop_error;

	  buffers += 4;
	  args += 4;
	  n_left_this_frame -= 4;
	}

      while (n_left_this_frame >= 1)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;

	  args[0] = bi0 = buffers[0];

	  b0 = vlib_get_buffer (vm, bi0);
	  b0->error = drop_error;

	  buffers += 1;
	  args += 1;
	  n_left_this_frame -= 1;
	}

      vlib_put_next_frame (vm, node, next_index, n_args_left);
    }

  return n_buffers;
}

static u8 *
format_stats_counter_name (u8 *s, va_list *va)
{
  u8 *id = va_arg (*va, u8 *);

  for (u32 i = 0; id[i] != 0; i++)
    vec_add1 (s, id[i] == ' ' ? ' ' : id[i]);

  return s;
}

/* The error bookkeeping takes three locks, and every path takes them in this
 * order, from the outside in:
 *
 * 1. the stats segment lock, vlib_stats_segment_lock. Error counters live in
 *    a vector in the stats segment, so growing it, and adding or removing the
 *    entries that name counters, take this lock. vlib_register_errors takes it
 *    from its first step to its last.
 *
 * 2. vlib_error_desc_lock. Nodes replace and free their error descriptions
 *    under it, so every copy of a description, and of the node name that
 *    names the descriptions, takes it.
 *
 * 3. vlib_node_name_lock. vlib_node_rename exchanges a node name under it, so
 *    a reader sees the previous or the new name and never one being freed.
 *    A rename also holds it while it frees the names retired by earlier
 *    renames, and that free takes the stats segment lock inside it.
 *
 * vlib_register_errors takes the stats segment lock and then the
 * descriptions. vlib_unregister_errors takes the descriptions and then the
 * names, and runs from vlib_register_errors, with the stats segment lock
 * held, and from vlib_node_rename, without it. vlib_stats_remove_entry takes
 * the stats segment lock again inside, which is the lock already held
 * outermost on the first path and the innermost lock on the second, so it is
 * the only place where the order is not strict from outside in, and it is
 * consistent with both. A caller which already holds a lock, as
 * vlib_unregister_errors does when vlib_register_errors calls it, leaves the
 * outside ones to its caller.
 *
 * A name is read without the worker barrier by vlib_error_counts_get, so it is
 * freed only once no reader can still hold it. A rename frees the names that
 * earlier renames retired, and never those retired in its own call or in a
 * section it reached, so the free runs in a section that started after every
 * reader that could have held them had copied them or would now read the new
 * name. A reader that copied a name before its retirement holds the stats
 * segment lock or the description lock throughout, and a worker main loop
 * refuses to take the stats segment lock while it has work to do, so the free
 * cannot run under such a copy.
 *
 * No holder of the description lock waits for the worker barrier. Callers of
 * the getter normally hold the barrier, which serializes them against each
 * other, and the only holder that has no barrier takes the lock around a
 * single node rename, so a barrier-free reader such as vlib_error_counts_get
 * never spins on a holder that is about to take the barrier. */
static clib_spinlock_t vlib_error_desc_lock;
static clib_spinlock_t vlib_node_name_lock;

/* Names an exchange retired, one vector per node index, freed by a later
 * rename. They are kept apart from the nodes so that vlib_node_rename retires
 * a name without touching the node structure. */
static u8 ***vlib_node_retired_names;

/* Set when a section of this thread retired a name. Names waiting to be freed
 * were retired before that section started, so its own next rename must not
 * free them: they include the names it retired itself, which a reader may
 * still be copying. The call that ends the section clears it again. */
static __thread u8 vlib_node_name_waiting;

/* Whether this thread must not reap the names waiting to be reaped. */
u8
vlib_node_name_waiting_in_section (void)
{
  return vlib_node_name_waiting;
}

void
vlib_node_name_retire (u32 node_index, u8 *name)
{
  vec_validate (vlib_node_retired_names, node_index);
  vec_add1 (vlib_node_retired_names[node_index], name);
  vlib_node_name_waiting = 1;
}

/* The thread holding the name lock section, and how many callers of that
 * thread are still inside it. vlib_node_rename calls a core, and the main
 * loop calls vlib_unregister_errors, inside the section, so the section
 * belongs to the thread and lasts until the last of its callers leaves. */
#define VLIB_NODE_NAME_NO_OWNER ((clib_thread_index_t) ~0)
static __thread clib_thread_index_t vlib_node_name_lock_owner = VLIB_NODE_NAME_NO_OWNER;
static __thread u32 vlib_node_name_lock_depth;

/* The two locks are initialized once, before the first worker thread can take
 * either, so that no thread ever runs a lock against a zero pointer. */
void
vlib_error_lock_init (void)
{
  clib_spinlock_init (&vlib_error_desc_lock);
  clib_spinlock_init (&vlib_node_name_lock);
}

void
vlib_error_desc_lock_get (void)
{
  clib_spinlock_lock (&vlib_error_desc_lock);
}

void
vlib_error_desc_lock_put (void)
{
  clib_spinlock_unlock (&vlib_error_desc_lock);
}

/* Drops the retired names. The caller holds the name lock, so no rename is
 * running, and the section it holds started after the last rename retired
 * them. */
static void
vlib_node_name_free_retired (void)
{
  u32 i, j;

  vlib_stats_segment_lock ();
  for (i = 0; i < vec_len (vlib_node_retired_names); i++)
    {
      u8 **names = vlib_node_retired_names[i];

      for (j = 0; j < vec_len (names); j++)
	vec_free (names[j]);
      vec_free (names);
    }
  vec_free (vlib_node_retired_names);
  vlib_node_retired_names = 0;
  vlib_stats_segment_unlock ();
}

u8
vlib_node_name_lock_get (void)
{
  if (vlib_node_name_lock_owner != VLIB_NODE_NAME_NO_OWNER)
    {
      vlib_node_name_lock_depth++;
      return 0;
    }

  clib_spinlock_lock (&vlib_node_name_lock);

  vlib_node_name_lock_owner = os_get_thread_index ();
  vlib_node_name_lock_depth = 1;
  return 1;
}

/* Leaves a call inside the section. Returns 1 when this call leaves the
 * section, and 0 when a caller of the same thread is still inside it. */
u8
vlib_node_name_lock_put (void)
{
  ASSERT (vlib_node_name_lock_owner == os_get_thread_index ());
  ASSERT (vlib_node_name_lock_depth > 0);

  if (--vlib_node_name_lock_depth > 0)
    return 0;

  vlib_node_name_lock_owner = VLIB_NODE_NAME_NO_OWNER;
  clib_spinlock_unlock (&vlib_node_name_lock);
  return 1;
}

/* Records that the section of a thread that retired names has ended. */
void
vlib_node_name_section_ended (void)
{
  ASSERT (vlib_node_name_lock_owner == VLIB_NODE_NAME_NO_OWNER);

  vlib_node_name_waiting = 0;
}

/* Frees the names earlier renames retired. A rename calls it right after it
 * takes the name lock, so no other rename is running, and its own section has
 * retired nothing yet. */
void
vlib_node_name_reap (void)
{
  vlib_node_name_free_retired ();
}

void
vlib_unregister_errors (vlib_main_t *vm, u32 node_index)
{
  vlib_error_main_t *em = &vm->error_main;
  vlib_node_t *n = vlib_get_node (vm, node_index);
  vlib_error_desc_t *cd;
  u8 names_locked;

  if (n->n_errors > 0)
    {
      /* The error descriptions are freed below, and the formatted error
       * names point into them. */
      vlib_error_desc_lock_get ();

      names_locked = vlib_node_name_lock_get ();
      cd = vec_elt_at_index (em->counters_heap, n->error_heap_index);
      for (u32 i = 0; i < n->n_errors; i++)
	vlib_stats_remove_entry (cd[i].stats_entry_index);
      heap_dealloc (em->counters_heap, n->error_heap_handle);
      n->n_errors = 0;

      vlib_error_desc_lock_put ();

      /* A name retired here is freed by the next rename. */
      if (names_locked)
	vlib_node_name_lock_put ();
    }
}

/* Makes the error codes of a node whose errors were registered after the
 * node was created visible to the node function through node->errors[]. */
void
vlib_node_update_runtime_errors (vlib_main_t *vm, u32 node_index)
{
  vlib_node_t *n = vlib_get_node (vm, node_index);
  vlib_node_runtime_t *rt = vlib_node_get_runtime (vm, node_index);

  ASSERT (vlib_get_thread_index () == 0);

  vec_reset_length (rt->errors);

  if (n->n_errors)
    vec_validate (rt->errors, n->n_errors - 1);

  for (u32 i = 0; i < n->n_errors; i++)
    rt->errors[i] = n->error_heap_index + i;

  vlib_worker_thread_node_runtime_update ();
}

/* Reserves given number of error codes for given node. */
void
vlib_register_errors (vlib_main_t *vm, u32 node_index, u32 n_errors,
		      char *error_strings[], vlib_error_desc_t counters[])
{
  vlib_error_main_t *em = &vm->error_main;
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n = vlib_get_node (vm, node_index);
  vlib_error_desc_t *cd;
  u32 n_threads = vlib_get_n_threads ();
  elog_event_type_t t = {};
  uword l;
  u64 **sc;

  ASSERT (vlib_get_thread_index () == 0);

  vlib_stats_segment_lock ();

  /* Free up any previous error strings. */
  vlib_unregister_errors (vm, node_index);

  /* Only the registered descriptions are replaced below, the legacy names
   * live in the error strings the node was registered with. */
  vlib_error_desc_lock_get ();

  n->n_errors = n_errors;
  n->error_counters = counters;

  if (n_errors == 0)
    {
      vlib_error_desc_lock_put ();
      goto done;
    }

  n->error_heap_index =
    heap_alloc (em->counters_heap, n_errors, n->error_heap_handle);
  l = vec_len (em->counters_heap);
  cd = vec_elt_at_index (em->counters_heap, n->error_heap_index);

  /*  Legacy node */
  if (!counters)
    {
      for (int i = 0; i < n_errors; i++)
	{
	  cd[i].name = error_strings[i];
	  cd[i].desc = error_strings[i];
	  cd[i].severity = VL_COUNTER_SEVERITY_ERROR;
	}
    }
  else
    clib_memcpy (cd, counters, n_errors * sizeof (counters[0]));

  vlib_error_desc_lock_put ();

  vec_validate (vm->error_elog_event_types, l - 1);

  if (em->stats_err_entry_index == 0)
    em->stats_err_entry_index = vlib_stats_add_counter_vector ("/node/errors");

  ASSERT (em->stats_err_entry_index != 0 && em->stats_err_entry_index != ~0);

  vlib_stats_validate (em->stats_err_entry_index, n_threads - 1, l - 1);
  sc = vlib_stats_get_entry_data_pointer (em->stats_err_entry_index);

  for (int i = 0; i < n_threads; i++)
    {
      vlib_main_t *tvm = vlib_get_main_by_index (i);
      vlib_error_main_t *tem = &tvm->error_main;
      tem->counters = sc[i];

      /* Zero counters for re-registrations of errors. */
      if (n->error_heap_index + n_errors <= vec_len (tem->counters_last_clear))
	clib_memcpy (tem->counters + n->error_heap_index,
		     tem->counters_last_clear + n->error_heap_index,
		     n_errors * sizeof (tem->counters[0]));
      else
	clib_memset (tem->counters + n->error_heap_index, 0,
		     n_errors * sizeof (tem->counters[0]));
    }

  /* Register counter indices in the stat segment directory */
  for (int i = 0; i < n_errors; i++)
    cd[i].stats_entry_index = vlib_stats_add_symlink (
      em->stats_err_entry_index, n->error_heap_index + i, "/err/%v/%U",
      n->name, format_stats_counter_name, cd[i].name);

  vec_validate (nm->node_by_error, n->error_heap_index + n_errors - 1);

  for (u32 i = 0; i < n_errors; i++)
    {
      t.format = (char *) format (0, "%v %s: %%d", n->name, cd[i].name);
      vec_free (vm->error_elog_event_types[n->error_heap_index + i].format);
      vm->error_elog_event_types[n->error_heap_index + i] = t;
      nm->node_by_error[n->error_heap_index + i] = n->index;
    }

done:
  vlib_stats_segment_unlock ();
}

uword
unformat_vlib_error (unformat_input_t *input, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  const vlib_error_main_t *em = &vm->error_main;
  vlib_error_t *error_index = va_arg (*args, vlib_error_t *);
  const vlib_node_t *node;
  char *error_name, *desc;
  u32 node_index;
  vlib_error_t i;
  int found = 0;

  if (!unformat (input, "%U.%s", unformat_vlib_node, vm, &node_index,
		 &error_name))
    return 0;

  node = vlib_get_node (vm, node_index);

  /* The error names belong to the error descriptions, which
   * vlib_unregister_errors frees. */
  vlib_error_desc_lock_get ();
  for (i = 0; i < node->n_errors; i++)
    {
      vlib_error_t ei = node->error_heap_index + i;

      desc = em->counters_heap[ei].name;
      if (desc && strcmp (desc, error_name) == 0)
	{
	  *error_index = ei;
	  found = 1;
	  break;
	}
    }
  vlib_error_desc_lock_put ();

  vec_free (error_name);
  return found;
}

static char *
sev2str (enum vl_counter_severity_e s)
{
  switch (s)
    {
    case VL_COUNTER_SEVERITY_ERROR:
      return "error";
    case VL_COUNTER_SEVERITY_WARN:
      return "warn";
    case VL_COUNTER_SEVERITY_INFO:
      return "info";
    default:
      return "unknown";
    }
}

/* Error counters and the node data used to report them, copied while the
 * workers run, so that formatting reads nothing which a worker or an error
 * registration can change. */
typedef struct
{
  /* Error count indexed by error index, less the count recorded at the last
   * clear of its thread. */
  u64 *counts;

  /* Name and description of each entry, indexed by error index. */
  char **names;
  char **descs;

  /* Severity indexed by error index. */
  enum vl_counter_severity_e *severities;

  /* Node indices, in node index order. */
  u32 *nodes;

  /* Number of error counters of each node in nodes. */
  u8 *n_errors;

  /* Error index of the first error counter of each node in nodes. */
  u32 *error_heap_index;
} vlib_error_counts_t;

static void
vlib_error_counts_free (vlib_error_counts_t *c)
{
  char **d;

  vec_foreach (d, c->names)
    vec_free (*d);
  vec_foreach (d, c->descs)
    vec_free (*d);
  vec_free (c->counts);
  vec_free (c->names);
  vec_free (c->descs);
  vec_free (c->severities);
  vec_free (c->nodes);
  vec_free (c->n_errors);
  vec_free (c->error_heap_index);
}

/* Counters are indexed by error index, so each thread contributes its own
 * counter less the value it recorded at the last counter clear. */
static void
vlib_error_counts_get (vlib_main_t *vm, vlib_error_counts_t *c)
{
  vlib_main_t *main_vm = vlib_get_first_main ();
  vlib_error_main_t *em = &main_vm->error_main;
  vlib_node_t *n;
  char *name;
  u32 i, index;

  vec_validate (c->counts, vec_len (em->counters) - 1);
  vec_validate (c->names, vec_len (em->counters) - 1);
  vec_validate (c->descs, vec_len (em->counters) - 1);
  vec_validate (c->severities, vec_len (em->counters) - 1);

  /* Counter vectors in the stats segment are re-allocated under the segment
   * lock when they grow, so take the counts with the lock held. */
  vlib_stats_segment_lock ();

  for (u32 t = 0; t < vlib_get_n_threads (); t++)
    {
      em = &vlib_get_main_by_index (t)->error_main;

      for (i = 0; i < vec_len (em->counters); i++)
	{
	  c->counts[i] += em->counters[i];
	  if (i < vec_len (em->counters_last_clear))
	    c->counts[i] -= em->counters_last_clear[i];
	}
    }

  vlib_stats_segment_unlock ();

  /* Unregistering a node frees its entries in counters_heap, and registering
   * one replaces them, so read them under the description lock. The node name
   * is copied under the same lock, and vlib_node_rename takes the lock to
   * exchange it, rather than replacing it under the reader. */
  vlib_error_desc_lock_get ();

  vec_foreach_pointer (n, main_vm->node_main.nodes)
    {
      if (n->n_errors == 0)
	continue;

      vec_add1 (c->nodes, n->index);
      vec_add1 (c->n_errors, n->n_errors);
      vec_add1 (c->error_heap_index, n->error_heap_index);

      name = (char *) vec_dup (n->name);
      for (u32 code = 0; code < n->n_errors; code++)
	{
	  index = n->error_heap_index + code;
	  c->names[index] = (char *) vec_dup (name);

	  if (n->error_counters)
	    {
	      c->descs[index] = (char *) vec_dup (n->error_counters[code].desc);
	      c->severities[index] = n->error_counters[code].severity;
	    }
	  else
	    {
	      /* Legacy nodes register an error string, which stays the
	       * description of the counter after the node is renamed. */
	      c->descs[index] = (char *) vec_dup (em->counters_heap[index].desc);
	      c->severities[index] = VL_COUNTER_SEVERITY_ERROR;
	    }
	}
      vec_free (name);
    }

  vlib_error_desc_lock_put ();
}

/* Worker threads are created together with their vlib_main_t, so their names
 * can be read without a barrier. */
static u8 *
vlib_error_thread_name (u32 thread_index)
{
  ASSERT (thread_index < vec_len (vlib_worker_threads));

  if (thread_index >= vec_len (vlib_worker_threads))
    return (u8 *) "";

  return vlib_worker_threads[thread_index].name;
}

static clib_error_t *
show_errors (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 code, i;
  u64 sum;
  int verbose = 0;
  u64 *sums = 0;
  vlib_error_counts_t c = {};

  if (unformat (input, "verbose %d", &verbose))
    ;
  else if (unformat (input, "verbose"))
    verbose = 1;

  if (verbose)
    vlib_cli_output (vm, "%=10s%=35s%=35s%=10s%=6s", "Count", "Node",
		     "Reason", "Severity", "Index");
  else
    vlib_cli_output (vm, "%=10s%=35s%=35s%=10s", "Count", "Node", "Reason", "Severity");

  vlib_error_counts_get (vm, &c);
  vec_validate (sums, vec_len (c.counts) - 1);

  for (u32 t = 0; t < vlib_get_n_threads (); t++)
    {
      if (verbose)
	vlib_cli_output (vm, "Thread %u (%v):", t, vlib_error_thread_name (t));

      for (u32 nj = 0; nj < vec_len (c.nodes); nj++)
	{
	  for (code = 0; code < c.n_errors[nj]; code++)
	    {
	      i = c.error_heap_index[nj] + code;
	      sums[i] += c.counts[i];

	      if (c.counts[i] == 0 && verbose < 2)
		continue;

	      if (verbose)
		vlib_cli_output (vm, "%10lu%=35v%=35s%=10s%=6d", c.counts[i], c.names[i],
				 c.descs[i], sev2str (c.severities[i]), i);
	      else
		vlib_cli_output (vm, "%10lu%=35v%=35s%=10s", c.counts[i], c.names[i], c.descs[i],
				 sev2str (c.severities[i]));
	    }
	}
    }

  if (verbose)
    vlib_cli_output (vm, "Total:");

  for (u32 nj = 0; nj < vec_len (c.nodes); nj++)
    {
      for (code = 0; code < c.n_errors[nj]; code++)
	{
	  i = c.error_heap_index[nj] + code;
	  sum = sums[i];
	  if (sum)
	    {
	      if (verbose)
		vlib_cli_output (vm, "%10lu%=40v%=20s%=10d", sum, c.names[i], c.descs[i], i);
	    }
	}
    }

  vec_free (sums);
  vlib_error_counts_free (&c);

  return 0;
}

VLIB_CLI_COMMAND (vlib_cli_show_errors) = {
  .path = "show errors",
  .short_help = "Show error counts",
  .function = show_errors,
  .is_mp_safe = 1,
};

VLIB_CLI_COMMAND (cli_show_node_counters, static) = {
  .path = "show node counters",
  .short_help = "Show node counters",
  .function = show_errors,
  .is_mp_safe = 1,
};

static clib_error_t *
clear_error_counters (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_error_main_t *em;
  u32 i;

  foreach_vlib_main ()
    {
      em = &this_vlib_main->error_main;
      vec_validate (em->counters_last_clear, vec_len (em->counters) - 1);
      for (i = 0; i < vec_len (em->counters); i++)
	em->counters_last_clear[i] = em->counters[i];
    }
  return 0;
}

VLIB_CLI_COMMAND (cli_clear_error_counters, static) = {
  .path = "clear errors",
  .short_help = "Clear error counters",
  .function = clear_error_counters,
};

VLIB_CLI_COMMAND (cli_clear_node_counters, static) = {
  .path = "clear node counters",
  .short_help = "Clear node counters",
  .function = clear_error_counters,
};
