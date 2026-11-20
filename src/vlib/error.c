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

/* The counts the report shows and the nodes it shows them under, read while
 * the workers run. Nothing of it is a name or a description: the report reads
 * those in place from counters_heap while it holds the description lock, so a
 * snapshot allocates for the counters it reports, and a counter of it costs a
 * count and a sum, not a copy of its name and its description. */
typedef struct
{
  /* Count of every error, over the threads, less the count a thread recorded
   * at its last counter clear, indexed by error index. */
  u64 *counts;

  /* Count of every error over the threads, indexed by error index. */
  u64 *sums;

  /* Node indices, in node index order. */
  u32 *nodes;

  /* Entry of counters_heap that holds the counters of each node in nodes,
   * in place. */
  vlib_error_desc_t **entries;

  /* Number of error counters of each node in nodes. */
  u8 *n_errors;

  /* Error index of the first error counter of each node in nodes. */
  u32 *error_heap_index;
} vlib_error_counts_t;

static void
vlib_error_counts_free (vlib_error_counts_t *c)
{
  vec_free (c->counts);
  vec_free (c->sums);
  vec_free (c->entries);
  vec_free (c->nodes);
  vec_free (c->n_errors);
  vec_free (c->error_heap_index);
}

/* True when every counter of the node at a position of the snapshot lies
 * within the vectors indexed by error index. A node whose counters lie past
 * them registered a table between the size of the snapshot and its list, which
 * the description lock lets through, so the report leaves its counters out
 * rather than read past the snapshot.
 *
 * A report whose size was skipped, because nothing measured a counter, is the
 * same condition rather than a path of its own: the skip leaves every vector
 * it would have sized empty, so the positions the walk is given all fall past
 * them and answer false, and a vector of length zero can name no counter to
 * read. */
static int
vlib_error_lists (vlib_error_counts_t *c, u32 nj)
{
  return (u64) c->error_heap_index[nj] + c->n_errors[nj] <= vec_len (c->counts);
}

/* True when the counter at an error index is one the snapshot holds and whose
 * counters_heap entry names it. The bound check is a proof: a node's error
 * index is its error_heap_index plus its code, and the vectors are at least as
 * long as counters_heap, so the list never names an index past either.
 *
 * The name test is not a proof that the entry is live. heap_dealloc does not
 * clear the block it frees, so an entry that a registration freed can keep a
 * non-zero name until something writes over it. What the test rules out is an
 * entry that no registration of the node ever set, and what the description
 * lock rules out is the publication of a node's table: the fields the walk
 * selects a node by and the entries it names are written under it. It does not
 * cover the stats_entry_index that vlib_register_errors writes after it
 * releases the lock, so a re-registration running then can have the report
 * show one counter of the node with the index before that write and another
 * with the one after it. That is a torn line of the report, not a free and not
 * a read past anything: together the lock and the test leave the description
 * of a counter of the node, or the stale copy of one, and both are strings the
 * heap still holds. A stale one is shown only when the node still holds the
 * counter, and such an entry costs no read past what the locks bound. */
static int
vlib_error_lists_at (vlib_error_main_t *em, u32 index)
{
  return index < vec_len (em->counters_heap) && em->counters_heap[index].name != 0;
}

/* True when the node holds a counter the report reads from counters_heap: it
 * registered a table of counters, rather than error strings, and its first
 * entry names one. The size of the snapshot and its list are both taken from
 * this test, so the two cannot disagree about which nodes are reported. */
static int
vlib_error_holds_counters (vlib_error_main_t *em, vlib_node_t *n)
{
  return n->n_errors != 0 && n->error_counters != 0 &&
	 vlib_error_lists_at (em, n->error_heap_index);
}

/* Number of the two vectors indexed by error index: the error index the
 * highest counter reaches, over the nodes whose counters the report lists.
 * The caller holds the description lock, so a registration cannot change the
 * fields it reads.
 *
 * A node is counted when vlib_error_holds_counters says it holds a counter, and
 * it reaches the error index of its whole table. A node whose table has since
 * gone out of scope still reaches that index, and its counters past the end of
 * the table are left out by the list, which names only the entries the heap
 * holds. The size is therefore the upper bound of everything the list can
 * name, not the exact set. */
static u32
vlib_error_counts_size (vlib_node_main_t *nm, vlib_error_main_t *em)
{
  vlib_node_t **node, *n;
  u32 index, n_counters = 0;

  vec_foreach (node, nm->nodes)
    {
      n = *node;

      if (!vlib_error_holds_counters (em, n))
	continue;

      index = n->error_heap_index + n->n_errors;
      if (index > n_counters)
	n_counters = index;
    }

  return n_counters;
}

/* Length of the longest counter vector of the threads, which is the number of
 * error indices the counters of the threads hold. The caller holds the stats
 * segment lock, which keeps the vectors from being re-allocated while they are
 * measured. A thread binds its counter vector inside vlib_register_errors,
 * which cannot run while its lock is held. */
static u32
vlib_error_counts_measure (void)
{
  u32 n_counters, n;

  n_counters = 0;

  for (u32 t = 0; t < vlib_get_n_threads (); t++)
    {
      n = vec_len (vlib_get_main_by_index (t)->error_main.counters);
      if (n > n_counters)
	n_counters = n;
    }

  return n_counters;
}

/* Reads the counter of every thread, less the count it recorded at its last
 * counter clear, into a snapshot that already holds the index of every counter
 * the threads have: the caller has sized it for vlib_error_counts_measure and
 * for the counters the nodes hold. The read is bounded by the length of that
 * snapshot and of the vector of the thread, so it writes nothing past either.
 * The caller holds the stats segment lock, which keeps the counter vectors
 * from being re-allocated under the read. A thread whose counter vector is
 * empty has registered no error, and counts nothing. */
static void
vlib_error_counts_read (vlib_error_counts_t *c)
{
  vlib_error_main_t *em;
  u32 n_last_clear, i, i_max;

  for (u32 t = 0; t < vlib_get_n_threads (); t++)
    {
      em = &vlib_get_main_by_index (t)->error_main;

      i_max = vec_len (em->counters);
      if (i_max > vec_len (c->counts))
	i_max = vec_len (c->counts);

      for (i = 0; i < i_max; i++)
	c->counts[i] += em->counters[i];

      n_last_clear = vec_len (em->counters_last_clear);
      if (n_last_clear > i_max)
	n_last_clear = i_max;

      for (i = 0; i < n_last_clear; i++)
	c->counts[i] -= em->counters_last_clear[i];
    }
}

/* Lists the nodes the report shows, and counts their errors over the threads.
 * The caller holds the description lock, which excludes the registration and
 * the unregistration of a node, so the entries of counters_heap cannot be
 * freed while they are read. Neither a name nor a description is copied:
 * the counters_heap entry holds both, and the report reads it in place while
 * it holds the description lock.
 *
 * A node is listed with the counters whose counters_heap entry names them, up
 * to the first one that does not, and is left out when it has none. An entry
 * past the end of counters_heap names nothing, so the list stops where the heap
 * does, and an entry past the end of the snapshot is not reachable: the
 * snapshot is at least as long as the heap. */
static void
vlib_error_counts_list (vlib_error_counts_t *c, vlib_node_main_t *nm, vlib_error_main_t *em)
{
  vlib_node_t **node, *n;
  u32 code, i;

  vec_foreach (node, nm->nodes)
    {
      n = *node;

      if (!vlib_error_holds_counters (em, n))
	continue;

      for (code = 0; code < n->n_errors; code++)
	if (!vlib_error_lists_at (em, n->error_heap_index + code))
	  break;

      if (code == 0)
	continue;

      vec_add1 (c->nodes, n->index);
      vec_add1 (c->entries, vec_elt_at_index (em->counters_heap, n->error_heap_index));
      vec_add1 (c->n_errors, code);
      vec_add1 (c->error_heap_index, n->error_heap_index);

      for (i = 0; i < code; i++)
	c->sums[n->error_heap_index + i] += c->counts[n->error_heap_index + i];
    }
}

/* Reads the counters the report shows: their counts over the threads, the
 * nodes they belong to, and their sums over the threads. The caller reads the
 * descriptions of them from counters_heap after this returns, and holds the
 * description lock until it has formatted them, so that no registration can
 * free an entry the report names.
 *
 * The read is split into two phases that never hold both locks:
 *
 * 1. the counters of the threads, under the stats segment lock alone;
 * 2. the nodes and their sums, under the description lock alone.
 *
 * Both locks are not held at once because their takers disagree on the order:
 * vlib_register_errors takes the segment lock and then the description lock,
 * while vlib_unregister_errors takes the description lock and then reaches the
 * segment lock through vlib_stats_remove_entry. A reader that held both in
 * either order would wait for a holder of the other, and the two would
 * deadlock. Master releases the segment lock before it takes the description
 * lock for the same reason, and this keeps that shape.
 *
 * The segment lock is re-entrant for one thread, so a registration made on the
 * thread that runs the report nests safely; the two phases are what covers two
 * threads. */
static void
vlib_error_counts_get (vlib_error_counts_t *c)
{
  vlib_main_t *main_vm = vlib_get_first_main ();
  vlib_node_main_t *nm = &main_vm->node_main;
  vlib_error_main_t *em = &main_vm->error_main;
  u32 n_counters, n_heap;

  /* Phase 1, the segment lock alone: the counters of the threads. The vector of
   * a thread lives in the stats segment, and vlib_register_errors grows it under
   * this lock, so the measure and the read below cannot race a grow of it.
   * counters_heap is a vector of the main VM, which vlib_register_errors grows
   * under the same lock, so its length is stable here too.
   *
   * The read is given a snapshot that already holds every index it writes: the
   * read is bounded by the length of the snapshot, so it would write nothing
   * at all into a vector the size had not allocated yet. A thread whose counter
   * vector is shorter than the longest one leaves its entries past that length
   * at zero. */
  vlib_stats_segment_lock ();

  n_counters = vlib_error_counts_measure ();

  n_heap = vec_len (em->counters_heap);
  if (n_counters < n_heap)
    n_counters = n_heap;

  if (n_counters)
    {
      vec_validate (c->counts, n_counters - 1);
      vec_validate (c->sums, n_counters - 1);

      vlib_error_counts_read (c);
    }

  vlib_stats_segment_unlock ();

  /* Phase 2, the description lock alone: the nodes that report a counter, and
   * the sum of each over the threads. This is the lock vlib_register_errors and
   * vlib_unregister_errors take to replace and free the entries of
   * counters_heap, so the entries read here are held for the whole phase.
   *
   * The lock also excludes a half-registered node from the walk.
   * vlib_register_errors takes it before it publishes n_errors and
   * error_counters, and its heap index and counters_heap entries are written
   * inside the section, so a node the walk reaches either has none of them or
   * has all of them, and an entry it reads names what the node holds. One
   * write of vlib_register_errors falls outside the section, the
   * stats_entry_index of each of its counters, so a re-registration of a node
   * the walk has already passed can leave a counter of that node printed with
   * the index it had before the write and another with the one after it. That
   * is a torn line of the report, not a free and not a read past the vectors:
   * the lock still holds the entries it names, and the node still holds the
   * counters. Master held the description lock across its whole walk and had
   * no such window; closing it here would mean holding the lock across the
   * rest of vlib_register_errors, which takes the stats segment lock inside
   * that region and would bring back the deadlock the two phases exist to
   * avoid.
   *
   * This phase writes no counter vector, reads no counter value of a thread and
   * re-measures no vector of a thread: it runs with the stats segment lock
   * released, and vlib_stats_validate may re-allocate the counters of a thread
   * under that lock. Its input is the c->counts that phase 1 read, and the only
   * thing it takes from it is its length. It writes only c->sums, its own
   * vector, grown here to the length of the counts it sums. A node that
   * registered after phase 1 sums the zero that phase 1 validated its index
   * to, and a node whose index lies past those vectors is left out by
   * vlib_error_lists. A report whose phase 1 was skipped, because nothing
   * measured a counter, validated neither vector; c->sums stays empty here and
   * vlib_error_lists leaves out every node, so no count is summed at all.
   *
   * The size is taken again here rather than kept from phase 1, because a
   * registration may have added a node between the phases, and this is the
   * answer that the listing below is checked against. The vectors are grown to
   * the highest error index a node reaches, and to the length of counters_heap,
   * so every index the list can name is held: the index is a node's
   * error_heap_index plus its code, it lies below the heap, and a node that
   * registered an entry of the heap and then did not reach the end of
   * vlib_register_errors is still within the heap. vec_validate only grows a
   * vector, so the counts the read wrote are kept.
   *
   * The bound this phase reaches is therefore the bound phase 1 reached, which
   * was the longest counter vector of the threads raised to the length of
   * counters_heap: this phase takes the highest error index of the nodes,
   * raises it to the same heap length, and a node never registers past the end
   * of the heap. The two can differ only when the heap is empty, where both
   * are zero. The size is taken again for the nodes, not to size the report
   * differently, so that the walk is checked against what the lock it holds
   * sees. */
  vlib_error_desc_lock_get ();

  n_counters = vlib_error_counts_size (nm, em);

  n_heap = vec_len (em->counters_heap);
  if (n_counters < n_heap)
    n_counters = n_heap;

  if (n_counters)
    vec_validate (c->sums, n_counters - 1);

  vlib_error_counts_list (c, nm, em);

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

/* Formats one counter of the report from its entry in counters_heap. The entry
 * is read in place while the caller holds the description lock, and it holds
 * the name and the description of the counter, so reporting a counter
 * allocates nothing for either. */
static void
vlib_error_format (vlib_main_t *vm, vlib_error_desc_t *cd, u32 index, u64 count, int verbose,
		   int total)
{
  if (total)
    {
      if (verbose)
	vlib_cli_output (vm, "%10lu%=40s%=20s%=10d", count, cd->name, cd->desc, index);
      return;
    }

  if (verbose)
    vlib_cli_output (vm, "%10lu%=35s%=35s%=10s%=6d", count, cd->name, cd->desc,
		     sev2str (cd->severity), index);
  else
    vlib_cli_output (vm, "%10lu%=35s%=35s%=10s", count, cd->name, cd->desc, sev2str (cd->severity));
}

/* Formats the counters of the node at a position of the snapshot as one
 * thread counted them, leaving out the counters that thread read as zero
 * unless verbose 2 asks for them. */
static void
vlib_error_format_thread (vlib_main_t *vm, vlib_error_counts_t *c, u32 nj, int verbose)
{
  u32 code, index;

  for (code = 0; code < c->n_errors[nj]; code++)
    {
      index = c->error_heap_index[nj] + code;

      if (c->counts[index] == 0 && verbose < 2)
	continue;

      vlib_error_format (vm, &c->entries[nj][code], index, c->counts[index], verbose, 0);
    }
}

/* Formats the count of the counters of every thread. */
static void
vlib_error_format_total (vlib_main_t *vm, vlib_error_counts_t *c, int verbose)
{
  u64 sum;
  u32 code, index;

  for (u32 nj = 0; nj < vec_len (c->nodes); nj++)
    {
      if (!vlib_error_lists (c, nj))
	continue;

      for (code = 0; code < c->n_errors[nj]; code++)
	{
	  index = c->error_heap_index[nj] + code;
	  sum = c->sums[index];
	  if (sum)
	    vlib_error_format (vm, &c->entries[nj][code], index, sum, verbose, 1);
	}
    }
}

static clib_error_t *
show_errors (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  int verbose = 0;
  vlib_error_counts_t c = {};

  if (unformat (input, "verbose %d", &verbose))
    ;
  else if (unformat (input, "verbose"))
    verbose = 1;

  vlib_error_counts_get (&c);

  /* The entries of counters_heap the report names are read after the lock the
   * counters were read under is released, and a registration or unregistration
   * in between would free them. The lock is therefore held across the whole
   * report: nothing here copies a name or a description, and nothing has to.
   * The names of the threads it prints are not locked. */
  vlib_error_desc_lock_get ();

  if (verbose)
    vlib_cli_output (vm, "%=10s%=35s%=35s%=10s%=6s", "Count", "Node",
		     "Reason", "Severity", "Index");
  else
    vlib_cli_output (vm, "%=10s%=35s%=35s%=10s", "Count", "Node", "Reason", "Severity");

  for (u32 t = 0; t < vlib_get_n_threads (); t++)
    {
      if (verbose)
	vlib_cli_output (vm, "Thread %u (%v):", t, vlib_error_thread_name (t));

      for (u32 nj = 0; nj < vec_len (c.nodes); nj++)
	if (vlib_error_lists (&c, nj))
	  vlib_error_format_thread (vm, &c, nj, verbose);
    }

  if (verbose)
    vlib_cli_output (vm, "Total:");

  vlib_error_format_total (vm, &c, verbose);

  vlib_error_desc_lock_put ();

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
clear_error_counters (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_error_main_t *em;
  u32 i;

  foreach_vlib_main ()
    {
      em = &this_vlib_main->error_main;

      /* A thread that has registered no error has no counter vector, and its
       * length less one is ~0, which vec_validate would ask the allocator for
       * as a 4 billion entry vector. It has nothing to clear either. */
      if (vec_len (em->counters) == 0)
	continue;

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
