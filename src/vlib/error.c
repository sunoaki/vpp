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

/* One counter of the report, copied out of counters_heap while the description
 * lock is held. The counter name and the reason are strings a registration owns,
 * and vlib_unregister_errors frees the entries of counters_heap that point at
 * them, so the report copies those strings into a buffer of its own as it takes
 * the snapshot. It has to: the report hands the main loop back as it formats,
 * and a registration or an unregistration that runs between two chunks could
 * free a string the report would otherwise still name. The description lock
 * keeps that from happening while the copies are made.
 *
 * The node name is covered the same way. vlib_node_rename exchanges it under
 * the description lock, retires the previous one, and a later rename frees the
 * retired names while it holds the same lock, so the name is copied under the
 * lock too. Each string is named by offset into a buffer of the snapshot, so
 * that growing that buffer does not move what the entries point at. */
typedef struct
{
  /* Offset in the name buffer of the snapshot of the name of this counter's
   * node. The name ends in a NUL there. */
  u32 node_name_offset;

  /* Offset in the string buffer of the snapshot of the name the registration
   * gave the counter, which is the symbol of its stats entry. A legacy
   * registration gives one error string, which becomes both the name and the
   * reason of the counter; name_is_desc records that, so the Counter column is
   * left empty rather than print the string twice. */
  u32 name_offset;

  /* Offset in the string buffer of the snapshot of the reason the registration
   * gave the counter. */
  u32 desc_offset;

  /* Whether the registration gave the counter a name of its own, which the
   * Counter column shows. */
  u8 name_is_desc;

  enum vl_counter_severity_e severity;
} vlib_error_entry_t;

/* Room the snapshot keeps for one node name, and for one counter name or one
 * reason, past which the copy is cut. Neither is the width of the column the
 * string is formatted into: the node name is formatted into a column of 35
 * characters, and justify() (vppinfra/format.c) cuts a longer name there, so a
 * name of 35 characters or more shows its first 35. Seven registrations in the
 * tree exceed that, the longest being 52 characters, and two pairs of them share
 * their first 35 and so render alike; that is the column's behaviour and not a
 * bound this buffer sets. The reason and the counter name are formatted into
 * columns of 35 and 32 characters, and are cut here far past those widths. The
 * room is per string copied, and the buffer holds one node name per listed node
 * and the strings of its counters, so it is bounded by the counters the heap
 * holds. */
#define VLIB_ERROR_NODE_NAME_BYTES 64
#define VLIB_ERROR_STRING_BYTES	   64

/* Width of the Counter column, the trailing column that names the counter of a
 * line. It follows the Severity column, so the Node and Reason columns keep the
 * widths and the order they had, and a Reason a registration wrote wider than
 * its column is still cut where it was. The longest symbol a registration
 * passes is under thirty characters, and a longer one is cut here rather than
 * run past the room a line is given. */
#define VLIB_ERROR_FORMAT_COUNTER_COLUMN 32

/* The string at an offset of a buffer of the snapshot, or the empty string when
 * the offset lies past it, which no entry the list wrote does. */
static char *
vlib_error_snapshot_string (u8 *buf, u32 offset)
{
  if (offset >= vec_len (buf))
    return "";

  return (char *) buf + offset;
}

/* Appends a NUL-terminated string a registration gave, cut at the room the
 * snapshot keeps for one string, to the string buffer, and returns the offset
 * it was written at. The caller has taken the room for every string it appends,
 * so this writes within it and allocates nothing: the description lock thus
 * covers the copy and not a grow of the buffer. A string that is NULL, which no
 * registration in the tree passes, is copied as the empty string. */
static u32
vlib_error_snapshot_append (u8 **bufp, char *str)
{
  u8 *buf = *bufp;
  u32 offset = vec_len (buf);
  u32 bytes = 0;

  if (str)
    bytes = clib_min (strlen (str), VLIB_ERROR_STRING_BYTES - 1);

  if (bytes)
    vec_add (buf, str, bytes);
  vec_add1 (buf, 0);

  *bufp = buf;

  return offset;
}

/* The counter name the report shows in its Counter column, or the empty string
 * when the name adds nothing to the reason. A legacy registration passes one
 * error string, which vlib_register_errors copies into both the name and the
 * reason of the counter, so showing the column would print that string twice.
 * A node registered with a table of counters names the symbol of its stats
 * entry, which its reason does not repeat. */
static char *
error_counter_name (u8 *strings, vlib_error_entry_t *entry)
{
  if (entry->name_is_desc)
    return "";

  return vlib_error_snapshot_string (strings, entry->name_offset);
}

/* Room one line of a counter takes before it. The columns of a counter line are
 * the count, the node name, the reason of the counter and its severity, which
 * the format string below fixes at 10, 35, 35 and 10 characters; verbose adds
 * the error index at 6, and the Counter column trails all of them. Those come
 * to 10 + 35 + 35 + 10 + 1 + 32 = 123 characters, where the one is the space
 * the Counter column puts before its name, and 129 with the index. justify()
 * cuts every column at its width, the count included, so no column of a line
 * runs past it and the line is at most those 129 characters and the newline:
 * 10 + 35 + 35 + 10 + 6 + 1 + 32 + 1 = 130 bytes. The room below is that, with
 * margin. */
#define VLIB_ERROR_FORMAT_LINE_BYTES 160

/* The counts the report shows, the nodes it shows them under, and the entries
 * of counters_heap the counters are read from. The report copies those entries
 * into a vector of its own, together with the strings they name, so that after
 * vlib_error_counts_get returns it holds no lock and names no block or string a
 * registration can free. That matters because the report formats the snapshot
 * across several chunks of the main loop, and a registration or a rename that
 * runs between two of them frees what it replaced. */
typedef struct
{
  /* Count of every error, over the threads, less the count a thread recorded
   * at its last counter clear, indexed by error index. */
  u64 *counts;

  /* Count of every error over the threads, indexed by error index. */
  u64 *sums;

  /* Node indices, in node index order. */
  u32 *nodes;

  /* Number of error counters of each node in nodes. */
  u8 *n_errors;

  /* Error index of the first error counter of each node in nodes. */
  u32 *error_heap_index;

  /* One entry per counter the report shows, in the order the counters are
   * listed: the counters of the first node in nodes, then those of the next. */
  vlib_error_entry_t *entries;

  /* Index in entries of the first counter of each node in nodes. */
  u32 *entry_index;

  /* The node names the entries name, one per listed node, each ending in a NUL.
   * An entry names its node's name by offset here, so that growing the buffer
   * does not move what the entries point at. */
  u8 *node_names;

  /* The counter names and reasons the entries name, each ending in a NUL. An
   * entry names them by offset here, for the same reason. */
  u8 *strings;
} vlib_error_counts_t;

static void
vlib_error_counts_free (vlib_error_counts_t *c)
{
  vec_free (c->counts);
  vec_free (c->sums);
  vec_free (c->entries);
  vec_free (c->entry_index);
  vec_free (c->nodes);
  vec_free (c->n_errors);
  vec_free (c->error_heap_index);
  vec_free (c->node_names);
  vec_free (c->strings);
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

/* The entry the report shows for a counter of the node at a position of the
 * snapshot. The caller has given the position to vlib_error_lists, so the
 * position is below the length of the vectors indexed by position, which the
 * list filled together: nodes, entry_index, n_errors and error_heap_index each
 * take one entry per listed node. The list sets the length of entries to the
 * last entry it writes, so an offset below the count of the position, added to
 * the first entry of that node, is below the length of entries. The test is
 * kept anyway, so that a report leaves a counter out rather than read past a
 * vector if a path ever breaks that. */
static vlib_error_entry_t *
vlib_error_counting_entry (vlib_error_counts_t *c, u32 nj, u32 code)
{
  u32 index;

  ASSERT (code < c->n_errors[nj]);

  index = c->entry_index[nj] + code;
  if (index >= vec_len (c->entries))
    return 0;

  return vec_elt_at_index (c->entries, index);
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
 * registered at least one error, and its first entry names one. The size of the
 * snapshot and its list are both taken from this test, so the two cannot
 * disagree about which nodes are reported.
 *
 * Both registration shapes pass here. A node registered with a table of
 * counters has n->error_counters set and entries that name their counters. A
 * legacy node registered with error strings has n->error_counters clear and
 * entries that vlib_register_errors filled from those strings, so its counters
 * name themselves just the same. Selecting on n->error_counters rather than on
 * the entry would drop every legacy node.
 *
 * No node that never registered an error reaches this test. vlib_register_errors
 * is the only writer of n_errors, it sets the field to the count it registered,
 * and vlib_unregister_errors sets it back to zero; the node structure itself is
 * zeroed when it is created. A node that never registered therefore answers
 * false on n_errors alone, and one that unregistered answers false the same way
 * even though heap_dealloc leaves the block it freed readable. What remains for
 * vlib_error_lists_at is to rule out a node whose error_heap_index lies past
 * the heap, which a registration in progress under the same lock cannot
 * publish, and an entry whose name is still zero because the registration that
 * allocated it has not reached its copy. */
static int
vlib_error_holds_counters (vlib_error_main_t *em, vlib_node_t *n)
{
  return n->n_errors != 0 && vlib_error_lists_at (em, n->error_heap_index);
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
 * freed while they are read. The entry of every listed counter is copied into
 * entries, the vector of the snapshot, and entry_index records where the
 * counters of each listed node begin in it, so the report holds the entries it
 * shows once it is done with the lock, and only the strings they point into
 * stay in counters_heap.
 *
 * The room of the vectors is taken by phase 1, under the segment lock, so the
 * lock held here covers the copies and the counts, and no allocation on that
 * path. A registration that grows the heap between the phases needs more room
 * than phase 1 took, and phase 2 takes it for that case only, before this walk
 * starts, so the walk itself allocates nothing.
 *
 * A node is listed with the counters whose counters_heap entry names them, up
 * to the first one that does not, and is left out when it has none. The walk
 * stops at that entry rather than skipping it, which assumes the entries of a
 * node are named from its error_heap_index on without a gap.
 * vlib_register_errors is the only writer of such a block: it holds the
 * description lock for the allocation and for the copies, and the walk holds
 * that lock too, so it sees no block half filled. The one way to a gap is an
 * error string that is NULL, which no registration in the tree passes; that
 * would lose the counters of the node past the entry, and not the report. An
 * entry past the end of counters_heap names nothing, so the list stops where
 * the heap does, and an entry past the end of the snapshot is not reachable: the
 * snapshot is at least as long as the heap. */
static void
vlib_error_counts_list (vlib_error_counts_t *c, vlib_node_main_t *nm, vlib_error_main_t *em)
{
  vlib_error_desc_t *cd;
  vlib_error_entry_t *entry;
  vlib_node_t **node, *n;
  u32 code, i, at, n_listed, name_bytes, name_offset, room;

  at = 0;
  room = vec_max_len (c->entries);

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

      /* The room of the vectors is that of the heap, and the counters the list
       * shows are disjoint ranges of it, so a listed node finds the room it
       * needs taken already. It needs more only when a registration grew the
       * heap after phase 1 measured it, and phase 2 sizes c->sums for that case
       * but leaves these vectors at the room phase 1 took, so the grow below is
       * what covers them. The name buffer needs nothing here: phase 2 sized it
       * from the same measure, and a listed node holds at least one counter, so
       * that buffer holds a name for every counter the measure reached. */
      if (at + code > room)
	{
	  n_listed = vec_len (c->nodes);
	  room = at + code;

	  vec_validate (c->entries, room - 1);
	  vec_validate (c->entry_index, room - 1);
	  vec_validate (c->nodes, room - 1);
	  vec_validate (c->n_errors, room - 1);
	  vec_validate (c->error_heap_index, room - 1);

	  /* The room past the entries taken is not part of the report. The
	   * length of c->entries is not cut back here: the copy below writes
	   * up to at + code, and the length is raised to that before it. The name
	   * buffer keeps the length it has, because the names already in it are
	   * named by the entries already listed, and the copy below appends to
	   * the room phase 2 took. */
	  vec_set_len (c->entry_index, n_listed);
	  vec_set_len (c->nodes, n_listed);
	  vec_set_len (c->n_errors, n_listed);
	  vec_set_len (c->error_heap_index, n_listed);
	}

      cd = em->counters_heap + n->error_heap_index;

      /* vec_elt_at_index asserts the index it is given is below the length, so
       * the length has to reach the last entry the copy writes. Phase 1 left
       * it at zero, and the fallback above left it at the room it took, so this
       * sets it in both cases. */
      if (at + code > vec_len (c->entries))
	vec_set_len (c->entries, at + code);

      /* The node name is copied here because a rename may retire and free it
       * once this lock is released, so the report keeps a copy of its own and
       * the entries of the node share it by offset. It is appended to the name
       * buffer, which the report holds room for, so the lock covers the copy and
       * not the growth: phase 1 takes the room for one name per listed node, and
       * phase 2 takes it again when the heap grew between the phases, so the
       * length of the buffer rises within room already taken and no append here
       * allocates. The name is cut at the room one name has and ends in a NUL,
       * and the column formats it as a C string. */
      name_bytes = clib_min (vec_len (n->name), VLIB_ERROR_NODE_NAME_BYTES - 1);
      name_offset = vec_len (c->node_names);
      vec_add (c->node_names, n->name, name_bytes);
      vec_add1 (c->node_names, 0);

      vec_add1 (c->nodes, n->index);
      vec_add1 (c->entry_index, at);
      vec_add1 (c->n_errors, code);
      vec_add1 (c->error_heap_index, n->error_heap_index);

      /* The name and the reason of the counter are copied for the same reason,
       * and into the string buffer, whose room phase 1 and phase 2 take from the
       * same measure as the name buffer: two strings of the room one has, for
       * each counter the heap holds. The entry names them by offset, so the
       * copies are made with the lock that excludes vlib_unregister_errors
       * freeing the entries that point at them. */
      for (i = 0; i < code; i++)
	{
	  entry = vec_elt_at_index (c->entries, at + i);
	  entry->node_name_offset = name_offset;
	  entry->name_is_desc =
	    cd[i].name == 0 || cd[i].desc == 0 || strcmp (cd[i].name, cd[i].desc) == 0;

	  entry->name_offset = vlib_error_snapshot_append (&c->strings, cd[i].name);
	  entry->desc_offset = vlib_error_snapshot_append (&c->strings, cd[i].desc);
	  entry->severity = cd[i].severity;

	  c->sums[n->error_heap_index + i] += c->counts[n->error_heap_index + i];
	}

      at += code;
    }
}

/* Reads the counters the report shows: their counts over the threads, the
 * nodes they belong to, their sums over the threads, and the entries of
 * counters_heap the counters are named by. It holds the locks it reads under
 * for no longer than the walk, and returns holding none: the report formats
 * and prints what it read afterwards, with nothing held.
 *
 * The read is split into two phases that never hold both locks:
 *
 * 1. the counters of the threads, under the stats segment lock alone;
 * 2. the nodes, their sums and their entries, under the description lock
 *    alone.
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
 * threads.
 *
 * Phase 1 also takes the room phase 2 fills out of it, from the length of
 * counters_heap it reads, so that the description lock covers the copies rather
 * than their allocation, the room of the names included. Phase 2 reads that
 * length again and takes only the room a grow of the heap since phase 1 made
 * necessary, which is the one allocation the description lock can still cover.
 * Both phases read the length under a lock that vlib_register_errors holds from
 * its first step to its last, so it cannot change between them. */
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

      /* The room the list fills under the description lock, so that the lock
       * covers the copies rather than their allocation. The counters the list
       * shows are disjoint ranges of the heap, and a listed node holds at least
       * one of them, so the vectors need room for the heap and no more. The
       * lengths are reset, not the vectors, so the list adds to room that is
       * taken already, and nothing is sized here when there is no heap. */
      if (n_heap)
	{
	  vec_validate (c->entries, n_heap - 1);
	  vec_validate (c->entry_index, n_heap - 1);
	  vec_validate (c->nodes, n_heap - 1);
	  vec_validate (c->n_errors, n_heap - 1);
	  vec_validate (c->error_heap_index, n_heap - 1);
	  vec_reset_length (c->entries);
	  vec_reset_length (c->entry_index);
	  vec_reset_length (c->nodes);
	  vec_reset_length (c->n_errors);
	  vec_reset_length (c->error_heap_index);

	  /* The name of a listed node, which the list copies one of per node, so
	   * the buffer needs room for the heap's worth of nodes and no more: a
	   * listed node holds at least one counter of the heap. The room is one
	   * name of the full length and its NUL per node, so the appends the list
	   * makes fit it whatever the names are, and the lock covers the copy and
	   * not a growth of it. The length is reset, so the list appends to the
	   * room this took. The strings a counter names are copied likewise, two
	   * of them per counter of the heap, and the string buffer takes their
	   * room the same way. */
	  vec_validate (c->node_names, (n_heap + 1) * (VLIB_ERROR_NODE_NAME_BYTES + 1) - 1);
	  vec_reset_length (c->node_names);

	  vec_validate (c->strings, (n_heap + 1) * 2 * (VLIB_ERROR_STRING_BYTES + 1) - 1);
	  vec_reset_length (c->strings);
	}

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
    {
      vec_validate (c->sums, n_counters - 1);

      /* Room for one name per listed node. A listed node holds at least one
       * counter, so the listed nodes number at most n_counters, and a buffer of
       * a full-length name and its NUL for each of them holds every name the
       * list appends. Phase 1 took that room for the heap it saw, so on that
       * path this finds the room taken and touches nothing; it allocates only
       * when a registration grew the heap after phase 1 measured it, and the
       * size it takes is linear in the heap and not in the counters listed so
       * far.
       *
       * The append the list makes therefore fits the room the buffer holds: a
       * u8 vector grows by at most 255 bytes without allocating, and one name
       * is at most VLIB_ERROR_NODE_NAME_BYTES + 1 bytes. That is what keeps the
       * copies the list makes under this lock from allocating on the ordinary
       * path. */
      if (vec_max_len (c->node_names) < (n_counters + 1) * (VLIB_ERROR_NODE_NAME_BYTES + 1))
	vec_validate (c->node_names, (n_counters + 1) * (VLIB_ERROR_NODE_NAME_BYTES + 1) - 1);

      vec_reset_length (c->node_names);

      if (vec_max_len (c->strings) < (n_counters + 1) * 2 * (VLIB_ERROR_STRING_BYTES + 1))
	vec_validate (c->strings, (n_counters + 1) * 2 * (VLIB_ERROR_STRING_BYTES + 1) - 1);

      vec_reset_length (c->strings);
    }

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

/* One thread of the report: its name, which is not locked, an output vector
 * that carries the lines it has formatted and not printed, and the work the
 * current chunk of the report has done. */
typedef struct
{
  u8 *name;

  u8 *text;

  /* The main loop the report hands back between two chunks. */
  vlib_main_t *vm;

  /* Lines formatted into the current chunk. */
  u32 lines;

  /* Time the current chunk started. */
  f64 chunk_start;
} vlib_error_thread_t;

/* Number of formatted lines a thread formats between two prints, before the
 * line the next print follows. */
#define VLIB_ERROR_FORMAT_BATCH 256

/* Room the thread line keeps for the name of a thread, past its fixed part. */
#define VLIB_ERROR_FORMAT_THREAD_BYTES 256

/* Number of lines the report formats into one chunk, and the time a chunk may
 * take, measured between two reads of the clock that are this many lines
 * apart. The report hands the main loop back after every chunk, so a report of
 * a box with many nodes costs the dispatch loop one chunk of work at a time
 * rather than the whole report. */
#define VLIB_ERROR_REPORT_CHUNK_LINES	1024
#define VLIB_ERROR_REPORT_CLOCK_LINES	32
#define VLIB_ERROR_REPORT_CHUNK_SECONDS 2e-3

/* Room the output vector of a thread holds, so that formatting a line of the
 * report adds no allocation. A print happens only after a line is written and
 * ends the vector there, so the vector holds BATCH lines, the line the print
 * follows, and the first line of the next batch, each within
 * VLIB_ERROR_FORMAT_LINE_BYTES before it is printed; a line longer than that
 * makes the print that follows it earlier rather than leave the line room. The
 * thread line is written first, and the name of its thread is not bounded
 * above, so it takes a margin of its own. The vector of the totals holds the
 * same room and, like that of a thread, ends at a chunk boundary, so it never
 * grows past it however many counters the walk shows. */
#define VLIB_ERROR_FORMAT_ROOM                                                                     \
  ((VLIB_ERROR_FORMAT_BATCH + 1) * VLIB_ERROR_FORMAT_LINE_BYTES + VLIB_ERROR_FORMAT_THREAD_BYTES)

/* Prints the lines a thread has formatted and not printed. Every line of the
 * vector ends one already, and vlib_cli_output ends only a line that does
 * not. */
static void
vlib_error_format_flush (vlib_main_t *vm, vlib_error_thread_t *t)
{
  u8 *s = t->text;

  if (vec_len (s) == 0)
    return;

  vlib_cli_output (vm, "%v", s);
  vec_reset_length (s);
}

/* Starts the lines of a thread with room for a batch of them and for its
 * thread line, which is what a thread that shows a counter formats first. The
 * thread line belongs to the verbose report alone, so without verbose the
 * lines start empty and the first counter formats the first one. The space is
 * taken for both, because a report that formats a counter needs it either
 * way. The total line the command passes here is the header of its own vector,
 * which holds it in that room until a total line outgrows it. The work counter
 * starts with the lines of this vector. */
static void
vlib_error_format_start (vlib_error_thread_t *t, vlib_main_t *vm, u32 thread_index, int verbose,
			 const char *line)
{
  t->vm = vm;
  t->lines = 0;
  t->chunk_start = vlib_time_now (vm);

  vec_validate (t->text, VLIB_ERROR_FORMAT_ROOM - 1);
  vec_reset_length (t->text);

  if (line)
    t->text = format (t->text, "%s", line);
  else if (verbose)
    t->text = format (t->text, "Thread %u (%v):\n", thread_index, t->name);
}

/* Prints the lines of the current chunk and hands the main loop back, so that
 * the report of a box with many nodes costs the dispatch loop one chunk of its
 * work at a time rather than the whole report. The report holds no lock here,
 * so the yield leaves no spinlock a worker main loop waits on. A command runs
 * on a process stack, and only a process can hand the main loop back; a caller
 * outside one runs the report through without a yield. */
static void
vlib_error_format_yield (vlib_error_thread_t *t)
{
  vlib_error_format_flush (t->vm, t);

  t->lines = 0;
  t->chunk_start = vlib_time_now (t->vm);

  if (!vlib_in_process_context (t->vm))
    return;

  vlib_process_yield (t->vm);
}

/* Accounts for the line just formatted, and hands the main loop back once the
 * chunk has spent its lines or its time. The time is read once every
 * VLIB_ERROR_REPORT_CLOCK_LINES lines rather than at each of them, so the
 * clock of a report that runs out on its line budget alone is read rarely. */
static void
vlib_error_format_chunk (vlib_error_thread_t *t)
{
  if (++t->lines < VLIB_ERROR_REPORT_CHUNK_LINES)
    {
      if (t->lines % VLIB_ERROR_REPORT_CLOCK_LINES)
	return;

      if (vlib_time_now (t->vm) - t->chunk_start < VLIB_ERROR_REPORT_CHUNK_SECONDS)
	return;
    }

  vlib_error_format_yield (t);
}

/* Formats the Counter column of a line: the symbol the registration gave the
 * counter, or nothing at all when the reason already names it, in which case
 * the line ends where Severity ends and gains no trailing space. The column
 * trails the line, so its space comes first and its name is cut at the width
 * rather than padded past it. A counter name a registration passes is a
 * NUL-terminated string, so %s reads it. */
static u8 *
format_vlib_error_counter (u8 *s, va_list *va)
{
  vlib_error_entry_t *entry = va_arg (*va, vlib_error_entry_t *);
  u8 *strings = va_arg (*va, u8 *);
  char *name = error_counter_name (strings, entry);

  if (name[0] == 0)
    return s;

  return format (s, " %.*s", VLIB_ERROR_FORMAT_COUNTER_COLUMN, name);
}

/* The node name of an entry of the snapshot, which the list copied under the
 * description lock and the format reads with none held. */
static char *
vlib_error_node_name (vlib_error_counts_t *c, vlib_error_entry_t *entry)
{
  if (entry->node_name_offset >= vec_len (c->node_names))
    return "";

  return (char *) c->node_names + entry->node_name_offset;
}

/* Formats one counter of the report from the entry the snapshot copied. The
 * report holds no lock here: the line is added to the output vector of the
 * thread it shows, and the vector is printed once it holds a batch of lines,
 * so the lines reach vlib_cli_output in a few large pieces rather than one
 * piece each. A chunk of the report ends at a print and a yield, so the
 * dispatch loop runs between the chunks of a report rather than after it. The
 * output is read when the command is done, so the batching delays nothing that
 * a reader waits for. A total line, which verbose alone asks for, goes to the
 * vector of the totals, which the command prints under its header, so it is
 * handled as a line of the report like any other.
 *
 * The Node column is the node name the snapshot copied, which is a C string in
 * the snapshot's own buffer, so %s reads it and nothing past its NUL. The Index
 * column stays the sixth column of the verbose line where it always was, and
 * the Counter column trails the line, so no line of a plain report loses the
 * header it had. */
static void
vlib_error_format (vlib_error_thread_t *t, vlib_error_counts_t *c, vlib_error_entry_t *entry,
		   u32 index, u64 count, int verbose, int total)
{
  char *node_name = vlib_error_node_name (c, entry);
  char *desc = vlib_error_snapshot_string (c->strings, entry->desc_offset);

  /* format returns the vector it grew, which is another one when it had to
   * allocate for the line, so the result is what the thread keeps. A total line
   * is part of the verbose report alone, so it formats nothing otherwise. */
  if (total)
    {
      if (verbose)
	t->text = format (t->text, "%10lu%=40s%=20s%=10d%U\n", count, node_name, desc, index,
			  format_vlib_error_counter, entry, c->strings);
    }
  else if (verbose)
    t->text =
      format (t->text, "%10lu%=35s%=35s%=10s%=6d%U\n", count, node_name, desc,
	      sev2str (entry->severity), index, format_vlib_error_counter, entry, c->strings);
  else
    t->text = format (t->text, "%10lu%=35s%=35s%=10s%U\n", count, node_name, desc,
		      sev2str (entry->severity), format_vlib_error_counter, entry, c->strings);

  /* The room of the vector is that of a batch, and a line of the next batch
   * past it, which every line that reaches here has. */
  if (vec_len (t->text) >= VLIB_ERROR_FORMAT_BATCH * VLIB_ERROR_FORMAT_LINE_BYTES)
    vlib_error_format_flush (t->vm, t);

  vlib_error_format_chunk (t);
}

/* Formats the counters of the node at a position of the snapshot as one
 * thread counted them, leaving out the counters that thread read as zero
 * unless verbose 2 asks for them. */
static void
vlib_error_format_thread (vlib_error_thread_t *t, vlib_error_counts_t *c, u32 nj, int verbose)
{
  vlib_error_entry_t *entry;
  u32 code, index;

  for (code = 0; code < c->n_errors[nj]; code++)
    {
      index = c->error_heap_index[nj] + code;

      if (c->counts[index] == 0 && verbose < 2)
	continue;

      entry = vlib_error_counting_entry (c, nj, code);
      if (entry)
	vlib_error_format (t, c, entry, index, c->counts[index], verbose, 0);
    }
}

/* Formats the count of the counters of every thread. They all go to the vector
 * of the totals, under the total header the command starts. The total section
 * belongs to the verbose report alone, so a plain report formats none of it. */
static void
vlib_error_format_total (vlib_error_thread_t *t, vlib_error_counts_t *c, int verbose)
{
  vlib_error_entry_t *entry;
  u64 sum;
  u32 code, index;

  if (!verbose)
    return;

  for (u32 nj = 0; nj < vec_len (c->nodes); nj++)
    {
      if (!vlib_error_lists (c, nj))
	continue;

      for (code = 0; code < c->n_errors[nj]; code++)
	{
	  index = c->error_heap_index[nj] + code;
	  sum = c->sums[index];
	  entry = vlib_error_counting_entry (c, nj, code);

	  if (sum && entry)
	    vlib_error_format (t, c, entry, index, sum, verbose, 1);
	}
    }
}

/* Formats the counters of one thread. A thread that shows no counter formats
 * no line, so it allocates nothing for one, and so does every thread of a
 * report that shows no node, which is the report of a VPP that registered no
 * error. The chunk the report has done starts over with the first line of a
 * thread, which is another point of the report at which the main loop can be
 * handed back. */
static void
vlib_error_report_thread (vlib_main_t *vm, vlib_error_counts_t *c, u32 thread_index, int verbose)
{
  vlib_error_thread_t t = { .name = vlib_error_thread_name (thread_index) };

  for (u32 nj = 0; nj < vec_len (c->nodes); nj++)
    {
      if (!vlib_error_lists (c, nj))
	continue;

      if (t.text == 0)
	vlib_error_format_start (&t, vm, thread_index, verbose, 0);

      vlib_error_format_thread (&t, c, nj, verbose);
    }

  vlib_error_format_flush (vm, &t);
  vec_free (t.text);
}

static clib_error_t *
show_errors (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_error_thread_t total = {};
  vlib_error_counts_t c = {};
  int verbose = 0;

  if (unformat (input, "verbose %d", &verbose))
    ;
  else if (unformat (input, "verbose"))
    verbose = 1;

  /* The walk copies the entry of every counter it shows into a vector of its
   * own, and returns with no lock held. The report formats and prints those
   * copies, so a registration that runs while it prints waits on no lock of
   * this command, and frees nothing the report reads. The walk is bounded by
   * the counters a node registers, and the report below hands the main loop
   * back as it goes, so neither part holds the main thread for the length of
   * the whole report. */
  vlib_error_counts_get (&c);

  /* The header names the columns the lines below it fill, in the order they
   * fill them. The Index column, which verbose alone shows, keeps the position
   * it had, and the Counter column trails it, so the header of a plain report
   * and the first five columns of a verbose one are where they were. */
  if (verbose)
    vlib_cli_output (vm, "%=10s%=35s%=35s%=10s%=6s %s", "Count", "Node", "Reason", "Severity",
		     "Index", "Counter");
  else
    vlib_cli_output (vm, "%=10s%=35s%=35s%=10s %s", "Count", "Node", "Reason", "Severity",
		     "Counter");

  for (u32 t = 0; t < vlib_get_n_threads (); t++)
    vlib_error_report_thread (vm, &c, t, verbose);

  /* The total header starts the vector of the totals, and holds the room of a
   * thread. The total lines end at a chunk boundary too, so the vector keeps
   * that room however many counters the walk shows. */
  if (verbose)
    vlib_error_format_start (&total, vm, 0, 0, "Total:\n");

  vlib_error_format_total (&total, &c, verbose);

  vlib_error_format_flush (vm, &total);
  vec_free (total.text);

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
