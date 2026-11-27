/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* node_cli.c: node CLI */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vlib/stats/stats.h>
#include <math.h>
#include <stdbool.h>

static int
node_cmp (void *a1, void *a2)
{
  vlib_node_t **n1 = a1;
  vlib_node_t **n2 = a2;

  return vec_cmp (n1[0]->name, n2[0]->name);
}

static clib_error_t *
show_node_graph (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n;
  u32 node_index;

  vlib_cli_output (vm, "%U\n", format_vlib_node_graph, nm, 0);

  if (unformat (input, "%U", unformat_vlib_node, vm, &node_index))
    {
      n = vlib_get_node (vm, node_index);
      vlib_cli_output (vm, "%U\n", format_vlib_node_graph, nm, n);
    }
  else
    {
      vlib_node_t **nodes = vec_dup (nm->nodes);
      uword i;

      vec_sort_with_function (nodes, node_cmp);

      for (i = 0; i < vec_len (nodes); i++)
	vlib_cli_output (vm, "%U\n\n", format_vlib_node_graph, nm, nodes[i]);

      vec_free (nodes);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_node_graph_command, static) = {
  .path = "show vlib graph",
  .short_help = "Show packet processing node graph",
  .function = show_node_graph,
};

static clib_error_t *
show_node_graphviz (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t **nodes = nm->nodes;
  u8 *chroot_filename = 0;
  int fd;
  uword *active = 0;
  u32 i, j;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 filter = 0, calls_filter = 0, vectors_filter = 0, both = 0;

  fd = -1;
  /* Get a line of input. */
  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "filter"))
	    filter = 1;
	  else if (unformat (line_input, "calls") && filter)
	    calls_filter = 1;
	  else if (unformat (line_input, "vectors") && filter)
	    vectors_filter = 1;
	  else if (unformat (line_input, "file %U", unformat_vlib_tmpfile,
			     &chroot_filename))
	    {
	      fd = open ((char *) chroot_filename,
			 O_CREAT | O_TRUNC | O_WRONLY, 0664);
	    }
	  else
	    return clib_error_return (0, "unknown input `%U'",
				      format_unformat_error, input);
	}
      unformat_free (line_input);
    }

  /*both is set to true if calls_filter and vectors_filter are, or neither */
  both = filter & (!(calls_filter ^ vectors_filter));

#define format__(vm__, fd__, ...) \
  if ((fd) < 0) \
    { \
      vlib_cli_output((vm__), ## __VA_ARGS__); \
    } \
  else \
    { \
      fdformat((fd__), ## __VA_ARGS__); \
    }

  format__ (vm, fd, "%s", "digraph {\n");

  clib_bitmap_alloc (active, vec_len (nodes));
  clib_bitmap_set_region (active, 0, 1, vec_len (nodes));
  if (filter)
    {
      /*Adding the legend to the dot file*/
      format__ (vm, fd, "%s",
		"  rankdir=\"LR\"\n  nodesep=2\n  subgraph cluster_legend {\n "
		"   label=\"Legend\"\n    style=\"solid\"\n    labelloc = b\n "
		"   subgraph cluster_colors {\n      label=\"Packets/Call\"\n "
		"     style=\"solid\"\n      labelloc = b\n");
      format__ (vm, fd, "%s",
		"      0 [label=\"No packet\", fixedsize=true shape=circle "
		"width=2 fontsize=17]\n"
		"      1 [label=\"1-32\", fillcolor=1 style=filled "
		"colorscheme=ylorrd8 fixedsize=true shape=circle width=2 "
		"fontsize=17]\n"
		"      2 [label=\"33-64\", fillcolor=2 style=filled "
		"colorscheme=ylorrd8 fixedsize=true shape=circle width=2 "
		"fontsize=17]\n"
		"      3 [label=\"65-96\", fillcolor=3 style=filled "
		"colorscheme=ylorrd8 fixedsize=true shape=circle width=2 "
		"fontsize=17]\n"
		"      4 [label=\"97-128\", fillcolor=4 style=filled "
		"colorscheme=ylorrd8 fixedsize=true shape=circle width=2 "
		"fontsize=17]\n"
		"      5 [label=\"129-160\", fillcolor=5 style=filled "
		"colorscheme=ylorrd8 fixedsize=true shape=circle width=2 "
		"fontsize=17]\n"
		"      6 [label=\"161-192\", fillcolor=6 style=filled "
		"colorscheme=ylorrd8 fixedsize=true shape=circle width=2 "
		"fontsize=17]\n"
		"      7 [label=\"193-224\", fillcolor=7 style=filled "
		"colorscheme=ylorrd8 fixedsize=true shape=circle width=2 "
		"fontsize=17]\n"
		"      8 [label=\"224+\", fillcolor=8 style=filled "
		"colorscheme=ylorrd8 fixedsize=true shape=circle width=2 "
		"fontsize=17]\n");
      format__ (vm, fd, "%s",
		"      0 -> 1 -> 2 -> 3 -> 4 [style=\"invis\",weight =100]\n  "
		"    5 -> 6 -> 7 -> 8 [style=\"invis\",weight =100]\n    }\n  "
		"  subgraph cluster_size {\n      label=\"Cycles/Packet\"\n   "
		"   style=\"solid\"\n      labelloc = b\n");
      format__ (
	vm, fd, "%s",
	"      a[label=\"0\",fixedsize=true shape=circle width=1] \n"
	"      b[label=\"10\",fixedsize=true shape=circle width=2 "
	"fontsize=17]\n"
	"      c[label=\"100\",fixedsize=true shape=circle width=3 "
	"fontsize=20]\n"
	"      d[label=\"1000\",fixedsize=true shape=circle width=4 "
	"fontsize=23]\n"
	"      a -> b -> c -> d  [style=\"invis\",weight =100]\n    }\n  }\n");

      vlib_worker_thread_barrier_sync (vm);
      for (j = 0; j < vec_len (nm->nodes); j++)
	{
	  vlib_node_t *n;
	  n = nm->nodes[j];
	  vlib_node_sync_stats (vm, n);
	}

      /* Updating the stats for multithreaded use cases.
       * We need to dup the nodes to sum the stats from all threads.*/
      nodes = vec_dup (nm->nodes);
      for (i = 1; i < vlib_get_n_threads (); i++)
	{
	  vlib_node_main_t *nm_clone;
	  vlib_main_t *vm_clone;
	  vlib_node_runtime_t *rt;
	  vlib_node_t *n;

	  vm_clone = vlib_get_main_by_index (i);
	  nm_clone = &vm_clone->node_main;

	  for (j = 0; j < vec_len (nm_clone->nodes); j++)
	    {
	      n = nm_clone->nodes[j];

	      rt = vlib_node_get_runtime (vm_clone, n->index);
	      /* Sync the stats directly in the duplicated node.*/
	      vlib_node_runtime_sync_stats_node (nodes[j], rt, 0, 0, 0);
	    }
	}
      vlib_worker_thread_barrier_release (vm);

      for (i = 0; i < vec_len (nodes); i++)
	{
	  u64 p, c, l;
	  c = nodes[i]->stats_total.calls - nodes[i]->stats_last_clear.calls;
	  p =
	    nodes[i]->stats_total.vectors - nodes[i]->stats_last_clear.vectors;
	  l = nodes[i]->stats_total.clocks - nodes[i]->stats_last_clear.clocks;

	  if ((both && c > 0 && p > 0) || (calls_filter && c > 0) ||
	      (vectors_filter && p > 0))
	    {
	      format__ (vm, fd, "  \"%v\" [shape=circle", nodes[i]->name);
	      /*Changing the size and the font of nodes that receive packets*/
	      if (p > 0)
		{
		  f64 x = (f64) l / (f64) p;
		  f64 size_ratio = (1 + log10 (x + 1));
		  format__ (vm, fd, " width=%.2f fontsize=%.2f fixedsize=true",
			    size_ratio, 11 + 3 * size_ratio);
		  /*Coloring nodes that are indeed called*/
		  if (c > 0)
		    {
		      u64 color = ((p - 1) / (32 * c)) + 1;
		      color = clib_min (color, 8);
		      format__ (
			vm, fd,
			" fillcolor=%u style=filled colorscheme=ylorrd8",
			color);
		    }
		}
	      format__ (vm, fd, "]\n");
	    }
	  else
	    {
	      clib_bitmap_set (active, i, 0);
	    }
	}
    }

  clib_bitmap_foreach (i, active)
    {
      for (j = 0; j < vec_len (nodes[i]->next_nodes); j++)
	{
	  if (nodes[i]->next_nodes[j] == VLIB_INVALID_NODE_INDEX)
	    continue;

	  if (!filter || clib_bitmap_get (active, nodes[i]->next_nodes[j]))
	    {
	      format__ (vm, fd, "  \"%v\" -> \"%v\"\n", nodes[i]->name,
			nodes[nodes[i]->next_nodes[j]]->name);
	    }
	}
    }

  format__ (vm, fd, "}\n");

  if (fd >= 0)
    {
      /*Dumping all the nodes saturates dot capacities to render a directed
       * graph. In this case, prefer using he fdp command to generate an
       * undirected graph. */
      const char *soft = filter ? "dot" : "fdp";
      vlib_cli_output (
	vm, "vlib graph dumped into `%s'. Run eg. `%s -Tsvg -O %s'.",
	chroot_filename, soft, chroot_filename);
    }

  clib_bitmap_free (active);
  vec_free (chroot_filename);
  if (filter)
    vec_free (nodes);
  if (fd >= 0)
    close (fd);
  return error;
}

/*?
 * Dump dot files data to draw a graph of all the nodes.
 * If the argument 'filter' is provided, only the active nodes (since the last
 * "clear run" command) are selected and they are scaled and colored according
 * to their utilization. You can choose to filter nodes that are called,
 * nodes that receive vectors or both (default).
 * The 'file' option allows to save data in a temp file.
 *
 * @cliexpar
 * @clistart
 * show vlib graphviz
 * show vlib graphviz filter file tmpfile
 * show vlib graphviz filter calls file tmpfile
 * @cliend
 * @cliexcmd{show vlib graphviz [filter][calls][vectors][file <filename>]}
?*/
VLIB_CLI_COMMAND (show_node_graphviz_command, static) = {
  .path = "show vlib graphviz",
  .short_help = "Dump packet processing node graph as a graphviz dotfile",
  .function = show_node_graphviz,
  .is_mp_safe = 1,
};

static const char *
node_runtime_state (const vlib_node_t *node, const vlib_process_t *process)
{
  if (process)
    {
      static const char *const states[] = {
#define _(n, s) [VLIB_PROCESS_STATE_##n] = #s,
	foreach_vlib_process_state
      };
      if (process->state >= ARRAY_LEN (states) || !states[process->state])
	return "unknown";
      return states[process->state];
    }

  if (node->type == VLIB_NODE_TYPE_INTERNAL)
    return "active";
  if (node->state == VLIB_NODE_STATE_DISABLED)
    return "disabled";
  if (node->state == VLIB_NODE_STATE_INTERRUPT)
    return "interrupt wait";
  return "polling";
}

static u8 *
format_vlib_node_state (u8 *s, va_list *va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  vlib_node_t *node = va_arg (*va, vlib_node_t *);
  vlib_process_t *process =
    node->type == VLIB_NODE_TYPE_PROCESS ? vlib_get_process_from_node (vm, node) : 0;
  return format (s, "%s", node_runtime_state (node, process));
}

typedef struct
{
  u8 *name;
  const char *state;
  u64 calls, vectors, clocks, suspends, max_clock;
  u32 max_clock_n;
  u16 flags;
  vlib_node_type_t type;
  bool events_pending;
} node_runtime_row_t;

typedef struct
{
  u64 input, output, drop, punt;
} node_runtime_vectors_t;

typedef struct
{
  node_runtime_row_t *rows;
  u8 *name;
  int cpu_id;
  f64 vector_rate, loops_per_second, seconds_per_clock;
  node_runtime_vectors_t vectors;
} node_runtime_thread_t;

typedef struct
{
  int brief, max, use_time, summary;
} node_runtime_options_t;

typedef struct
{
  f64 elapsed, update_interval;
  bool show_threads;
} node_runtime_report_t;

static node_runtime_row_t
node_runtime_read_row (vlib_main_t *vm, vlib_node_t *node)
{
  vlib_process_t *process =
    node->type == VLIB_NODE_TYPE_PROCESS ? vlib_get_process_from_node (vm, node) : 0;
  return (node_runtime_row_t) {
    .name = node->name,
    .state = node_runtime_state (node, process),
    .calls = node->stats_total.calls - node->stats_last_clear.calls,
    .vectors = node->stats_total.vectors - node->stats_last_clear.vectors,
    .clocks = node->stats_total.clocks - node->stats_last_clear.clocks,
    .suspends = node->stats_total.suspends - node->stats_last_clear.suspends,
    .max_clock = node->stats_total.max_clock,
    .max_clock_n = node->stats_total.max_clock_n,
    .flags = node->flags,
    .type = node->type,
    .events_pending = process && !clib_bitmap_is_zero (process->non_empty_event_type_bitmap),
  };
}

static u8 *
format_node_runtime_header (u8 *s, va_list *va)
{
  int max = va_arg (*va, int);
  int use_time = va_arg (*va, int);

  if (max)
    return format (s, "%=30s%=17s%=16s%=16s%=16s%=16s", "Name", "Max Node Clocks", "Vectors at Max",
		   "Max Clocks", use_time ? "Avg Time (ns)" : "Avg Clocks", "Avg Vectors/Call");

  return format (s, "%=30s%=12s%=16s%=16s%=16s%=16s%=16s", "Name", "State", "Calls", "Vectors",
		 "Suspends", use_time ? "Packet-Time" : "Packet-Clocks", "Vectors/Call");
}

static u8 *
format_node_runtime_row (u8 *s, va_list *va)
{
  node_runtime_row_t *row = va_arg (*va, node_runtime_row_t *);
  f64 seconds_per_clock = va_arg (*va, f64);
  int max = va_arg (*va, int);
  int use_time = va_arg (*va, int);
  u32 indent = format_get_indent (s);
  u64 clocks = row->clocks;
  u64 work = row->vectors ? row->vectors : row->calls ? row->calls : row->suspends;
  f64 vectors_per_call = row->calls ? (f64) row->vectors / (f64) row->calls : 0;

  if (use_time)
    clocks *= 1e9 * seconds_per_clock;

  f64 cost = work ? (f64) clocks / (f64) work : 0;
  if (max)
    {
      f64 max_clock = (f64) row->max_clock;
      f64 max_per_vector = row->max_clock_n ? max_clock / (f64) row->max_clock_n : 0;
      s = format (s, "%-30v%=17.2e%=16d%=16.2e%=16.2e%=16.2e", row->name, max_clock,
		  row->max_clock_n, max_per_vector, cost, vectors_per_call);
    }
  else
    s = format (s, "%-30v%=12s%16Ld%16Ld%16Ld%16.2e%16.2f", row->name, row->state, row->calls,
		row->vectors, row->suspends, cost, vectors_per_call);

  if (row->events_pending)
    s = format (s, "\n%Uevents pending, ", format_white_space, indent + 4);

  return s;
}

static void
node_runtime_add_vectors (node_runtime_vectors_t *counts, vlib_node_type_t type, u16 flags,
			  u64 vectors)
{
  if (type == VLIB_NODE_TYPE_INPUT)
    counts->input += vectors;
  if (type != VLIB_NODE_TYPE_INTERNAL)
    return;

  if (flags & VLIB_NODE_FLAG_IS_HANDOFF)
    counts->input += vectors;
  if (flags & VLIB_NODE_FLAG_IS_OUTPUT)
    counts->output += vectors;
  if (flags & VLIB_NODE_FLAG_IS_DROP)
    counts->drop += vectors;
  if (flags & VLIB_NODE_FLAG_IS_PUNT)
    counts->punt += vectors;
}

static void
node_runtime_thread_header (vlib_main_t *vm, const node_runtime_report_t *report,
			    const node_runtime_thread_t *thread, u32 index)
{
  if (report->show_threads)
    {
      if (index > 0)
	vlib_cli_output (vm, "---------------");
      if (thread->cpu_id > -1)
	vlib_cli_output (vm, "Thread %d %s (lcore %u)", index, thread->name, thread->cpu_id);
      else
	vlib_cli_output (vm, "Thread %d %s", index, thread->name);
    }

  f64 dt = report->elapsed;
  vlib_cli_output (vm,
		   "Time %.1f, %f sec internal node vector rate %.2f loops/sec %.2f\n"
		   "  vector rates in %.4e, out %.4e, drop %.4e, punt %.4e",
		   dt, report->update_interval, thread->vector_rate, thread->loops_per_second,
		   (f64) thread->vectors.input / dt, (f64) thread->vectors.output / dt,
		   (f64) thread->vectors.drop / dt, (f64) thread->vectors.punt / dt);
}

static int
node_runtime_row_cmp (void *first, void *second)
{
  node_runtime_row_t *left = first, *right = second;
  return vec_cmp (left->name, right->name);
}

static node_runtime_thread_t *
node_runtime_capture (vlib_main_t *vm, f64 time_now, node_runtime_report_t *report)
{
  node_runtime_thread_t *threads = 0;
  u32 n_threads = vlib_get_n_threads ();
  report->show_threads = n_threads > 1;

  vlib_worker_thread_barrier_sync (vm);
  for (u32 i = 0; i < n_threads; i++)
    {
      vlib_main_t *stat_vm = vlib_get_main_by_index (i);
      if (!stat_vm)
	continue;

      vlib_node_main_t *nm = &stat_vm->node_main;
      node_runtime_thread_t *thread;
      vec_add2 (threads, thread, 1);
      *thread = (node_runtime_thread_t) { .seconds_per_clock = stat_vm->clib_time.seconds_per_clock,
					  .loops_per_second = stat_vm->loops_per_second };
      if (report->show_threads)
	{
	  vlib_worker_thread_t *worker = vlib_worker_threads + (thread - threads);
	  thread->name = vec_dup (worker->name);
	  thread->cpu_id = worker->cpu_id;
	}

      if (vec_len (nm->nodes))
	thread->rows = vec_new (node_runtime_row_t, vec_len (nm->nodes));
      for (u32 j = 0; j < vec_len (nm->nodes); j++)
	{
	  vlib_node_t *node = nm->nodes[j];
	  vlib_node_sync_stats (stat_vm, node);
	  node_runtime_row_t *row = &thread->rows[j];
	  *row = node_runtime_read_row (stat_vm, node);
	  row->name = vec_dup (node->name);
	}
      thread->vector_rate = vlib_internal_node_vector_rate (stat_vm);
      /* The last retained thread's clear baseline applies to every block. */
      report->elapsed = time_now - nm->time_last_runtime_stats_clear;
    }
  vlib_worker_thread_barrier_release (vm);
  report->update_interval = vlib_stats_get_segment_update_rate ();
  return threads;
}

#define NODE_RUNTIME_ROWS_PER_BATCH 64

static void
node_runtime_emit (vlib_main_t *vm, node_runtime_thread_t *threads,
		   const node_runtime_report_t *report, const node_runtime_options_t *options)
{
  node_runtime_thread_t *thread;
  node_runtime_row_t *row;
  uword remaining = 0;
  vec_foreach (thread, threads)
    {
      remaining += vec_len (thread->rows);
      vec_foreach (row, thread->rows)
	node_runtime_add_vectors (&thread->vectors, row->type, row->flags, row->vectors);
      vec_sort_with_function (thread->rows, node_runtime_row_cmp);
    }

  u32 batch = 0;
  vec_foreach (thread, threads)
    {
      node_runtime_thread_header (vm, report, thread, thread - threads);
      vlib_cli_output (vm, "%U", format_node_runtime_header, options->max, options->use_time);
      vec_foreach (row, thread->rows)
	{
	  if (!options->brief || row->calls || row->suspends)
	    vlib_cli_output (vm, "%U", format_node_runtime_row, row, thread->seconds_per_clock,
			     options->max, options->use_time);
	  vec_free (row->name);
	  remaining--;
	  if (++batch == NODE_RUNTIME_ROWS_PER_BATCH && remaining)
	    {
	      batch = 0;
	      vlib_process_yield (vm);
	    }
	}
      vec_free (thread->rows);
      vec_free (thread->name);
    }
  vec_free (threads);
}

typedef struct
{
  vlib_main_t *vm;
  vlib_node_t **nodes;
  f64 vector_rate;
} node_runtime_live_thread_t;

static node_runtime_live_thread_t *
node_runtime_scrape (vlib_main_t *vm, f64 time_now, node_runtime_report_t *report)
{
  node_runtime_live_thread_t *threads = 0;
  u32 n_threads = vlib_get_n_threads ();
  report->show_threads = n_threads > 1;

  vlib_worker_thread_barrier_sync (vm);
  for (u32 i = 0; i < n_threads; i++)
    {
      vlib_main_t *stat_vm = vlib_get_main_by_index (i);
      if (!stat_vm)
	continue;

      vlib_node_main_t *nm = &stat_vm->node_main;
      vlib_node_t *node;
      vec_foreach_pointer (node, nm->nodes)
	vlib_node_sync_stats (stat_vm, node);

      node_runtime_live_thread_t thread = {
	.vm = stat_vm,
	.nodes = vec_dup (nm->nodes),
	.vector_rate = vlib_internal_node_vector_rate (stat_vm),
      };
      vec_add1 (threads, thread);
      report->elapsed = time_now - nm->time_last_runtime_stats_clear;
    }
  vlib_worker_thread_barrier_release (vm);
  report->update_interval = vlib_stats_get_segment_update_rate ();
  return threads;
}

static void
node_runtime_display_sync (vlib_main_t *vm, f64 time_now, const node_runtime_options_t *options)
{
  node_runtime_report_t report = {};
  node_runtime_live_thread_t *threads = node_runtime_scrape (vm, time_now, &report);
  node_runtime_live_thread_t *live;

  vec_foreach (live, threads)
    {
      vlib_node_t *node;
      u32 index = live - threads;
      node_runtime_thread_t thread = { .vector_rate = live->vector_rate,
				       .loops_per_second = live->vm->loops_per_second };
      if (report.show_threads)
	{
	  thread.name = vlib_worker_threads[index].name;
	  thread.cpu_id = vlib_worker_threads[index].cpu_id;
	}

      vec_sort_with_function (live->nodes, node_cmp);
      vec_foreach_pointer (node, live->nodes)
	node_runtime_add_vectors (&thread.vectors, node->type, node->flags,
				  node->stats_total.vectors - node->stats_last_clear.vectors);
      node_runtime_thread_header (vm, &report, &thread, index);

      if (!options->summary)
	{
	  vlib_cli_output (vm, "%U", format_node_runtime_header, options->max, options->use_time);
	  vec_foreach_pointer (node, live->nodes)
	    {
	      node_runtime_row_t row = node_runtime_read_row (live->vm, node);
	      if (!options->brief || row.calls || row.suspends)
		vlib_cli_output (vm, "%U", format_node_runtime_row, &row,
				 live->vm->clib_time.seconds_per_clock, options->max,
				 options->use_time);
	    }
	}
      vec_free (live->nodes);
    }
  vec_free (threads);
}

static clib_error_t *
show_node_runtime_internal (vlib_main_t *vm, unformat_input_t *input, bool cooperative)
{
  u32 node_index;
  f64 time_now = vlib_time_now (vm);

  if (unformat (input, "%U", unformat_vlib_node, vm, &node_index))
    {
      vlib_node_t *node = vlib_get_node (vm, node_index);
      vlib_node_sync_stats (vm, node);
      vlib_cli_output (vm, "%U\n", format_node_runtime_header, 0, 0);
      node_runtime_row_t row = node_runtime_read_row (vm, node);
      vlib_cli_output (vm, "%U\n", format_node_runtime_row, &row, vm->clib_time.seconds_per_clock,
		       0, 0);
      return 0;
    }

  node_runtime_options_t options = { .brief = 1 };
  options.use_time = unformat (input, "time") || unformat (input, "t");
  if (unformat (input, "brief") || unformat (input, "b"))
    options.brief = 1;
  if (unformat (input, "verbose") || unformat (input, "v"))
    options.brief = 0;
  options.max = unformat (input, "max") || unformat (input, "m");
  options.summary =
    unformat (input, "summary") || unformat (input, "sum") || unformat (input, "su");

  /* Do not suspend an input that may still dispatch another command. */
  if (cooperative && !options.summary && unformat (input, "%U", unformat_eof) &&
      (vlib_get_n_threads () < 2 || !vlib_worker_thread_barrier_held ()))
    {
      node_runtime_report_t report = {};
      node_runtime_thread_t *threads = node_runtime_capture (vm, time_now, &report);
      node_runtime_emit (vm, threads, &report, &options);
    }
  else
    node_runtime_display_sync (vm, time_now, &options);

  return 0;
}

static clib_error_t *
show_node_runtime (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  return show_node_runtime_internal (vm, input, false);
}

static clib_error_t *
show_node_runtime_with_yield (vlib_main_t *vm, unformat_input_t *input)
{
  return show_node_runtime_internal (vm, input, true);
}

VLIB_CLI_COMMAND (show_node_runtime_command, static) = {
  .path = "show runtime",
  .short_help = "show runtime [time] [verbose] [max] [summary]",
  .function = show_node_runtime,
  .is_mp_safe = 1,
  .function_with_yield = show_node_runtime_with_yield,
};

static clib_error_t *
clear_node_runtime (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_node_main_t *nm;
  vlib_node_t *n;
  int i, j;
  vlib_main_t **stat_vms = 0, *stat_vm;
  vlib_node_runtime_t *r;

  for (i = 0; i < vlib_get_n_threads (); i++)
    {
      stat_vm = vlib_get_main_by_index (i);
      if (stat_vm)
	vec_add1 (stat_vms, stat_vm);
    }

  vlib_worker_thread_barrier_sync (vm);

  for (j = 0; j < vec_len (stat_vms); j++)
    {
      stat_vm = stat_vms[j];
      nm = &stat_vm->node_main;

      for (i = 0; i < vec_len (nm->nodes); i++)
	{
	  n = nm->nodes[i];
	  vlib_node_sync_stats (stat_vm, n);
	  n->stats_last_clear = n->stats_total;

	  r = vlib_node_get_runtime (stat_vm, n->index);
	  r->max_clock = 0;
	}
      /* Note: input/output rates computed using vlib_global_main */
      nm->time_last_runtime_stats_clear = vlib_time_now (vm);
    }

  vlib_stats_set_timestamp (STAT_COUNTER_LAST_STATS_CLEAR,
			    vm->node_main.time_last_runtime_stats_clear);
  vlib_worker_thread_barrier_release (vm);

  vec_free (stat_vms);

  return 0;
}

VLIB_CLI_COMMAND (clear_node_runtime_command, static) = {
  .path = "clear runtime",
  .short_help = "Clear packet processing runtime statistics",
  .function = clear_node_runtime,
};

static clib_error_t *
show_node (vlib_main_t * vm, unformat_input_t * input,
	   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n;
  u8 *s = 0, *s2 = 0;
  u32 i, node_index = ~0, verbose = 0;
  char *type_str;
  u8 valid_node_name = 0;
  u64 cl, ca, v;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "index %u", &node_index))
	;
      else if (unformat (line_input, "verbose"))
	verbose = 1;
      else
	if (unformat (line_input, "%U", unformat_vlib_node, vm, &node_index))
	valid_node_name = 1;
      else if (!valid_node_name)
	error = clib_error_return (0, "unknown node name: '%U'",
				   format_unformat_error, line_input);
      else
	error = clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, line_input);

      if (error)
	break;
    }

  unformat_free (line_input);

  if (error)
    return error;

  if (node_index >= vec_len (vm->node_main.nodes))
    return clib_error_return (0, "please specify valid node");

  n = vlib_get_node (vm, node_index);
  vlib_node_sync_stats (vm, n);

  switch (n->type)
    {
    case VLIB_NODE_TYPE_INTERNAL:
      type_str = "internal";
      break;
    case VLIB_NODE_TYPE_INPUT:
      type_str = "input";
      break;
    case VLIB_NODE_TYPE_PRE_INPUT:
      type_str = "pre-input";
      break;
    case VLIB_NODE_TYPE_PROCESS:
      type_str = "process";
      break;
    case VLIB_NODE_TYPE_SCHED:
      type_str = "sched";
      break;
    default:
      type_str = "unknown";
    }

  if (n->sibling_of)
    s = format (s, ", sibling-of %s", n->sibling_of);

  vlib_cli_output (vm, "node %v, type %s, state %U, index %d%v\n",
		   n->name, type_str, format_vlib_node_state, vm, n,
		   n->index, s);
  vec_reset_length (s);

  if (n->node_fn_registrations)
    {
      vlib_node_fn_registration_t *fnr = n->node_fn_registrations;
      vlib_node_fn_variant_t *v;
      while (fnr)
	{
	  v = vec_elt_at_index (vm->node_main.variants, fnr->march_variant);
	  if (vec_len (s) == 0)
	    s = format (s, "\n    %-15s  %=8s  %6s  %s", "Name", "Priority",
			"Active", "Description");
	  s = format (s, "\n    %-15s  %8d  %=6s  %s", v->suffix, v->priority,
		      fnr->function == n->function ? "yes" : "", v->desc);
	  fnr = fnr->next_registration;
	}
    }
  else
    s = format (s, "\n    default only");
  vlib_cli_output (vm, "  node function variants:%v\n", s);
  vec_reset_length (s);

  for (i = 0; i < vec_len (n->next_nodes); i++)
    {
      vlib_node_t *pn;
      if (n->next_nodes[i] == VLIB_INVALID_NODE_INDEX)
	continue;

      pn = vec_elt (nm->nodes, n->next_nodes[i]);

      if (vec_len (s) == 0)
	s = format (s, "\n    %10s  %10s  %=30s %8s",
		    "next-index", "node-index", "Node", "Vectors");

      s = format (s, "\n    %=10u  %=10u  %=30v %=8llu", i, n->next_nodes[i],
		  pn->name, vec_elt (n->n_vectors_by_next_node, i));
    }

  if (vec_len (s) == 0)
    s = format (s, "\n    none");
  vlib_cli_output (vm, "\n  next nodes:%v\n", s);
  vec_reset_length (s);

  if (n->type == VLIB_NODE_TYPE_INTERNAL)
    {
      int j = 0;
      clib_bitmap_foreach (i, n->prev_node_bitmap)  {
	    vlib_node_t *pn = vlib_get_node (vm, i);
	    if (j++ % 3 == 0)
	      s = format (s, "\n    ");
	    s2 = format (s2, "%v (%u)", pn->name, i);
	    s = format (s, "%-35v", s2);
	    vec_reset_length (s2);
	  }

      if (vec_len (s) == 0)
	s = format (s, "\n    none");
      vlib_cli_output (vm, "\n  known previous nodes:%v\n", s);
      vec_reset_length (s);
      vec_free (s2);
    }

  if (!verbose)
    goto done;

  s = format (s, "\n%8s %=12s %=12s %=12s %=12s %=12s\n", "Thread", "Calls",
	      "Clocks", "Vectors", "Max Clock", "Max Vectors");
  for (i = 0; i < vlib_get_n_threads (); i++)
    {
      n = vlib_get_node (vlib_get_main_by_index (i), node_index);
      vlib_node_sync_stats (vlib_get_main_by_index (i), n);

      cl = n->stats_total.clocks - n->stats_last_clear.clocks;
      ca = n->stats_total.calls - n->stats_last_clear.calls;
      v = n->stats_total.vectors - n->stats_last_clear.vectors;

      s = format (s, "%=8u %=12lu %=12lu %=12lu %=12u %=12u\n", i, ca, cl, v,
		  n->stats_total.max_clock, n->stats_total.max_clock_n);
    }

  vlib_cli_output (vm, "%v", s);

done:

  vec_free (s);
  return 0;
}

VLIB_CLI_COMMAND (show_node_command, static) = {
  .path = "show node",
  .short_help = "show node [index] <node-name | node-index>",
  .function = show_node,
};

static clib_error_t *
set_node_fn(vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 node_index, march_variant;
  vlib_node_t *n;
  clib_error_t *err = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (!unformat (line_input, "%U", unformat_vlib_node, vm, &node_index))
    {
      err = clib_error_return (0, "please specify valid node name");
      goto done;
    }

  if (!unformat (line_input, "%U", unformat_vlib_node_variant, &march_variant))
    {
      err = clib_error_return (0, "please specify node function variant");
      goto done;
    }

  n = vlib_get_node (vm, node_index);

  if (n->node_fn_registrations == 0)
    {
      err = clib_error_return (0, "node doesn't have function variants");
      goto done;
    }

  if (vlib_node_set_march_variant (vm, node_index, march_variant))
    {
      vlib_node_fn_variant_t *v;
      v = vec_elt_at_index (vm->node_main.variants, march_variant);
      err = clib_error_return (0, "node function variant '%s' not found",
			       v->suffix);
      goto done;
    }


done:
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (set_node_fn_command, static) = {
  .path = "set node function",
  .short_help = "set node function <node-name> <variant-name>",
  .function = set_node_fn,
};

/* Dummy function to get us linked in. */
void
vlib_node_cli_reference (void)
{
}
