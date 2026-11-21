/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/file.h>

#include <vppinfra/file.h>

#include <plugins/linux-cp/lcp_interface.h>
#include <linux-cp/lcp_router.h>
#include <linux-cp/lcp_nl.h>
#include <vlib/unix/plugin.h>
#include <vnet/fib/fib_entry_src.h>
#include <vnet/fib/fib_table.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/mfib/mfib_entry_src.h>
#include <vppinfra/hash.h>
#include <netlink/route/nexthop.h>
#include <linux/mpls.h>

static u32 host_vif;
const static char *host_template = "tap%d";

/* Description the linux_nl plugin uses when it registers the notification
 * netlink socket with the vlib file poller.
 */
#define LCP_NETLINK_ROUTE_FILE "linux-cp netlink route socket"

static clib_error_t *
lcp_add_pair_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  u32 phy_sw_if_index, host_sw_if_index;
  u8 is_add, *host_name;
  vnet_main_t *vnm = vnet_get_main ();

  ++host_vif;
  host_name = format (NULL, host_template, host_vif);
  phy_sw_if_index = host_sw_if_index = ~0;
  is_add = 1;
  lcp_main.test_mode = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "phy %U", unformat_vnet_sw_interface, vnm,
			 &phy_sw_if_index))
	;
      else if (unformat (input, "host %U", unformat_vnet_sw_interface, vnm,
			 &host_sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input:%U", format_unformat_error,
				  input);
    }

  if (phy_sw_if_index == ~0)
    return clib_error_return (0, "ERROR; no phy:%U", format_unformat_error,
			      input);

  lip_host_type_t host_type =
    (vnet_sw_interface_is_p2p (vnm, phy_sw_if_index) ? LCP_ITF_HOST_TUN :
						       LCP_ITF_HOST_TAP);

  int rv;

  if (is_add)
    {
      if (host_sw_if_index == ~0)
	return clib_error_return (0, "ERROR no-host:%U", format_unformat_error,
				  input);

      rv = lcp_itf_pair_add (host_sw_if_index, phy_sw_if_index, host_name, host_vif, host_type,
			     lcp_get_default_ns ());
    }
  else
    rv = lcp_itf_pair_del (phy_sw_if_index);

  if (rv)
    return clib_error_return (0, "ERROR rv:%d", rv);

  return (NULL);
}

VLIB_CLI_COMMAND (test_time_range_command, static) = {
  .path = "test lcp",
  .short_help = "lcp [add|del] phy <SW_IF_INDEX> host <SW_IF_INDEX>",
  .function = lcp_add_pair_command_fn,
};

static clib_file_t *
lcp_nl_route_file_get (void)
{
  clib_file_main_t *fm = &file_main;
  u32 description_len = sizeof (LCP_NETLINK_ROUTE_FILE) - 1;
  clib_file_t **fp;

  pool_foreach (fp, fm->file_pool)
    {
      clib_file_t *f = fp[0];

      if (!f || !f->description || !f->error_function)
	continue;

      if (strncmp ((char *) f->description, LCP_NETLINK_ROUTE_FILE, description_len) == 0)
	return f;
    }

  return 0;
}

static clib_error_t *
lcp_nl_error_cmd (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_file_t *file, *target;
  clib_file_t file_copy;
  clib_error_t *error;
  u8 use_invalid_fd = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "invalid-fd"))
	use_invalid_fd = 1;
      else
	return clib_error_return (0, "unknown input:%U", format_unformat_error, input);
    }

  file = lcp_nl_route_file_get ();
  if (!file)
    return clib_error_return (0, "no file \"%s\" is registered", LCP_NETLINK_ROUTE_FILE);

  target = file;
  if (use_invalid_fd)
    {
      /* Only the copy gets an unusable descriptor, the registered file and
       * its descriptor are left untouched. */
      file_copy = *file;
      file_copy.file_descriptor = (u32) ~0;
      target = &file_copy;
    }

  vlib_cli_output (vm, "netlink-error: target fd %d%s", (int) target->file_descriptor,
		   use_invalid_fd ? " (copy with invalid-fd)" : "");

  /* Mirror the vlib file poller: count the error event, then invoke the
   * registered callback. */
  target->error_events++;

  error = target->error_function (target);
  if (error)
    {
      vlib_cli_output (vm, "netlink-error: callback error: %v", error->what);
      clib_error_free (error);
    }
  else
    vlib_cli_output (vm, "netlink-error: callback returned no error");

  return 0;
}

VLIB_CLI_COMMAND (test_lcp_netlink_error_command, static) = {
  .path = "test lcp netlink-error",
  .short_help = "test lcp netlink-error [invalid-fd]",
  .function = lcp_nl_error_cmd,
};

static u32
lcp_router_test_mroute_index (u32 table, u32 group, u8 wildcard, const ip4_address_t *source)
{
  u32 mfib_index = mfib_table_find (FIB_PROTOCOL_IP4, table);
  mfib_prefix_t mprefix = {
    .fp_proto = FIB_PROTOCOL_IP4,
    /* (*,G) is indexed at 32 bits and (S,G) at 64. The fixture receives both
     * addresses in the byte order of unformat_ip4_address. */
    .fp_len = wildcard ? 32 : 64,
  };

  memcpy (&mprefix.fp_grp_addr.ip4, &group, sizeof (group));
  memcpy (&mprefix.fp_src_addr.ip4, source, sizeof (ip4_address_t));

  return mfib_index == ~0 ? ~0 : mfib_table_lookup_exact_match (mfib_index, &mprefix);
}

/* The source names MFIB formats an entry with. The numeric value has no API
 * constant to read it from, so the fixture prints the name beside the id. */
static const char *lcp_router_test_mfib_source_names[] = MFIB_SOURCE_NAMES;

static clib_error_t *
lcp_router_test_mroute_cmd (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  ip4_address_t source = {};
  u32 table, group, entry;
  u8 wildcard = 0;
  mfib_entry_t *mfib_entry;

  if (!unformat (input, "table %u", &table) ||
      !unformat (input, "%U", unformat_ip4_address, &group))
    return clib_error_return (0, "expected table and group");
  if (unformat (input, "wildcard"))
    wildcard = 1;
  else if (!unformat (input, "source %U", unformat_ip4_address, &source))
    return clib_error_return (0, "expected wildcard or source");

  if (wildcard)
    source.as_u32 = 0;

  entry = lcp_router_test_mroute_index (table, group, wildcard, &source);
  if (entry == ~0)
    {
      vlib_cli_output (vm, "entry:absent");
      return 0;
    }

  mfib_entry = mfib_entry_get (entry);
  {
    u32 ii;
    mfib_entry_src_t *source_ep;

    /* The id of the source the linux-nl plugin installs its routes under, so a
     * test can name it without an API constant for its numeric value. */
    vlib_cli_output (vm, "entry:present plugin-low:%d", MFIB_SOURCE_PLUGIN_LOW);
    vec_foreach_index (ii, mfib_entry->mfe_srcs)
      {
	source_ep = vec_elt_at_index (mfib_entry->mfe_srcs, ii);
	vlib_cli_output (vm, "source:%d name:%s flags:%s paths:%u itfs:%u", source_ep->mfes_src,
			 source_ep->mfes_src < ARRAY_LEN (lcp_router_test_mfib_source_names) ?
			   lcp_router_test_mfib_source_names[source_ep->mfes_src] :
			   "unknown",
			 (source_ep->mfes_flags & MFIB_ENTRY_SRC_FLAG_STALE) ? "stale" : "replayed",
			 source_ep->mfes_pl == FIB_NODE_INDEX_INVALID ?
			   0 :
			   fib_path_list_get_n_paths (source_ep->mfes_pl),
			 source_ep->mfes_itfs ? hash_elts (source_ep->mfes_itfs) : 0);
      }
  }

  return 0;
}

VLIB_CLI_COMMAND (test_lcp_router_mroute_command, static) = {
  .path = "test lcp mroute",
  .short_help = "test lcp mroute table <id> <group> [source <addr>|wildcard]",
  .function = lcp_router_test_mroute_cmd,
};

static fib_table_walk_rc_t
lcp_router_test_refs (fib_node_index_t entry, void *arg)
{
  lcp_router_table_state_t *state = arg;
  for (u32 ii = 0; ii < ARRAY_LEN (state->sources); ii++)
    {
      fib_entry_src_t *source = fib_entry_src_find (fib_entry_get (entry), state->sources[ii]);
      if (source && source->fes_ref_count != 1)
	state->refs++;
    }
  return FIB_TABLE_WALK_CONTINUE;
}

static void
lcp_router_test_state (vlib_main_t *vm, fib_protocol_t proto, lcp_router_table_state_t *state)
{
  vlib_cli_output (vm, "refs:%u fib:%u mfib:%u", state->refs, state->fib_index, state->mfib_index);
  vlib_cli_output (vm, "mcast-routes:%u", state->mcast_routes);
  state->refs = 0;
  fib_table_walk (state->fib_index, proto, lcp_router_test_refs, state);
  vlib_cli_output (vm, "invalid-source-refs:%u", state->refs);
  if (proto == FIB_PROTOCOL_IP4)
    {
      fib_prefix_t broadcast = {
	.fp_proto = proto,
	.fp_len = 32,
	.fp_addr.ip4.as_u32 = ~0,
      };
      u32 entry = fib_table_lookup_exact_match (state->fib_index, &broadcast);
      fib_entry_src_t *source =
	entry == ~0 ? NULL : fib_entry_src_find (fib_entry_get (entry), state->sources[2]);
      vlib_cli_output (vm, "broadcast refs:%u local:%u", source ? source->fes_ref_count : 0,
		       source ? !!(source->fes_entry_flags & FIB_ENTRY_FLAG_LOCAL) : 0);
    }
}

static clib_error_t *
lcp_router_test_entry (vlib_main_t *vm, unformat_input_t *input, fib_protocol_t proto,
		       const lcp_router_table_state_t *state)
{
  fib_prefix_t prefix = { .fp_proto = proto };
  u32 length, eos;
  if (proto == FIB_PROTOCOL_MPLS)
    {
      if (!unformat (input, "%u eos %u", &prefix.fp_label, &eos) || eos > 1)
	return clib_error_return (0, "expected label and eos 0 or 1");
      prefix.fp_len = 21;
      prefix.fp_eos = eos;
      prefix.fp_payload_proto = eos ? DPO_PROTO_IP4 : DPO_PROTO_MPLS;
    }
  else
    {
      if (!(proto == FIB_PROTOCOL_IP4 ?
	      unformat (input, "%U/%u", unformat_ip4_address, &prefix.fp_addr.ip4, &length) :
	      unformat (input, "%U/%u", unformat_ip6_address, &prefix.fp_addr.ip6, &length)) ||
	  length > (proto == FIB_PROTOCOL_IP4 ? 32 : 128))
	return clib_error_return (0, "expected prefix");
      prefix.fp_len = length;
    }
  u32 entry = fib_table_lookup_exact_match (state->fib_index, &prefix);
  const char *names[] = { "static", "dynamic", "permanent" };
  for (u32 ii = 0; ii < ARRAY_LEN (state->sources); ii++)
    {
      fib_entry_src_t *source =
	entry == ~0 ? NULL : fib_entry_src_find (fib_entry_get (entry), state->sources[ii]);
      vlib_cli_output (vm, "%s:%u refs:%u", names[ii], source != NULL,
		       source ? source->fes_ref_count : 0);
    }
  if (proto != FIB_PROTOCOL_MPLS)
    {
      const char *forwarding = "none";
      if (entry != ~0)
	{
	  const dpo_id_t *dpo = fib_entry_contribute_ip_forwarding (entry);
	  if (dpo->dpoi_type == DPO_LOAD_BALANCE && load_balance_n_buckets (dpo->dpoi_index) == 1)
	    dpo = load_balance_get_bucket (dpo->dpoi_index, 0);
	  forwarding = dpo->dpoi_type == DPO_RECEIVE ? "receive" :
		       dpo->dpoi_type == DPO_DROP    ? "drop" :
						       "other";
	}
      vlib_cli_output (vm, "forwarding:%s", forwarding);
    }
  return 0;
}

static clib_error_t *
lcp_router_test_cross_fib_cmd (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 (*cross_fib_count) (void) =
    vlib_get_plugin_symbol ("linux_nl_plugin.so", "lcp_router_cross_fib_nexthop_count");

  if (!cross_fib_count)
    return clib_error_return (0, "linux_nl router symbols unavailable");

  vlib_cli_output (vm, "cross-fib:%u", cross_fib_count ());

  return 0;
}

VLIB_CLI_COMMAND (test_lcp_router_cross_fib_command, static) = {
  .path = "test lcp cross-fib",
  .short_help = "test lcp cross-fib",
  .function = lcp_router_test_cross_fib_cmd,
};

/*
 * The address family a command names. An optional match, because the same
 * words are the first of a prefix: "ip4" reads as an address of the family
 * nl_addr_parse() is given, so a caller that meant a prefix has to be able to
 * try the family and go on with "ip4" still in the input when it fails.
 */
static fib_protocol_t
lcp_router_test_family (unformat_input_t *input)
{
  if (unformat (input, "ip4"))
    return FIB_PROTOCOL_IP4;
  if (unformat (input, "ip6"))
    return FIB_PROTOCOL_IP6;
  if (unformat (input, "mpls"))
    return FIB_PROTOCOL_MPLS;

  return FIB_PROTOCOL_NONE;
}

static void *
lcp_router_neigh_step_symbol (unformat_input_t *input)
{
  if (unformat (input, "mark"))
    return vlib_get_plugin_symbol ("linux_nl_plugin.so", "lcp_router_neigh_test_mark_all");
  if (unformat (input, "end"))
    return vlib_get_plugin_symbol ("linux_nl_plugin.so", "lcp_router_neigh_test_end");

  return NULL;
}

/*
 * What the plugin holds for a table, without touching the table: the record
 * and the indices it names. The record outlived an API delete before the
 * plugin learned to notice one, and a path that read it through the MFIB then
 * indexed a table that the delete freed.
 */
static clib_error_t *
lcp_router_test_table_cmd (vlib_main_t *vm, unformat_input_t *input)
{
  int (*get_state) (u32, fib_protocol_t, lcp_router_table_state_t *) =
    vlib_get_plugin_symbol ("linux_nl_plugin.so", "lcp_router_table_state");
  lcp_router_table_state_t state;
  fib_protocol_t proto;
  u32 table;

  if (!get_state)
    return clib_error_return (0, "linux_nl router symbols unavailable");
  proto = lcp_router_test_family (input);
  if (FIB_PROTOCOL_NONE == proto)
    return clib_error_return (0, "expected ip4 or ip6");
  if (!unformat (input, "table %u", &table))
    return clib_error_return (0, "expected table");

  if (!get_state (table, proto, &state))
    {
      vlib_cli_output (vm, "router-record:absent");
      return 0;
    }

  /* The state already says whether the record still holds its table: the
   * lookup a command that installs or removes trades would report the record
   * absent, and release it instead.
   *
   * The record's indices are printed next to the ones the table id resolves to
   * now, so that a test can require them equal: the two come from different
   * lookups, the record from its own fields and the table from the FIB and
   * MFIB. */
  vlib_cli_output (vm, "router-record:present fib:%u table-fib:%u mfib:%u table-mfib:%u",
		   state.fib_index, fib_table_find (proto, table), state.mfib_index,
		   mfib_table_find (proto, table));
  return 0;
}

static clib_error_t *
lcp_router_test_neigh_sync_cmd (vlib_main_t *vm, unformat_input_t *input)
{
  void *step = lcp_router_neigh_step_symbol (input);

  if (!step)
    return clib_error_return (0, "expected neighbor step mark|end");

  ((void (*) (void)) step) ();

  return 0;
}

static clib_error_t *
lcp_router_test_cmd (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  const nl_vft_t *vft = vlib_get_plugin_symbol ("linux_nl_plugin.so", "lcp_router_vft");
  int (*get_state) (u32, fib_protocol_t, lcp_router_table_state_t *) =
    vlib_get_plugin_symbol ("linux_nl_plugin.so", "lcp_router_table_state");
  lcp_router_table_state_t state;
  fib_protocol_t proto, base_proto = FIB_PROTOCOL_NONE;
  u32 table, protocol, label;
  int family;
  u8 *destination = NULL;
  struct nl_addr *dst = NULL;
  struct rtnl_route *route;
  u8 is_del = 0, replace = 0;
  u8 rtype;

  if (!vft || !get_state)
    return clib_error_return (0, "linux_nl router symbols unavailable");
  if (unformat (input, "begin"))
    {
      vft->nvl_rt_route_sync_begin.cb ();
      return 0;
    }
  if (unformat (input, "end"))
    {
      vft->nvl_rt_route_sync_end.cb ();
      return 0;
    }
  /* The neighbor steps are dispatched before an address family is required. */
  if (unformat (input, "neigh"))
    return lcp_router_test_neigh_sync_cmd (vm, input);
  /* So is the record probe: it reads the plugin's record, not the table. */
  if (unformat (input, "record"))
    return lcp_router_test_table_cmd (vm, input);
  proto = lcp_router_test_family (input);
  if (FIB_PROTOCOL_NONE == proto)
    return clib_error_return (0, "expected ip4, ip6 or mpls");
  if (!unformat (input, "table %u", &table))
    return clib_error_return (0, "expected table");
  if (unformat (input, "state"))
    {
      if (!get_state (table, proto, &state))
	vlib_cli_output (vm, "absent fib:%u mfib:%u", fib_table_find (proto, table),
			 proto == FIB_PROTOCOL_MPLS ? ~0 : mfib_table_find (proto, table));
      else
	lcp_router_test_state (vm, proto, &state);
      return 0;
    }
  if (unformat (input, "entry"))
    {
      if (!get_state (table, proto, &state))
	return clib_error_return (0, "router table absent");
      return lcp_router_test_entry (vm, input, proto, &state);
    }

  /*
   * The verbs below take the base "<family> table <id>" that state and entry
   * already require before them, so that a route can be written the way the
   * tests build it, with the table named once at the front. The base says
   * nothing new: a route lives in the table of its own family.
   */
  base_proto = lcp_router_test_family (input);
  if (FIB_PROTOCOL_NONE == base_proto)
    base_proto = proto;
  else
    {
      u32 base_table;

      if (!unformat (input, "table %u", &base_table))
	return clib_error_return (0, "the base needs table <id>");
      if (base_table != table || base_proto != proto)
	return clib_error_return (0, "the base names %U table %u, not %U table %u",
				  format_fib_protocol, base_proto, base_table, format_fib_protocol,
				  proto, table);
    }

  if (unformat (input, "del"))
    is_del = 1;
  else if (unformat (input, "replace"))
    replace = 1;
  else if (!unformat (input, "add"))
    return clib_error_return (0, "expected add, replace or del");

  family = proto == FIB_PROTOCOL_IP4 ? AF_INET : proto == FIB_PROTOCOL_IP6 ? AF_INET6 : AF_MPLS;
  if (proto == FIB_PROTOCOL_MPLS)
    {
      if (!unformat (input, "%u", &label))
	return clib_error_return (0, "expected label");
      label = htonl ((label << MPLS_LS_LABEL_SHIFT) | MPLS_LS_S_MASK);
      dst = nl_addr_build (AF_MPLS, &label, sizeof (label));
      nl_addr_set_prefixlen (dst, 20);
    }
  else
    {
      /*
       * "%s" reads one word, so it would take the "ip4" of a base written
       * after the verb and nl_addr_parse() would accept it as an address,
       * leaving "table <id> ..." behind as unknown input. Say what is wrong
       * instead of failing further along.
       */
      /* A failed match leaves the input where it was, so one attempt is
       * enough to tell a base from a prefix. */
      if (FIB_PROTOCOL_NONE != lcp_router_test_family (input))
	return clib_error_return (0, "the base comes before <verb>, not after it");

      if (!unformat (input, "%s", &destination))
	return clib_error_return (0, "expected prefix");
      int rv = nl_addr_parse ((char *) destination, family, &dst);
      vec_free (destination);
      if (rv)
	return clib_error_return (0, "invalid prefix");
    }
  if (!unformat (input, "proto %u", &protocol))
    {
      nl_addr_put (dst);
      return clib_error_return (0, "expected route protocol");
    }

  /*
   * A multicast route travels in a routing family of its own: the kernel
   * reports one under RTNL_FAMILY_IPMR for IPv4 and RTNL_FAMILY_IP6MR for
   * IPv6, and builds its group and source there too. The family is also what
   * lets the source attach at all: rtnl_route_set_src() refuses an AF_INET
   * address with NLE_SRCRT_NOSUPPORT and stores nothing, so a route built in
   * AF_INET reaches the plugin with no source and installs as the (*,G)
   * entry.
   */
  rtype = RTN_UNICAST;
  if (unformat (input, "multicast"))
    {
      struct nl_addr *group;

      if (FIB_PROTOCOL_MPLS == proto)
	{
	  nl_addr_put (dst);
	  return clib_error_return (0, "a multicast route has no mpls family");
	}
      if (FIB_PROTOCOL_IP4 != proto)
	{
	  nl_addr_put (dst);
	  return clib_error_return (0, "the fixture builds IPv4 multicast routes only");
	}
      family = RTNL_FAMILY_IPMR;
      rtype = RTN_MULTICAST;

      group = nl_addr_build (family, nl_addr_get_binary_addr (dst), nl_addr_get_len (dst));
      nl_addr_put (dst);
      if (!group)
	return clib_error_return (0, "failed to build the multicast group");
      dst = group;
      nl_addr_set_prefixlen (dst, 32);
    }

  route = rtnl_route_alloc ();
  /* rtnl_route_set_family() accepts only the unicast families; for a
   * multicast route rtnl_route_set_dst() is what records the family. */
  if (RTN_MULTICAST != rtype)
    rtnl_route_set_family (route, family);
  rtnl_route_set_table (route, table);
  rtnl_route_set_protocol (route, protocol);
  rtnl_route_set_dst (route, dst);
  nl_addr_put (dst);
  if (unformat (input, "drop"))
    rtnl_route_set_type (route, RTN_BLACKHOLE);
  else
    {
      u32 vif;

      rtnl_route_set_type (route, rtype);
      if (RTN_MULTICAST == rtype)
	{
	  /* The destination is the group; the source is the address the route
	   * selects its senders on. Both are in the multicast family. */
	  ip4_address_t source = {};
	  struct nl_addr *nl_source;
	  int rv;

	  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT &&
	      !unformat (input, "source %U", unformat_ip4_address, &source))
	    {
	      rtnl_route_put (route);
	      return clib_error_return (0, "expected multicast source");
	    }
	  nl_source = nl_addr_build (family, &source, sizeof (source));
	  if (!nl_source)
	    {
	      rtnl_route_put (route);
	      return clib_error_return (0, "failed to build the multicast source");
	    }
	  nl_addr_set_prefixlen (nl_source, 32);
	  rv = rtnl_route_set_src (route, nl_source);
	  nl_addr_put (nl_source);
	  if (rv < 0)
	    {
	      rtnl_route_put (route);
	      return clib_error_return (0, "libnl rejected the multicast source: %d", rv);
	    }
	}
      while (unformat (input, "vif %u", &vif))
	{
	  struct rtnl_nexthop *nh = rtnl_route_nh_alloc ();
	  rtnl_route_nh_set_ifindex (nh, vif);
	  ip4_address_t gateway;
	  if (unformat (input, "via %U", unformat_ip4_address, &gateway))
	    {
	      struct nl_addr *via = nl_addr_build (AF_INET, &gateway, sizeof (gateway));
	      if (proto == FIB_PROTOCOL_MPLS)
		rtnl_route_nh_set_via (nh, via);
	      else
		rtnl_route_nh_set_gateway (nh, via);
	      nl_addr_put (via);
	    }
	  else if (proto == FIB_PROTOCOL_MPLS)
	    {
	      rtnl_route_nh_free (nh);
	      rtnl_route_put (route);
	      return clib_error_return (0, "expected MPLS next hop");
	    }
	  rtnl_route_add_nexthop (route, nh);
	}
    }
  if (is_del)
    vft->nvl_rt_route_del.cb (route);
  else
    vft->nvl_rt_route_add.cb (route, replace);
  rtnl_route_put (route);
  return 0;
}

VLIB_CLI_COMMAND (test_lcp_router_command, static) = {
  .path = "test lcp router",
  .short_help = "test lcp router begin|end|neigh mark|end|"
		"record <ip4|ip6> table <id>|"
		"<ip4|ip6|mpls> table <id> state|entry|"
		"[<ip4|ip6|mpls> table <id>] add|replace|del ...",
  .function = lcp_router_test_cmd,
};

static clib_error_t *
lcp_nl_sync_pause_cmd (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  void (*set_pause) (u8) =
    vlib_get_plugin_symbol ("linux_nl_plugin.so", "lcp_nl_test_set_sync_pause");
  u8 enable;

  if (!set_pause)
    return clib_error_return (0, "linux_nl sync pause unavailable");
  if (unformat (input, "on"))
    enable = 1;
  else if (unformat (input, "off"))
    enable = 0;
  else
    return clib_error_return (0, "expected on or off");
  set_pause (enable);
  return 0;
}

VLIB_CLI_COMMAND (test_lcp_netlink_sync_pause_command, static) = {
  .path = "test lcp netlink-sync-pause",
  .short_help = "test lcp netlink-sync-pause on|off",
  .function = lcp_nl_sync_pause_cmd,
};

static clib_error_t *
lcp_nl_dump_cmd (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  int (*inject) (u32, u32) =
    vlib_get_plugin_symbol ("linux_nl_plugin.so", "lcp_nl_test_inject_dump");
  u32 type, scenario;

  if (!inject)
    return clib_error_return (0, "linux_nl dump injection unavailable");
  if (!unformat (input, "%u %u", &type, &scenario))
    return clib_error_return (0, "expected dump type and scenario");
  if (inject (type, scenario))
    return clib_error_return (0, "invalid or busy dump injection");
  return 0;
}

VLIB_CLI_COMMAND (test_lcp_netlink_dump_command, static) = {
  .path = "test lcp netlink-dump",
  .short_help = "test lcp netlink-dump <type:0-3> <scenario:1-7>",
  .function = lcp_nl_dump_cmd,
};

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Linux Control Plane - Unit Test",
  .default_disabled = 1,
};
