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

      rv = lcp_itf_pair_add (host_sw_if_index, phy_sw_if_index, host_name,
			     host_vif, host_type, NULL);
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
  vlib_cli_output (vm, "refs:%u fib:%u mfib:%u", state->refs, state->fib_index,
		   state->mfib_index);
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
      fib_entry_src_t *source = entry == ~0 ? NULL :
	fib_entry_src_find (fib_entry_get (entry), state->sources[2]);
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
      fib_entry_src_t *source = entry == ~0 ? NULL :
	fib_entry_src_find (fib_entry_get (entry), state->sources[ii]);
      vlib_cli_output (vm, "%s:%u refs:%u", names[ii], source != NULL,
		       source ? source->fes_ref_count : 0);
    }
  if (proto != FIB_PROTOCOL_MPLS)
    {
      const char *forwarding = "none";
      if (entry != ~0)
	{
	  const dpo_id_t *dpo = fib_entry_contribute_ip_forwarding (entry);
	  if (dpo->dpoi_type == DPO_LOAD_BALANCE &&
	      load_balance_n_buckets (dpo->dpoi_index) == 1)
	    dpo = load_balance_get_bucket (dpo->dpoi_index, 0);
	  forwarding = dpo->dpoi_type == DPO_RECEIVE ? "receive" :
		       dpo->dpoi_type == DPO_DROP ? "drop" : "other";
	}
      vlib_cli_output (vm, "forwarding:%s", forwarding);
    }
  return 0;
}

static clib_error_t *
lcp_router_test_cmd (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  const nl_vft_t *vft = vlib_get_plugin_symbol ("linux_nl_plugin.so", "lcp_router_vft");
  int (*get_state) (u32, fib_protocol_t, lcp_router_table_state_t *) =
    vlib_get_plugin_symbol ("linux_nl_plugin.so", "lcp_router_table_state");
  lcp_router_table_state_t state;
  fib_protocol_t proto;
  u32 table, protocol, label;
  int family;
  u8 *destination = NULL;
  struct nl_addr *dst = NULL;
  struct rtnl_route *route;
  u8 is_del = 0, replace = 0;

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
  if (unformat (input, "ip4"))
    proto = FIB_PROTOCOL_IP4;
  else if (unformat (input, "ip6"))
    proto = FIB_PROTOCOL_IP6;
  else if (unformat (input, "mpls"))
    proto = FIB_PROTOCOL_MPLS;
  else
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
  route = rtnl_route_alloc ();
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
      rtnl_route_set_type (route, RTN_UNICAST);
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
  .short_help = "test lcp router begin|end|<ip4|ip6|mpls> table <id> "
		"state|entry|add|replace|del ...",
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
