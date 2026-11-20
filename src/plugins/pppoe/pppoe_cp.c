/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Intel and/or its affiliates.
 */

#include <pppoe/pppoe.h>

static bool
pppoe_dp_interface_is_ethernet (vnet_main_t *vnm, u32 dp_sw_if_index)
{
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, dp_sw_if_index);
  u32 hw_if_index = si->hw_if_index;

  /* a sub-interface sends on the hardware interface of its super interface */
  while (hw_if_index != ~0 && si->type == VNET_SW_INTERFACE_TYPE_SUB)
    {
      si = vnet_get_sw_interface (vnm, si->sup_sw_if_index);
      hw_if_index = si->hw_if_index;
    }

  if (hw_if_index == ~0)
    return false;

  return vnet_get_hw_interface (vnm, hw_if_index)->hw_class_index ==
	 ethernet_hw_interface_class.index;
}

static void
pppoe_cp_binding_set (pppoe_main_t *pem, u32 cp_sw_if_index, u32 dp_sw_if_index)
{
  vec_validate_init_empty (pem->cp_if_index_by_sw_if_index, dp_sw_if_index, ~0);
  pem->cp_if_index_by_sw_if_index[dp_sw_if_index] = cp_sw_if_index;

  vec_validate_init_empty (pem->dp_if_index_by_sw_if_index, cp_sw_if_index, ~0);
  pem->dp_if_index_by_sw_if_index[cp_sw_if_index] = dp_sw_if_index;
}

static void
pppoe_cp_binding_clear (pppoe_main_t *pem, u32 cp_sw_if_index, u32 dp_sw_if_index)
{
  if (pppoe_cp_if_index_by_dp (pem, dp_sw_if_index) == cp_sw_if_index)
    pem->cp_if_index_by_sw_if_index[dp_sw_if_index] = ~0;

  if (pppoe_dp_if_index_by_cp (pem, cp_sw_if_index) == dp_sw_if_index)
    pem->dp_if_index_by_sw_if_index[cp_sw_if_index] = ~0;
}

/*
 * The control plane interface captures PPPoE discovery frames for the data
 * plane interface it is paired with. Pairing does not subscribe the interface
 * to the pppoe-input feature: ethernet_input already sends PPPoE session and
 * discovery frames to the PPPoE nodes by ethertype, and the feature would
 * divert every other frame on the interface into them as well.
 */
int
pppoe_add_del_cp (u32 cp_sw_if_index, u32 dp_sw_if_index, u8 is_add)
{
  pppoe_main_t *pem = &pppoe_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 cp_peer, dp_peer;

  if (cp_sw_if_index == ~0 || dp_sw_if_index == ~0 || cp_sw_if_index == dp_sw_if_index)
    return VNET_API_ERROR_INVALID_ARGUMENT;

  if (!vnet_sw_interface_is_valid (vnm, cp_sw_if_index) ||
      !vnet_sw_interface_is_valid (vnm, dp_sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (!pppoe_dp_interface_is_ethernet (vnm, dp_sw_if_index))
    return VNET_API_ERROR_NON_ETHERNET;

  cp_peer = pppoe_cp_if_index_by_dp (pem, dp_sw_if_index);
  dp_peer = pppoe_dp_if_index_by_cp (pem, cp_sw_if_index);

  if (is_add)
    {
      if (cp_peer != ~0 || dp_peer != ~0)
	return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;

      pppoe_cp_binding_set (pem, cp_sw_if_index, dp_sw_if_index);
      return 0;
    }

  if (cp_peer != cp_sw_if_index && dp_peer != dp_sw_if_index)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  pppoe_cp_binding_clear (pem, cp_sw_if_index, dp_sw_if_index);
  return 0;
}

static clib_error_t *
pppoe_map_error (int rv)
{
  switch (rv)
    {
    case VNET_API_ERROR_ENTRY_ALREADY_EXISTS:
      return clib_error_return (0, "an interface is already mapped");
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "no such mapping");
    case VNET_API_ERROR_NON_ETHERNET:
      return clib_error_return (0, "data plane interface is not ethernet");
    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (0, "unknown interface");
    case VNET_API_ERROR_INVALID_ARGUMENT:
      return clib_error_return (0, "interfaces are not distinct");
    default:
      return clib_error_return (0, "pppoe_add_del_cp returned %d", rv);
    }
}

static clib_error_t *
pppoe_add_del_cp_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  u32 cp_sw_if_index = ~0;
  u32 dp_sw_if_index = ~0;
  clib_error_t *error = NULL;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "dp %U", unformat_vnet_sw_interface, vnet_get_main (),
			 &dp_sw_if_index))
	;
      else if (unformat (line_input, "cp %U", unformat_vnet_sw_interface, vnet_get_main (),
			 &cp_sw_if_index))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'", format_unformat_error, line_input);
	  goto done;
	}
    }

  if (cp_sw_if_index == ~0 || dp_sw_if_index == ~0)
    {
      error = clib_error_return (0, "dp and cp interfaces must be given");
      goto done;
    }

  rv = pppoe_add_del_cp (cp_sw_if_index, dp_sw_if_index, is_add);
  if (rv)
    error = pppoe_map_error (rv);

done:
  unformat_free (line_input);

  return error;
}

/*?
 * Pair the interface that carries the control plane negotiation of a PPPoE
 * access concentrator with the interface that carries its data plane traffic.
 *
 * @cliexpar
 * Example of how to pair two interfaces:
 * @cliexcmd{create pppoe map dp GigabitEthernet0/8/0 cp host-eth0}
 * Example of how to remove the pairing:
 * @cliexcmd{create pppoe map dp GigabitEthernet0/8/0 cp host-eth0 del}
 ?*/
VLIB_CLI_COMMAND (create_pppoe_map_command, static) = {
  .path = "create pppoe map",
  .short_help = "create pppoe map dp <intfc> cp <intfc> [del]",
  .function = pppoe_add_del_cp_command_fn,
};

static clib_error_t *
show_pppoe_cp_binding_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  pppoe_main_t *pem = &pppoe_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 dp_sw_if_index;
  u32 n_bindings = 0;

  for (dp_sw_if_index = 0; dp_sw_if_index < vec_len (pem->cp_if_index_by_sw_if_index);
       dp_sw_if_index++)
    {
      u32 cp_sw_if_index = pem->cp_if_index_by_sw_if_index[dp_sw_if_index];

      if (cp_sw_if_index == ~0)
	continue;

      if (n_bindings == 0)
	vlib_cli_output (vm, "%-32s%-32s", "Data plane interface", "Control plane interface");

      vlib_cli_output (vm, "%-32U%-32U", format_vnet_sw_if_index_name, vnm, dp_sw_if_index,
		       format_vnet_sw_if_index_name, vnm, cp_sw_if_index);
      n_bindings++;
    }

  if (n_bindings == 0)
    vlib_cli_output (vm, "No PPPoE control plane binding configured...");

  return 0;
}

/*?
 * Display the control plane and data plane interface pairs of the PPPoE
 * plugin.
 *
 * @cliexpar
 * Example of how to display the pairs:
 * @cliexstart{show pppoe control-plane binding}
 * Data plane interface            Control plane interface
 * GigabitEthernet0/8/0            host-eth0
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (show_pppoe_cp_binding_command, static) = {
  .path = "show pppoe control-plane binding",
  .short_help = "show pppoe control-plane binding",
  .function = show_pppoe_cp_binding_command_fn,
};
