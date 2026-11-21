/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Intel and/or its affiliates.
 */

/*
 * pppoe_api.c - pppoe api
 */

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>
#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>

#include <pppoe/pppoe.h>

#include <vnet/format_fns.h>
#include <pppoe/pppoe.api_enum.h>
#include <pppoe/pppoe.api_types.h>

#define REPLY_MSG_ID_BASE pem->msg_id_base
#include <vlibapi/api_helper_macros.h>

static int
pppoe_add_del_session_from_api (vnet_pppoe_add_del_session_args_t *a, u32 decap_fib_index,
				vl_api_interface_index_t encap_if_index, u8 disable_fib,
				u32 *sw_if_indexp)
{
  int rv;

  a->decap_fib_index = decap_fib_index;
  a->encap_if_index = encap_if_index;
  a->disable_fib = disable_fib;
  /* the API names the session by its ID and address, not by a session a
   * queued observation was made for */
  a->generation = ~0;

  rv = vnet_pppoe_add_del_session (a, sw_if_indexp);
  if (rv)
    *sw_if_indexp = ~0;

  return rv;
}

static void
vl_api_pppoe_add_del_session_t_handler (vl_api_pppoe_add_del_session_t *mp)
{
  vl_api_pppoe_add_del_session_reply_t *rmp;
  int rv = 0;
  u32 decap_fib_index;
  u32 sw_if_index = ~0;
  ip4_main_t *im = &ip4_main;
  pppoe_main_t *pem = &pppoe_main;

  /*
   * The data plane interface is resolved from the client's MAC, which the
   * binding learns only from a frame the client sent: the add names no
   * interface and the binding cannot be given one here, so an add for a MAC
   * with no binding is rejected as an invalid interface index. The control
   * plane path learns the MAC before it adds the session, so it meets the
   * requirement by construction; this message cannot. pppoe_add_del_session_v2
   * names the interface instead.
   */
  uword *p = hash_get (im->fib_index_by_table_id, ntohl (mp->decap_vrf_id));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_INNER_FIB;
      goto out;
    }
  decap_fib_index = p[0];

  vnet_pppoe_add_del_session_args_t a = {
    .is_add = mp->is_add,
    .session_id = ntohs (mp->session_id),
  };
  ip_address_decode (&mp->client_ip, &a.client_ip);
  clib_memcpy (a.client_mac, mp->client_mac, 6);

  rv = pppoe_add_del_session_from_api (&a, decap_fib_index, ~0, 0, &sw_if_index);

out:
  REPLY_MACRO2 (VL_API_PPPOE_ADD_DEL_SESSION_REPLY, ({ rmp->sw_if_index = ntohl (sw_if_index); }));
}

static void
vl_api_pppoe_add_del_session_v2_t_handler (vl_api_pppoe_add_del_session_v2_t *mp)
{
  vl_api_pppoe_add_del_session_v2_reply_t *rmp;
  int rv = 0;
  u32 decap_fib_index;
  u32 sw_if_index = ~0;
  ip4_main_t *im = &ip4_main;
  pppoe_main_t *pem = &pppoe_main;

  /*
   * The request names the interface towards the client when it knows it, as
   * the control plane does for a session it creates from a negotiation frame.
   * With 0xFFFFFFFF the binding is asked instead, and it only knows a client
   * from a frame the client sent, so such an add for a MAC with no binding is
   * rejected as an invalid interface index.
   */
  uword *p = hash_get (im->fib_index_by_table_id, ntohl (mp->decap_vrf_id));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_INNER_FIB;
      goto out;
    }
  decap_fib_index = p[0];

  vnet_pppoe_add_del_session_args_t a = {
    .is_add = mp->is_add,
    .session_id = ntohs (mp->session_id),
  };
  ip_address_decode (&mp->client_ip, &a.client_ip);
  clib_memcpy (a.client_mac, mp->client_mac, 6);

  rv = pppoe_add_del_session_from_api (&a, decap_fib_index, ntohl (mp->encap_if_index),
				       mp->disable_fib, &sw_if_index);

out:
  REPLY_MACRO2 (VL_API_PPPOE_ADD_DEL_SESSION_V2_REPLY,
		({ rmp->sw_if_index = ntohl (sw_if_index); }));
}

static void
send_pppoe_session_details (pppoe_session_t *t, vl_api_registration_t *reg, u32 context)
{
  vl_api_pppoe_session_details_t *rmp;
  pppoe_main_t *pem = &pppoe_main;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  u8 is_ipv6 = !ip46_address_is_ip4 (&t->client_ip);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (pem->msg_id_base + VL_API_PPPOE_SESSION_DETAILS);
  ip_address_encode (&t->client_ip, is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4, &rmp->client_ip);

  if (is_ipv6)
    {
      rmp->decap_vrf_id = htonl (im6->fibs[t->decap_fib_index].ft_table_id);
    }
  else
    {
      rmp->decap_vrf_id = htonl (im4->fibs[t->decap_fib_index].ft_table_id);
    }
  rmp->session_id = htons (t->session_id);
  rmp->encap_if_index = htonl (t->encap_if_index);
  clib_memcpy (rmp->local_mac, t->local_mac, 6);
  clib_memcpy (rmp->client_mac, t->client_mac, 6);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_pppoe_session_dump_t_handler (vl_api_pppoe_session_dump_t *mp)
{
  vl_api_registration_t *reg;
  pppoe_main_t *pem = &pppoe_main;
  pppoe_session_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      pool_foreach (t, pem->sessions)
	{
	  send_pppoe_session_details (t, reg, mp->context);
	}
    }
  else
    {
      t = pppoe_session_find_by_sw_if_index (sw_if_index);
      if (t)
	send_pppoe_session_details (t, reg, mp->context);
    }
}

/*
 * The message names one interface while the binding needs two, and pppoe.api
 * may not change yet, so the handler cannot express what the binding needs:
 *
 *  - the message index is read as the control plane interface, and the data
 *    plane interface is the one it is already bound to;
 *  - with no binding to look up, an add has no data plane interface and is
 *    rejected as an invalid argument, so a binding can only be created from
 *    the CLI;
 *  - for a delete the message index stands in for the data plane interface
 *    too, which only matches when it is the same index, so an unbind fails as
 *    well.
 *
 * In short, every add_del_cp message over the API fails until the message
 * carries both indexes; see the follow-up noted on the plugin.
 */
static u32
pppoe_api_dp_peer (u32 cp_sw_if_index, u8 is_add)
{
  pppoe_main_t *pem = &pppoe_main;
  u32 dp_sw_if_index;

  dp_sw_if_index = pppoe_dp_if_index_by_cp (pem, cp_sw_if_index);
  if (dp_sw_if_index != ~0)
    return dp_sw_if_index;

  /* an add cannot guess the peer, and a delete has no pairing to fall back
   * on: the single index names one interface, which cannot be both */
  return is_add ? ~0 : cp_sw_if_index;
}

static void
vl_api_pppoe_add_del_cp_t_handler (vl_api_pppoe_add_del_cp_t *mp)
{
  vl_api_pppoe_add_del_cp_reply_t *rmp;
  u32 cp_sw_if_index = ntohl (mp->sw_if_index);
  i32 rv = 0;
  pppoe_main_t *pem = &pppoe_main;

  rv =
    pppoe_add_del_cp (cp_sw_if_index, pppoe_api_dp_peer (cp_sw_if_index, mp->is_add), mp->is_add);

  REPLY_MACRO (VL_API_PPPOE_ADD_DEL_CP_REPLY);
}

/*
 * pppoe_add_del_cp naming both interfaces of the pair, so the handler no
 * longer has to look the other one up in the binding.
 */
static void
vl_api_pppoe_add_del_cp_v2_t_handler (vl_api_pppoe_add_del_cp_v2_t *mp)
{
  vl_api_pppoe_add_del_cp_v2_reply_t *rmp;
  i32 rv = 0;
  pppoe_main_t *pem = &pppoe_main;

  rv = pppoe_add_del_cp (ntohl (mp->cp_sw_if_index), ntohl (mp->dp_sw_if_index), mp->is_add);

  REPLY_MACRO (VL_API_PPPOE_ADD_DEL_CP_V2_REPLY);
}

typedef struct
{
  u32 context;
  u32 dp_sw_if_index;
  u32 cp_sw_if_index;
  i32 rv;
} pppoe_cp_binding_reply_t;

static void
send_pppoe_cp_binding_details (vl_api_registration_t *reg, pppoe_cp_binding_reply_t *b)
{
  vl_api_pppoe_cp_binding_details_t *rmp;
  pppoe_main_t *pem = &pppoe_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (pem->msg_id_base + VL_API_PPPOE_CP_BINDING_DETAILS);
  rmp->context = b->context;
  rmp->retval = htonl (b->rv);
  rmp->dp_sw_if_index = htonl (b->dp_sw_if_index);
  rmp->cp_sw_if_index = htonl (b->cp_sw_if_index);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_pppoe_cp_binding_dump_t_handler (vl_api_pppoe_cp_binding_dump_t *mp)
{
  vl_api_registration_t *reg;
  pppoe_main_t *pem = &pppoe_main;
  pppoe_cp_binding_reply_t b = {};
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 dp_sw_if_index, cp_sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  b.context = mp->context;

  /* every binding: iterate the data plane side of cp_if_index_by_sw_if_index
   * and send the control plane interface each one is paired with */
  if (~0 == sw_if_index)
    {
      for (dp_sw_if_index = 0; dp_sw_if_index < vec_len (pem->cp_if_index_by_sw_if_index);
	   dp_sw_if_index++)
	{
	  cp_sw_if_index = pppoe_cp_if_index_by_dp (pem, dp_sw_if_index);
	  if (~0 == cp_sw_if_index)
	    continue;
	  b.dp_sw_if_index = dp_sw_if_index;
	  b.cp_sw_if_index = cp_sw_if_index;
	  send_pppoe_cp_binding_details (reg, &b);
	}
      return;
    }

  /* one binding: the index may name either side of the pair */
  cp_sw_if_index = pppoe_cp_if_index_by_dp (pem, sw_if_index);
  if (~0 == cp_sw_if_index)
    {
      cp_sw_if_index = sw_if_index;
      b.dp_sw_if_index = pppoe_dp_if_index_by_cp (pem, sw_if_index);
      if (~0 == b.dp_sw_if_index)
	{
	  b.cp_sw_if_index = ~0;
	  b.rv = VNET_API_ERROR_INVALID_INTERFACE;
	  send_pppoe_cp_binding_details (reg, &b);
	  return;
	}
    }
  else
    b.dp_sw_if_index = sw_if_index;

  b.cp_sw_if_index = cp_sw_if_index;
  send_pppoe_cp_binding_details (reg, &b);
}

#include <pppoe/pppoe.api.c>
static clib_error_t *
pppoe_api_hookup (vlib_main_t *vm)
{
  pppoe_main_t *pem = &pppoe_main;

  pem->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (pppoe_api_hookup);
