/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Intel and/or its affiliates.
 */

#include <stdbool.h>

#include <vlib/vlib.h>
#include <ppp/packet.h>
#include <pppoe/pppoe.h>

#define foreach_pppoe_cp_next                                                                      \
  _ (DROP, "error-drop")                                                                           \
  _ (INTERFACE, "interface-output")

typedef enum
{
#define _(s, n) PPPOE_CP_NEXT_##s,
  foreach_pppoe_cp_next
#undef _
    PPPOE_CP_N_NEXT,
} pppoe_cp_next_t;

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u32 cp_if_index;
  u8 pppoe_code;
  u16 ppp_proto;
  u32 error;
} pppoe_cp_trace_t;

static u8 *
format_pppoe_cp_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pppoe_cp_trace_t *t = va_arg (*args, pppoe_cp_trace_t *);

  s = format (s,
	      "PPPoE dispatch from sw_if_index %d cp_if_index %d next %d "
	      "error %d\n  pppoe_code 0x%x  ppp_proto 0x%x",
	      t->sw_if_index, t->cp_if_index, t->next_index, t->error, t->pppoe_code, t->ppp_proto);

  return s;
}

/*
 * Everything below changes the session table or the main interface database,
 * so on a worker it is handed to the main thread, which changes them under
 * the barrier. The session is named by its interface and the count the slot
 * kept when the frame was read, because the main thread may have freed that
 * session and handed the slot to the next one by the time the work runs.
 */
static void
pppoe_cp_session_request (pppoe_session_t *t, u8 is_ip6, const ip46_address_t *client_ip)
{
  vnet_pppoe_add_del_session_args_t a;

  clib_memset (&a, 0, sizeof (a));
  a.is_add = 1;
  a.is_ip6 = is_ip6;
  a.session_id = t->session_id;
  a.encap_if_index = t->encap_if_index;
  a.decap_fib_index = fib_table_find (is_ip6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4, 0);
  /* the session this observation is made for, which the main thread checks
   * before it applies the address */
  a.generation = t->generation;
  clib_memcpy (a.client_mac, t->client_mac, 6);
  clib_memcpy (a.local_mac, t->local_mac, 6);

  if (client_ip)
    ip46_address_copy (is_ip6 ? &a.client_ip6 : &a.client_ip, client_ip);

  vlib_rpc_call_main_thread (vnet_pppoe_add_del_session_cb, (u8 *) &a, sizeof (a));
}

static void
pppoe_cp_lcp_echo (pppoe_session_t *t, u8 code)
{
  /*
   * A reply names the request it answers, as the data plane last saw the
   * ledger; the main thread decides whether the answer counts. A request
   * carries an epoch too, which the main thread numbers itself.
   */
  pppoe_lcp_echo_t echo = {
    .hw_if_index = t->hw_if_index,
    .session_id = t->session_id,
    .generation = t->generation,
    .is_request = code == PPP_LCP_ECHO_REQUEST,
    .request_epoch = t->lcp_echo_request_epoch,
  };

  vlib_rpc_call_main_thread (vnet_pppoe_lcp_echo_cb, (u8 *) &echo, sizeof (echo));
}

/*
 * Both handlers below decode what the access concentrator sends, because the
 * caller only hands them the frames it read on the control plane side and
 * matched against the paired data plane port. A Configure-Nak named here is
 * the concentrator's own, which carries the option it wants the client to
 * use; the one the client sends travels the session path instead.
 *
 * IPCP hands the client its address in the address option of that
 * Configure-Nak, and the address is what the session routes.
 */
static void
pppoe_cp_handle_ipcp (pppoe_session_t *t, u8 *packet, u32 len)
{
  ppp_control_header_t *hdr = (ppp_control_header_t *) packet;
  u32 pkt_len;
  u8 *end, *opt;

  if (len < sizeof (*hdr) || hdr->code != PPP_IPCP_CONFIGURE_NAK)
    return;

  /* the packet length is part of the header and bounds the options */
  pkt_len = clib_net_to_host_u16 (hdr->length);
  if (pkt_len < sizeof (*hdr))
    return;

  end = packet + (pkt_len < len ? pkt_len : len);

  for (opt = (u8 *) (hdr + 1); opt + sizeof (ppp_control_option_t) <= end;
       opt += ((ppp_control_option_t *) opt)->length)
    {
      ppp_control_option_t *o = (ppp_control_option_t *) opt;
      ip46_address_t client_ip;

      if (o->length < sizeof (*o) || opt + o->length > end)
	return;

      if (o->type != PPP_IPCP_OPTION_IP_ADDRESS ||
	  o->length != sizeof (*o) + sizeof (ip4_address_t))
	continue;

      clib_memset (&client_ip, 0, sizeof (client_ip));
      clib_memcpy (&client_ip.ip4, o->data, sizeof (client_ip.ip4));
      pppoe_cp_session_request (t, 0 /* is_ip6 */, &client_ip);
      return;
    }
}

/*
 * IPv6CP negotiates the interface identifier both ends use; the one the client
 * gets is what the concentrator puts in its Configure-Nak, and the client
 * address is the link-local address built from it. A router advertisement
 * later carries the global prefix.
 */
static void
pppoe_cp_handle_ipv6cp (pppoe_session_t *t, u8 *packet, u32 len)
{
  ppp_control_header_t *hdr = (ppp_control_header_t *) packet;
  pppoe_ip6_ident_update_t update = {
    .hw_if_index = t->hw_if_index,
    .session_id = t->session_id,
    .generation = t->generation,
  };
  u8 *end, *opt;
  u32 pkt_len;

  if (len < sizeof (*hdr) || hdr->code != PPP_IPV6CP_CONFIGURE_NAK)
    return;

  pkt_len = clib_net_to_host_u16 (hdr->length);
  if (pkt_len < sizeof (*hdr))
    return;

  end = packet + (pkt_len < len ? pkt_len : len);

  for (opt = (u8 *) (hdr + 1); opt + sizeof (ppp_control_option_t) <= end;
       opt += ((ppp_control_option_t *) opt)->length)
    {
      ppp_control_option_t *o = (ppp_control_option_t *) opt;

      if (o->length < sizeof (*o) || opt + o->length > end)
	return;

      if (o->type != PPP_IPV6CP_OPTION_INTERFACE_IDENTIFIER ||
	  o->length != sizeof (*o) + sizeof (update.ip6_ident))
	continue;

      clib_memcpy (&update.ip6_ident, o->data, sizeof (update.ip6_ident));
      vlib_rpc_call_main_thread (vnet_pppoe_ip6_ident_cb, (u8 *) &update, sizeof (update));
      return;
    }
}

static void
pppoe_cp_handle_ip6_ra (pppoe_session_t *t, u8 *icmp6, u32 len)
{
  icmp6_router_advertisement_header_t *ra = (icmp6_router_advertisement_header_t *) icmp6;
  u8 *opt = (u8 *) (ra + 1);
  u8 *end = icmp6 + len;

  if (len < sizeof (*ra))
    return;

  while (opt + sizeof (icmp6_neighbor_discovery_option_header_t) <= end)
    {
      icmp6_neighbor_discovery_option_header_t *oh =
	(icmp6_neighbor_discovery_option_header_t *) opt;
      u32 opt_len = oh->n_data_u64s * 8;
      pppoe_ip6_prefix_t update = {
	.hw_if_index = t->hw_if_index,
	.session_id = t->session_id,
	.generation = t->generation,
      };

      /* a zero length would keep the walk in place */
      if (opt_len == 0 || opt + opt_len > end)
	return;

      if (oh->type != ICMP6_NEIGHBOR_DISCOVERY_OPTION_prefix_information ||
	  opt_len < sizeof (icmp6_neighbor_discovery_prefix_information_option_t))
	goto next;

      {
	icmp6_neighbor_discovery_prefix_information_option_t *po =
	  (icmp6_neighbor_discovery_prefix_information_option_t *) opt;

	/*
	 * The prefix completes the interface identifier IPv6CP negotiated,
	 * which is the low 64 bits: a shorter prefix would turn part of the
	 * identifier into prefix bits and a longer one would lose prefix bits.
	 * Multicast, link-local and unspecified prefixes are not addresses the
	 * client is reached at.
	 */
	if (po->dst_address_length != 64 || ip6_address_is_multicast (&po->dst_address) ||
	    ip6_address_is_link_local_unicast (&po->dst_address) ||
	    ip6_address_is_unspecified (&po->dst_address))
	  goto next;

	update.prefix = po->dst_address;
	update.prefix_len = po->dst_address_length;
	update.session_id = t->session_id;
      }

      vlib_rpc_call_main_thread (vnet_pppoe_ip6_prefix_cb, (u8 *) &update, sizeof (update));
      return;

    next:
      opt += opt_len;
    }
}

/* The node never changes the session table itself: a worker only reads it to
 * attribute a frame, and what the frame means is handed to the main thread.
 * len is the whole frame counted from data[0], the way the reset leaves it. */
static void
pppoe_cp_session_frame (pppoe_session_t *t, pppoe_header_t *pppoe0, u32 len, bool is_from_client)
{
  u8 *packet = (u8 *) (pppoe0 + 1);

  /* the headers in front of the payload, which the frame must at least hold */
  if (PREDICT_FALSE (len <= sizeof (ethernet_header_t) + sizeof (*pppoe0)))
    return;

  len -= sizeof (ethernet_header_t) + sizeof (*pppoe0);

  switch (clib_net_to_host_u16 (pppoe0->ppp_proto))
    {
    case PPP_PROTOCOL_lcp:
      if (len < sizeof (ppp_control_header_t))
	break;
      /*
       * The limit on unanswered echo requests judges the client, so only the
       * frames the client sends can drive it: those arrive on the data plane
       * port, and the control plane only reads them.
       */
      if (is_from_client)
	if (((ppp_control_header_t *) packet)->code == PPP_LCP_ECHO_REQUEST ||
	    ((ppp_control_header_t *) packet)->code == PPP_LCP_ECHO_REPLY)
	  pppoe_cp_lcp_echo (t, ((ppp_control_header_t *) packet)->code);
      break;

    case PPP_PROTOCOL_IPCP:
      pppoe_cp_handle_ipcp (t, packet, len);
      break;

    case PPP_PROTOCOL_IPV6CP:
      pppoe_cp_handle_ipv6cp (t, packet, len);
      break;

    case PPP_PROTOCOL_ip6:
      {
	ip6_header_t *ip6 = (ip6_header_t *) packet;
	icmp46_header_t *icmp6;

	if (len < sizeof (*ip6) + sizeof (*icmp6) || ip6->protocol != IP_PROTOCOL_ICMP6)
	  break;

	icmp6 = (icmp46_header_t *) (ip6 + 1);

	if (icmp6->type == ICMP6_router_advertisement)
	  pppoe_cp_handle_ip6_ra (t, (u8 *) icmp6, len - sizeof (*ip6));
	else if (icmp6->type == ICMP6_router_solicitation)
	  pppoe_cp_session_request (t, 1 /* is_ip6 */, NULL);
      }
      break;

    default:
      break;
    }
}

VLIB_NODE_FN (pppoe_cp_dispatch_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  pppoe_main_t *pem = &pppoe_main;
  vnet_main_t *vnm = pem->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  u32 pkts_decapsulated = 0;
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  pppoe_entry_key_t cached_key;
  pppoe_entry_result_t cached_result;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  /* Clear the one-entry cache in case session table was updated */
  cached_key.raw = ~0;
  cached_result.raw = ~0; /* warning be gone */

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ethernet_header_t *h0;
	  pppoe_header_t *pppoe0;
	  pppoe_entry_key_t key0;
	  pppoe_entry_result_t result0;

	  u32 bucket0;
	  u32 next0;
	  u32 error0 = 0;
	  u32 rx_sw_if_index0 = ~0, tx_sw_if_index0 = ~0, cp_if_index0, data_sw_if_index0, len0;
	  u32 packet_len0;
	  u16 ppp_proto0;
	  vnet_hw_interface_t *hi;
	  vnet_sw_interface_t *si;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  /* the frame starts at data[0]: reset also puts the payload back, which
	   * the length below counts */
	  vlib_buffer_reset (b0);
	  /* the pppoe header is behind the ethernet header, whether ethernet input
	   * left the buffer at data[0] or the decap node advanced it to the pppoe
	   * header before handing the frame over */
	  pppoe0 = (pppoe_header_t *) (vlib_buffer_get_current (b0) + sizeof (ethernet_header_t));
	  rx_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  /* the frame length stays counted from data[0]: the callee subtracts
	   * the headers in front of the payload */
	  packet_len0 = vlib_buffer_length_in_chain (vm, b0);

	  if (PREDICT_FALSE (packet_len0 < sizeof (ethernet_header_t) + sizeof (*pppoe0)) ||
	      PREDICT_FALSE (pppoe0->ver_type != PPPOE_VER_TYPE))
	    {
	      error0 = PPPOE_ERROR_BAD_VER_TYPE;
	      next0 = PPPOE_INPUT_NEXT_DROP;
	      goto trace00;
	    }

	  ppp_proto0 = clib_net_to_host_u16 (pppoe0->ppp_proto);

	  h0 = vlib_buffer_get_current (b0);

	  /*
	   * Two kinds of frames reach this node, told apart by the port they
	   * arrived on. On a data plane port the client sends a frame, and the
	   * port it arrived on is the one its session was built for: the frame is
	   * observed against that session when it names it, and forwarded to the
	   * control plane port the port is paired with. On a control plane port
	   * the access concentrator answers on the session the frame names.
	   *
	   * A worker only reads the session table: a session is learned by the
	   * main thread when the session is added. The link table maps a client
	   * MAC to the port its frames arrive on, and the control plane hands it
	   * over when it pairs a port; the add of a session takes the data plane
	   * port its caller names and does not consult the table.
	   */
	  cp_if_index0 = pppoe_cp_if_index_by_dp (pem, rx_sw_if_index0);
	  if (cp_if_index0 != ~0)
	    {
	      /*
	       * The session the port holds is the one the client's frames belong
	       * to, and the frame names it: a frame that names another session is
	       * not this client's, and the concentrator's answer is the one that
	       * travels the other way. Only the client's own frames count as the
	       * client answering, because a host on the control plane port could
	       * answer an echo on a live session's behalf: PPPoE has no shared
	       * secret, the session ID is handed out in the clear during discovery
	       * and the client MAC is carried on the wire.
	       */
	      if (pem->is_auto_discovery)
		{
		  pppoe_session_t *t = pppoe_session_find_by_sw_if_index (rx_sw_if_index0);

		  if (t && t->is_admin_up &&
		      t->session_id == clib_net_to_host_u16 (pppoe0->session_id))
		    pppoe_cp_session_frame (t, pppoe0, packet_len0, true);
		}

	      pppoe_lookup_1 (&pem->link_table, &cached_key, &cached_result, h0->src_address, 0,
			      &key0, &bucket0, &result0);

	      /* learn the port the client's frames arrive on */
	      pppoe_learn_process (&pem->link_table, rx_sw_if_index0, &key0, &cached_key, &bucket0,
				   &result0);

	      next0 = PPPOE_CP_NEXT_INTERFACE;
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = cp_if_index0;
	      goto done00;
	    }

	  /*
	   * The node cannot tell who sent a frame on the control plane port, so
	   * what that port carries is never used to judge whether the client is
	   * alive: the liveness that ends a session comes from the frames the
	   * client itself sends over the data plane port, observed above, and only
	   * when the operator turned auto discovery on.
	   *
	   * A port with no pairing has no control plane port to hand a session
	   * frame to, so the frame is dropped here and counted as such. Master
	   * sent it to interface index ~0, which the interface output path dropped
	   * without naming why.
	   */
	  data_sw_if_index0 = pppoe_dp_if_index_by_cp (pem, rx_sw_if_index0);
	  if (PREDICT_FALSE (data_sw_if_index0 == ~0))
	    {
	      error0 = PPPOE_ERROR_NO_CONTROL_PLANE_PORT;
	      next0 = PPPOE_INPUT_NEXT_DROP;
	      goto trace00;
	    }

	  /*
	   * A frame that names a session goes to the port that session is on,
	   * found the way the session was learned: its client's MAC address and
	   * its session ID. The destination address of the frame is not that
	   * lookup: a concentrator that sends under a host address, or a frame
	   * routed to the client, names a destination the link table may not hold,
	   * and the port it reads there would not be where the session lives. A
	   * frame that names no session keeps the link table's answer for its
	   * destination, which is how the client's own discovery frames were sent
	   * back.
	   */
	  tx_sw_if_index0 = ~0;
	  if (pppoe0->session_id != 0)
	    {
	      /* the table's key carries the session ID as the frame does, in
	       * network order, which is how decap and the add write it */
	      pppoe_lookup_1 (&pem->session_table, &cached_key, &cached_result, h0->dst_address,
			      pppoe0->session_id, &key0, &bucket0, &result0);
	      tx_sw_if_index0 = result0.fields.sw_if_index;
	    }

	  if (PREDICT_FALSE (tx_sw_if_index0 == ~0))
	    {
	      pppoe_lookup_1 (&pem->link_table, &cached_key, &cached_result, h0->dst_address, 0,
			      &key0, &bucket0, &result0);
	      tx_sw_if_index0 = result0.fields.sw_if_index;
	    }

	  if (PREDICT_FALSE (tx_sw_if_index0 == ~0))
	    {
	      error0 = PPPOE_ERROR_NO_SUCH_SESSION;
	      next0 = PPPOE_INPUT_NEXT_DROP;
	      goto trace00;
	    }

	  next0 = PPPOE_CP_NEXT_INTERFACE;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = tx_sw_if_index0;

	  /*
	   * A frame the concentrator sent is forwarded to the data plane port its
	   * client is paired with and goes out under that port's address, the way
	   * the frame from the client went out under the control plane port's. The
	   * copy names the Ethernet source field, 6 bytes into the frame, through
	   * the header pointer rather than through current_data + 6: current_data
	   * is put back to the start of the frame above and the header pointer is
	   * derived from it, so where this copy lands cannot drift.
	   *
	   * An IP payload is the client's own packet and keeps its source: the
	   * pseudo-header of a UDP or TCP checksum covers that address, and
	   * nothing on this path recomputes the checksum a changed source would
	   * invalidate.
	   */
	  if (ppp_proto0 == PPP_PROTOCOL_ip4 || ppp_proto0 == PPP_PROTOCOL_ip6)
	    goto done00;

	  si = vnet_get_sw_interface (vnm, tx_sw_if_index0);
	  if (si->type == VNET_SW_INTERFACE_TYPE_SUB)
	    {
	      si = vnet_get_sw_interface (vnm, si->sup_sw_if_index);
	    }
	  hi = vnet_get_hw_interface (vnm, si->hw_if_index);
	  clib_memcpy_fast (h0->src_address, hi->hw_address, sizeof (h0->src_address));

	done00:
	  len0 = vlib_buffer_length_in_chain (vm, b0);

	  pkts_decapsulated++;
	  stats_n_packets += 1;
	  stats_n_bytes += len0;

	  /* Batch stats increment on the same pppoe session so counter
	     is not incremented per packet */
	  if (PREDICT_FALSE (rx_sw_if_index0 != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len0;
	      if (stats_n_packets)
		vlib_increment_combined_counter (
		  im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX, thread_index,
		  stats_sw_if_index, stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len0;
	      stats_sw_if_index = rx_sw_if_index0;
	    }

	trace00:
	  b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      pppoe_cp_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->error = error0;
	      tr->sw_if_index = rx_sw_if_index0;
	      tr->cp_if_index = cp_if_index0;
	      tr->pppoe_code = pppoe0->code;
	      tr->ppp_proto = clib_net_to_host_u16 (pppoe0->ppp_proto);
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0,
					   next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  /* Do we still need this now that session tx stats is kept? */
  vlib_node_increment_counter (vm, pppoe_input_node.index, PPPOE_ERROR_DECAPSULATED,
			       pkts_decapsulated);

  /* Increment any remaining batch stats */
  if (stats_n_packets)
    {
      vlib_increment_combined_counter (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
				       thread_index, stats_sw_if_index, stats_n_packets,
				       stats_n_bytes);
      node->runtime_data[0] = stats_sw_if_index;
    }

  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (pppoe_cp_dispatch_node) = {
  .name = "pppoe-cp-dispatch",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = PPPOE_N_ERROR,
  .error_strings = pppoe_error_strings,

  .n_next_nodes = PPPOE_CP_N_NEXT,
  .next_nodes = {
#define _(s, n) [PPPOE_CP_NEXT_##s] = n,
    foreach_pppoe_cp_next
#undef _
  },

  .format_trace = format_pppoe_cp_trace,
};
