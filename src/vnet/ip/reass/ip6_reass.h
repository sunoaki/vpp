/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

/**
 * @file
 * @brief Helpers shared by IPv6 shallow and full reassembly.
 */

#ifndef __included_ip6_reass_h__
#define __included_ip6_reass_h__

#include <vnet/vnet.h>
#include <vnet/ip/icmp6.h>
#include <vnet/ip/ip6_packet.h>

/**
 * @brief Length in bytes of the fragment data carried by a fragment.
 *
 * RFC 8200 section 4.5 computes the length of a fragment by subtracting from
 * the Payload Length field the headers between the IPv6 header and the
 * fragment itself, so the bytes following the fragment header are the bytes
 * the Payload Length field declares. Deriving the length from the Payload
 * Length field instead of the buffer chain length keeps frame padding and
 * trailers from being counted as fragment data.
 *
 * Returns false, leaving *fragment_data_len untouched, when the Payload
 * Length field does not reach past the fragment header or when the buffer
 * chain is shorter than the packet the Payload Length field declares. Both
 * cases would underflow the subtraction above.
 *
 * @param vm vlib main
 * @param b fragment buffer, IPv6 header at vlib_buffer_get_current
 * @param fragment_data_len result
 * @return true when the length was computed
 */
always_inline bool
ip6_reass_fragment_data_len (vlib_main_t *vm, vlib_buffer_t *b,
			     u32 *fragment_data_len)
{
  ip6_header_t *ip = vlib_buffer_get_current (b);
  u32 fragment_data_offset =
    vnet_buffer (b)->ip.reass.ip6_frag_hdr_offset + sizeof (ip6_frag_hdr_t);
  u32 packet_len =
    sizeof (ip6_header_t) + clib_net_to_host_u16 (ip->payload_length);

  if (packet_len < fragment_data_offset ||
      vlib_buffer_length_in_chain (vm, b) < packet_len)
    return false;

  *fragment_data_len = packet_len - fragment_data_offset;
  return true;
}

/**
 * @brief Report a fragment whose Payload Length field cannot be used.
 *
 * Sets an ICMPv6 Parameter Problem, code 0, pointing at the Payload Length
 * field, which is what RFC 8200 section 4.5 asks for a length derived from a
 * malformed Payload Length field.
 *
 * @param b buffer holding the fragment
 */
always_inline void
ip6_reass_set_payload_length_error (vlib_buffer_t *b)
{
  ip6_header_t *ip = vlib_buffer_get_current (b);

  icmp6_error_set_vnet_buffer (
    b, ICMP6_parameter_problem,
    ICMP6_parameter_problem_erroneous_header_field,
    (u8 *) &ip->payload_length - (u8 *) ip);
}

#endif /* __included_ip6_reass_h__ */
