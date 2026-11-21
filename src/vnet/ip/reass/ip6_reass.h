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
 * Length field ends before the fragment data or when the buffer chain is
 * shorter than the packet the Payload Length field declares. The first
 * condition protects the subtraction above; the second rejects a frame that
 * cannot back the declared length.
 *
 * @param vm vlib main
 * @param b fragment buffer, IPv6 header at vlib_buffer_get_current
 * @param fragment_data_len result
 * @return true when the length was computed
 */
always_inline bool
ip6_reass_fragment_data_len (vlib_main_t *vm, vlib_buffer_t *b, u32 *fragment_data_len)
{
  ip6_header_t *ip = vlib_buffer_get_current (b);
  u32 fragment_data_offset =
    vnet_buffer (b)->ip.reass.ip6_frag_hdr_offset + sizeof (ip6_frag_hdr_t);
  u32 packet_len = sizeof (ip6_header_t) + clib_net_to_host_u16 (ip->payload_length);

  if (packet_len < fragment_data_offset || vlib_buffer_length_in_chain (vm, b) < packet_len)
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

  icmp6_error_set_vnet_buffer (b, ICMP6_parameter_problem,
			       ICMP6_parameter_problem_erroneous_header_field,
			       (u8 *) &ip->payload_length - (u8 *) ip);
}

/**
 * @brief Report a fragment header the packet does not hold in full.
 *
 * RFC 8200 section 4.5 puts the fragment header inside the payload the
 * Payload Length field declares. A header chain that reaches a fragment
 * header those bounds end inside is malformed, so the packet is answered with
 * ICMPv6 Parameter Problem, code 0, pointing at the first byte of the header.
 *
 * @param b buffer holding the fragment
 * @param fragment_hdr_offset offset of the fragment header from the IPv6 header
 */
always_inline void
ip6_reass_set_truncated_fragment_header_error (vlib_buffer_t *b, u32 fragment_hdr_offset)
{
  icmp6_error_set_vnet_buffer (b, ICMP6_parameter_problem,
			       ICMP6_parameter_problem_erroneous_header_field, fragment_hdr_offset);
}

/**
 * @brief Locate a fragment header the packet does not hold in full.
 *
 * ip6_ext_header_walk stops at a fragment header that straddles the end of the
 * packet instead of reporting it, so the returned chain ends at the header
 * before it and a caller cannot tell such a packet from one whose chain never
 * reaches a fragment header. The advance is recomputed here under the same
 * bounds the walk uses, and the result is only reported when those bounds come
 * from the packet itself: a chain the walk cut short at IP6_EXT_HDR_MAX or
 * IP6_EXT_HDR_MAX_DEPTH ends the same way and is not malformed.
 *
 * @param b buffer holding the packet
 * @param ip IPv6 header the chain was walked from
 * @param chain header chain returned by ip6_ext_header_walk
 * @param fragment_hdr_offset result: offset of the fragment header from the
 *        IPv6 header, written only when the function returns true
 * @return true when the chain ends at a fragment header the packet does not
 *         cover
 */
always_inline bool
ip6_reass_truncated_fragment_header (vlib_buffer_t *b, ip6_header_t *ip, ip6_ext_hdr_chain_t *chain,
				     u32 *fragment_hdr_offset)
{
  int last = chain->length - 1;
  u32 packet_max_offset;
  u32 max_offset;
  u32 next_offset;
  u32 last_offset;
  int last_proto;

  if (last < 0 || chain->length >= IP6_EXT_HDR_MAX)
    return false;

  last_offset = chain->eh[last].offset;
  last_proto = (int) chain->eh[last].protocol;

  /* A fragment header the walk reported lies inside the bounds already, and no
   * extension header follows a terminating one.
   */
  if (!ip6_ext_hdr (last_proto) && last_proto != IP_PROTOCOL_IPSEC_AH)
    return false;

  packet_max_offset = clib_min (vlib_bytes_left_in_buffer (b, ip),
				sizeof (ip6_header_t) + clib_net_to_host_u16 (ip->payload_length));
  max_offset = clib_min (packet_max_offset, IP6_EXT_HDR_MAX_DEPTH);

  /* The walk only records an entry it could read the first two bytes of. */
  if (last_offset + sizeof (ip6_ext_header_t) > max_offset)
    return false;

  ip6_ext_header_t *last_hdr = ip6_ext_next_header_offset (ip, last_offset);
  if (last_hdr->next_hdr != IP_PROTOCOL_IPV6_FRAGMENTATION)
    return false;

  next_offset = last_offset + ip6_ext_header_len_s (last_proto, last_hdr);
  if (next_offset > max_offset)
    return false;

  /* The walk advanced here, so only a fragment header that runs past the end
   * of the packet stops it. Bounds the depth limit set instead are not a
   * malformed packet.
   */
  if (next_offset + sizeof (ip6_frag_hdr_t) <= packet_max_offset)
    return false;

  *fragment_hdr_offset = next_offset;
  return true;
}

#endif /* __included_ip6_reass_h__ */
