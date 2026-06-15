/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

/*
 * Feature-arc TTL/hop-limit fixup for transparent host forwarding.
 *
 * When VPP sits between a Linux host tap and a physical uplink, it acts
 * as a transparent forwarder for host-originated traffic. However,
 * ip4/ip6-rewrite decrements TTL/hop-limit on every forwarded packet,
 * breaking protocols that transmit with TTL=1 (DHCPv6, eBGP, etc.).
 *
 * This module registers ip4-ttl-fixup and ip6-ttl-fixup nodes on the
 * ip4-unicast and ip6-unicast input feature arcs respectively, enabled
 * only on configured source interfaces (e.g. tap0). The node performs
 * a FIB lookup and resolves the load-balance to find the output
 * adjacency. If the adjacency's output sw_if_index matches the
 * configured destination (uplink), the packet is marked with the
 * VNET_BUFFER_F_LOCALLY_ORIGINATED flag so ip4/ip6-rewrite skips
 * TTL/hop-limit decrement.
 *
 * Only packets from the configured source interface traverse this node.
 * All other traffic follows the regular graph path with zero overhead.
 */

#ifndef __IP_TTL_FIXUP_H__
#define __IP_TTL_FIXUP_H__

#include <vnet/vnet.h>

typedef struct
{
  /* Per-source interface: expected destination sw_if_index.
   * Indexed by sw_if_index. Value is the destination sw_if_index
   * for which TTL/hop-limit decrement should be skipped.
   * Example: dst_by_src[tap0_sw_if_index] = uplink_sw_if_index
   */
  u32 *dst_by_src;

  /* Quick check: non-zero when at least one pair is configured. */
  u8 enabled;
} ip_ttl_fixup_cfg_t;

extern ip_ttl_fixup_cfg_t ip_ttl_fixup_cfg;

/**
 * TTL fixup main structure for API and management.
 */
typedef struct
{
  u16 msg_id_base;
  vnet_main_t *vnet_main;
} ip_ttl_fixup_main_t;

extern ip_ttl_fixup_main_t ip_ttl_fixup_main;

#endif /* __IP_TTL_FIXUP_H__ */
