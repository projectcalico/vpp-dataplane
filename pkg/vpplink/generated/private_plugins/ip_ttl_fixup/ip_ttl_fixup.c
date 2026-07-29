/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

/*
 * ip_ttl_fixup.c - Feature-arc TTL/hop-limit fixup for transparent forwarding.
 *
 * Registers ip4-ttl-fixup / ip6-ttl-fixup on the ip4-unicast / ip6-unicast
 * input feature arcs. When enabled on a source interface (tap0), the node
 * performs a FIB lookup, resolves the load-balance DPO to find the output
 * adjacency, and if adj->rewrite_header.sw_if_index matches the configured
 * destination (uplink), sets VNET_BUFFER_F_LOCALLY_ORIGINATED so ip4/ip6-
 * rewrite skips TTL decrement.
 *
 * Only packets arriving on the configured source interface traverse this
 * node. All other traffic follows the normal graph with zero overhead.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <ip_ttl_fixup/ip_ttl_fixup.h>
#include <vnet/ip/ip4_forward.h>
#include <vnet/ip/ip6_forward.h>
#include <vnet/ip/lookup.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/adj/adj.h>
#include <vnet/feature/feature.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

#include <ip_ttl_fixup/ip_ttl_fixup.api_enum.h>
#include <ip_ttl_fixup/ip_ttl_fixup.api_types.h>

#include <vnet/format_fns.h>

#define REPLY_MSG_ID_BASE ttfm->msg_id_base
#include <vlibapi/api_helper_macros.h>

ip_ttl_fixup_cfg_t ip_ttl_fixup_cfg = {
  .enabled = 0,
  .dst_by_src = 0,
};

ip_ttl_fixup_main_t ip_ttl_fixup_main;

/* ----------------------------------------------------------------
 * Configuration
 * ---------------------------------------------------------------- */

static void
ip_ttl_fixup_recompute_enabled (void)
{
  ip_ttl_fixup_cfg_t *cfg = &ip_ttl_fixup_cfg;
  u32 ii;

  cfg->enabled = 0;
  vec_foreach_index (ii, cfg->dst_by_src)
    {
      if (cfg->dst_by_src[ii] != (u32) ~0)
	{
	  cfg->enabled = 1;
	  break;
	}
    }
}

static void
ip_ttl_fixup_disable_src (u32 src_sw_if_index, int disable_feature)
{
  ip_ttl_fixup_cfg_t *cfg = &ip_ttl_fixup_cfg;

  if (src_sw_if_index >= vec_len (cfg->dst_by_src) || cfg->dst_by_src[src_sw_if_index] == (u32) ~0)
    return;

  cfg->dst_by_src[src_sw_if_index] = ~0;

  if (disable_feature)
    {
      vnet_feature_enable_disable ("ip4-unicast", "ip4-ttl-fixup", src_sw_if_index, 0, 0, 0);
      vnet_feature_enable_disable ("ip6-unicast", "ip6-ttl-fixup", src_sw_if_index, 0, 0, 0);
    }
}

static int
ip_ttl_fixup_configure (u32 src_sw_if_index, u32 dst_sw_if_index, int enable)
{
  ip_ttl_fixup_cfg_t *cfg = &ip_ttl_fixup_cfg;
  ip_ttl_fixup_main_t *ttfm = &ip_ttl_fixup_main;

  if (pool_is_free_index (ttfm->vnet_main->interface_main.sw_interfaces, src_sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  if (enable && pool_is_free_index (ttfm->vnet_main->interface_main.sw_interfaces, dst_sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX_2;

  vec_validate_init_empty (cfg->dst_by_src, src_sw_if_index, ~0);

  int was_enabled =
    (src_sw_if_index < vec_len (cfg->dst_by_src) && cfg->dst_by_src[src_sw_if_index] != (u32) ~0);

  if (enable)
    {
      cfg->dst_by_src[src_sw_if_index] = dst_sw_if_index;
    }
  else
    {
      cfg->dst_by_src[src_sw_if_index] = ~0;
    }

  int now_enabled = (cfg->dst_by_src[src_sw_if_index] != (u32) ~0);

  /* Enable / disable the input feature arc on the source interface
   * only when the state actually changes. */
  if (!was_enabled && now_enabled)
    {
      vnet_feature_enable_disable ("ip4-unicast", "ip4-ttl-fixup", src_sw_if_index, 1, 0, 0);
      vnet_feature_enable_disable ("ip6-unicast", "ip6-ttl-fixup", src_sw_if_index, 1, 0, 0);
    }
  else if (was_enabled && !now_enabled)
    {
      vnet_feature_enable_disable ("ip4-unicast", "ip4-ttl-fixup", src_sw_if_index, 0, 0, 0);
      vnet_feature_enable_disable ("ip6-unicast", "ip6-ttl-fixup", src_sw_if_index, 0, 0, 0);
    }

  ip_ttl_fixup_recompute_enabled ();

  return 0;
}

static clib_error_t *
ip_ttl_fixup_sw_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  ip_ttl_fixup_cfg_t *cfg = &ip_ttl_fixup_cfg;

  if (is_add)
    return 0;

  /* Clean up any configuration referencing the deleted interface. */
  if (sw_if_index < vec_len (cfg->dst_by_src) && cfg->dst_by_src[sw_if_index] != (u32) ~0)
    ip_ttl_fixup_disable_src (sw_if_index, 0 /* interface already deleted */);

  /* Also clean up entries where this interface is the destination. */
  {
    u32 ii;
    vec_foreach_index (ii, cfg->dst_by_src)
      {
	if (cfg->dst_by_src[ii] == sw_if_index)
	  ip_ttl_fixup_disable_src (ii, !pool_is_free_index (vnm->interface_main.sw_interfaces,
							     ii) /* source still exists */);
      }
  }

  ip_ttl_fixup_recompute_enabled ();

  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (ip_ttl_fixup_sw_interface_add_del);

/* ----------------------------------------------------------------
 * IPv4 feature-arc node
 * ---------------------------------------------------------------- */

typedef struct
{
  u32 rx_sw_if_index;
  u32 adj_sw_if_index;
  u32 dst_sw_if_index;
  u8 skip;
} ip_ttl_fixup_trace_t;

static u8 *
format_ip4_ttl_fixup_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip_ttl_fixup_trace_t *t = va_arg (*args, ip_ttl_fixup_trace_t *);

  s = format (s,
	      "ip4-ttl-fixup: rx_sw_if_index %u adj_sw_if_index %u "
	      "expected_dst %u skip %u",
	      t->rx_sw_if_index, t->adj_sw_if_index, t->dst_sw_if_index, t->skip);
  return s;
}

VLIB_NODE_FN (ip4_ttl_fixup_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ip_ttl_fixup_cfg_t *cfg = &ip_ttl_fixup_cfg;
  ip4_main_t *im = &ip4_main;
  u32 n_left, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left);
  b = bufs;
  next = nexts;

  while (n_left > 0)
    {
      u32 rx_sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      u32 expected_dst = ~0;
      u32 adj_out_sw = ~0;
      u8 skip = 0;

      if (PREDICT_TRUE (rx_sw_if_index < vec_len (cfg->dst_by_src)))
	{
	  expected_dst = cfg->dst_by_src[rx_sw_if_index];
	  if (PREDICT_TRUE (expected_dst != (u32) ~0))
	    {
	      /* FIB lookup - mirrors what ip4-lookup does. */
	      ip4_header_t *ip0 = vlib_buffer_get_current (b[0]);
	      u32 lbi;
	      const load_balance_t *lb;
	      const dpo_id_t *dpo;

	      ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, b[0]);
	      lbi = ip4_fib_forwarding_lookup (vnet_buffer (b[0])->ip.fib_index, &ip0->dst_address);
	      lb = load_balance_get (lbi);

	      if (PREDICT_TRUE (lb->lb_n_buckets == 1))
		dpo = load_balance_get_bucket_i (lb, 0);
	      else
		{
		  u32 hc = ip4_compute_flow_hash (ip0, lb->lb_hash_config);
		  dpo = load_balance_get_fwd_bucket (lb, hc & lb->lb_n_buckets_minus_1);
		}

	      if (dpo->dpoi_type == DPO_ADJACENCY || dpo->dpoi_type == DPO_ADJACENCY_INCOMPLETE ||
		  dpo->dpoi_type == DPO_ADJACENCY_MIDCHAIN)
		{
		  const ip_adjacency_t *adj = adj_get (dpo->dpoi_index);
		  adj_out_sw = adj->rewrite_header.sw_if_index;
		  if (adj_out_sw == expected_dst)
		    {
		      b[0]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
		      skip = 1;
		    }
		}
	    }
	}

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip_ttl_fixup_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->rx_sw_if_index = rx_sw_if_index;
	  t->adj_sw_if_index = adj_out_sw;
	  t->dst_sw_if_index = expected_dst;
	  t->skip = skip;
	}

      vnet_feature_next_u16 (&next[0], b[0]);

      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip4_ttl_fixup_node) = {
  .name = "ip4-ttl-fixup",
  .vector_size = sizeof (u32),
  .format_trace = format_ip4_ttl_fixup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "ip4-drop",
  },
};

VNET_FEATURE_INIT (ip4_ttl_fixup_feat, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ip4-ttl-fixup",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

/* ----------------------------------------------------------------
 * IPv6 feature-arc node
 * ---------------------------------------------------------------- */

static u8 *
format_ip6_ttl_fixup_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip_ttl_fixup_trace_t *t = va_arg (*args, ip_ttl_fixup_trace_t *);

  s = format (s,
	      "ip6-ttl-fixup: rx_sw_if_index %u adj_sw_if_index %u "
	      "expected_dst %u skip %u",
	      t->rx_sw_if_index, t->adj_sw_if_index, t->dst_sw_if_index, t->skip);
  return s;
}

VLIB_NODE_FN (ip6_ttl_fixup_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ip_ttl_fixup_cfg_t *cfg = &ip_ttl_fixup_cfg;
  ip6_main_t *im = &ip6_main;
  u32 n_left, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left);
  b = bufs;
  next = nexts;

  while (n_left > 0)
    {
      u32 rx_sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      u32 expected_dst = ~0;
      u32 adj_out_sw = ~0;
      u8 skip = 0;

      if (PREDICT_TRUE (rx_sw_if_index < vec_len (cfg->dst_by_src)))
	{
	  expected_dst = cfg->dst_by_src[rx_sw_if_index];
	  if (PREDICT_TRUE (expected_dst != (u32) ~0))
	    {
	      /* FIB lookup - mirrors what ip6-lookup does. */
	      ip6_header_t *ip0 = vlib_buffer_get_current (b[0]);
	      u32 lbi;
	      const load_balance_t *lb;
	      const dpo_id_t *dpo;

	      ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, b[0]);
	      lbi =
		ip6_fib_table_fwding_lookup (vnet_buffer (b[0])->ip.fib_index, &ip0->dst_address);
	      lb = load_balance_get (lbi);

	      if (PREDICT_TRUE (lb->lb_n_buckets == 1))
		dpo = load_balance_get_bucket_i (lb, 0);
	      else
		{
		  u32 hc = ip6_compute_flow_hash (ip0, lb->lb_hash_config);
		  dpo = load_balance_get_fwd_bucket (lb, hc & lb->lb_n_buckets_minus_1);
		}

	      if (dpo->dpoi_type == DPO_ADJACENCY || dpo->dpoi_type == DPO_ADJACENCY_INCOMPLETE ||
		  dpo->dpoi_type == DPO_ADJACENCY_MIDCHAIN)
		{
		  const ip_adjacency_t *adj = adj_get (dpo->dpoi_index);
		  adj_out_sw = adj->rewrite_header.sw_if_index;
		  if (adj_out_sw == expected_dst)
		    {
		      b[0]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
		      skip = 1;
		    }
		}
	    }
	}

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip_ttl_fixup_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->rx_sw_if_index = rx_sw_if_index;
	  t->adj_sw_if_index = adj_out_sw;
	  t->dst_sw_if_index = expected_dst;
	  t->skip = skip;
	}

      vnet_feature_next_u16 (&next[0], b[0]);

      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip6_ttl_fixup_node) = {
  .name = "ip6-ttl-fixup",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_ttl_fixup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "ip6-drop",
  },
};

VNET_FEATURE_INIT (ip6_ttl_fixup_feat, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "ip6-ttl-fixup",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};

/* ----------------------------------------------------------------
 * API message handler
 * ---------------------------------------------------------------- */

static void
vl_api_ip_ttl_fixup_configure_t_handler (vl_api_ip_ttl_fixup_configure_t *mp)
{
  ip_ttl_fixup_main_t *ttfm = &ip_ttl_fixup_main;
  vl_api_ip_ttl_fixup_configure_reply_t *rmp;
  int rv;

  rv =
    ip_ttl_fixup_configure (ntohl (mp->src_sw_if_index), ntohl (mp->dst_sw_if_index), mp->enable);

  REPLY_MACRO (VL_API_IP_TTL_FIXUP_CONFIGURE_REPLY);
}

/* ----------------------------------------------------------------
 * CLI
 * ---------------------------------------------------------------- */

static clib_error_t *
ip_ttl_fixup_configure_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  ip_ttl_fixup_main_t *ttfm = &ip_ttl_fixup_main;
  u32 src_sw_if_index = ~0, dst_sw_if_index = ~0;
  int enable = 1;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "enable"))
	enable = 1;
      else if (src_sw_if_index == ~0 && unformat (input, "%U", unformat_vnet_sw_interface,
						  ttfm->vnet_main, &src_sw_if_index))
	;
      else if (dst_sw_if_index == ~0 && unformat (input, "%U", unformat_vnet_sw_interface,
						  ttfm->vnet_main, &dst_sw_if_index))
	;
      else
	break;
    }

  if (src_sw_if_index == ~0 || dst_sw_if_index == ~0)
    return clib_error_return (0, "Please specify source and destination interfaces...");

  rv = ip_ttl_fixup_configure (src_sw_if_index, dst_sw_if_index, enable);

  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (0, "Invalid source interface...");
    case VNET_API_ERROR_INVALID_SW_IF_INDEX_2:
      return clib_error_return (0, "Invalid destination interface...");
    default:
      return clib_error_return (0, "ip_ttl_fixup_configure returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (ip_ttl_fixup_configure_command, static) = {
  .path = "ttl fixup configure",
  .short_help = "ttl fixup configure <src-interface> <dst-interface> [enable|disable]",
  .function = ip_ttl_fixup_configure_command_fn,
};

static clib_error_t *
ip_ttl_fixup_show_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  ip_ttl_fixup_cfg_t *cfg = &ip_ttl_fixup_cfg;
  ip_ttl_fixup_main_t *ttfm = &ip_ttl_fixup_main;
  u32 ii;

  if (!cfg->enabled)
    {
      vlib_cli_output (vm, "TTL fixup: disabled (no pairs configured)");
      return 0;
    }

  vlib_cli_output (vm, "TTL fixup: enabled");
  vlib_cli_output (vm, "  %-30s %-30s", "Source", "Destination");
  vec_foreach_index (ii, cfg->dst_by_src)
    {
      if (cfg->dst_by_src[ii] != (u32) ~0)
	vlib_cli_output (vm, "  %-30U %-30U", format_vnet_sw_if_index_name, ttfm->vnet_main, ii,
			 format_vnet_sw_if_index_name, ttfm->vnet_main, cfg->dst_by_src[ii]);
    }

  return 0;
}

VLIB_CLI_COMMAND (ip_ttl_fixup_show_command, static) = {
  .path = "show ttl fixup",
  .short_help = "show ttl fixup",
  .function = ip_ttl_fixup_show_command_fn,
};

/* ----------------------------------------------------------------
 * Init / API hookup
 * ---------------------------------------------------------------- */

#include <ip_ttl_fixup/ip_ttl_fixup.api.c>

static clib_error_t *
ip_ttl_fixup_api_hookup (vlib_main_t *vm)
{
  ip_ttl_fixup_main_t *ttfm = &ip_ttl_fixup_main;

  ttfm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (ip_ttl_fixup_api_hookup);

static clib_error_t *
ip_ttl_fixup_init (vlib_main_t *vm)
{
  ip_ttl_fixup_main_t *ttfm = &ip_ttl_fixup_main;

  ttfm->vnet_main = vnet_get_main ();

  return 0;
}

VLIB_INIT_FUNCTION (ip_ttl_fixup_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "IP TTL/Hop-limit fixup for transparent host forwarding",
};
