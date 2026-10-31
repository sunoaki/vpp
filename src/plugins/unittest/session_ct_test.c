/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/session/application_local.h>
#include <vnet/session/session.h>

#define CT_TEST_PENDING 16
#define CT_TEST_FRESH	CT_TEST_PENDING

typedef enum
{
  CT_TEST_CLIENT,
  CT_TEST_FIRST_SERVER,
  CT_TEST_SECOND_SERVER,
  CT_TEST_N_APPS,
} ct_test_app_role_t;

typedef struct
{
  u32 replies[CT_TEST_PENDING + 1];
  u32 cleanups[CT_TEST_PENDING + 1];
  u32 refused;
  u32 accepted;
  u32 connected;
  u32 errors;
  u32 submitted;
  session_handle_t client_handle;
  u32 apps[CT_TEST_N_APPS];
  session_endpoint_cfg_t sep;
  vnet_unlisten_args_t unlisten;
  u32 initial_sessions;
  u32 initial_connections;
  u32 listening_sessions;
  u32 listening_connections;
  u32 old_index;
  u64 old_id;
  u8 occupied;
} ct_listener_test_t;

static ct_listener_test_t ct_listener_test;

static void
ct_test_disconnect (session_t *s)
{
  vnet_disconnect_args_t args = {
    .handle = session_handle (s),
    .app_index = app_worker_get (s->app_wrk_index)->app_index,
  };
  if (vnet_disconnect_session (&args))
    clib_atomic_fetch_add_relax (&ct_listener_test.errors, 1);
}

static int
ct_test_accept (session_t *s)
{
  ct_connection_t *ct = (ct_connection_t *) session_get_transport (s);

  clib_atomic_fetch_add_relax (&ct_listener_test.accepted, 1);
  if (ct->client_opaque != CT_TEST_FRESH)
    {
      clib_atomic_fetch_add_relax (&ct_listener_test.errors, 1);
      return -1;
    }
  return 0;
}

static int
ct_test_connected (u32 app_wrk_index, u32 opaque, session_t *s, session_error_t err)
{
  ct_listener_test_t *state = &ct_listener_test;

  if (opaque > CT_TEST_FRESH)
    {
      clib_atomic_fetch_add_relax (&state->errors, 1);
      return -1;
    }
  clib_atomic_fetch_add_relax (&state->replies[opaque], 1);
  if (opaque < CT_TEST_FRESH && !s && err == SESSION_E_REFUSED)
    clib_atomic_fetch_add_relax (&state->refused, 1);
  else if (opaque == CT_TEST_FRESH && s && !err)
    {
      state->client_handle = session_handle (s);
      clib_atomic_fetch_add_relax (&state->connected, 1);
    }
  else
    clib_atomic_fetch_add_relax (&state->errors, 1);
  return 0;
}

static void
ct_test_half_cleanup (session_t *s)
{
  if (s->opaque <= CT_TEST_FRESH)
    clib_atomic_fetch_add_relax (&ct_listener_test.cleanups[s->opaque], 1);
  else
    clib_atomic_fetch_add_relax (&ct_listener_test.errors, 1);
}

static int
ct_test_segment (u32 app_wrk_index, u64 segment_handle)
{
  return 0;
}

static int
ct_test_rx (session_t *s)
{
  clib_atomic_fetch_add_relax (&ct_listener_test.errors, 1);
  return 0;
}

static session_cb_vft_t ct_test_callbacks = {
  .session_accept_callback = ct_test_accept,
  .session_connected_callback = ct_test_connected,
  .session_disconnect_callback = ct_test_disconnect,
  .session_reset_callback = ct_test_disconnect,
  .half_open_cleanup_callback = ct_test_half_cleanup,
  .add_segment_callback = ct_test_segment,
  .del_segment_callback = ct_test_segment,
  .builtin_app_rx_callback = ct_test_rx,
};

static int
ct_test_attach (char *name, u8 local, u32 *app_index)
{
  u64 options[APP_OPTIONS_N_OPTIONS] = { 0 };
  vnet_app_attach_args_t args = {
    .api_client_index = ~0,
    .options = options,
    .session_cb_vft = &ct_test_callbacks,
    .name = format (0, "%s", name),
  };
  int rv;

  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_FLAGS] |=
    local ? APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE : APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 16 << 20;
  rv = vnet_application_attach (&args);
  vec_free (args.name);
  if (!rv)
    *app_index = args.app_index;
  return rv;
}

static u32
ct_test_session_count (void)
{
  session_worker_t *wrk;
  u32 count = 0;

  vec_foreach (wrk, session_main.wrk)
    count += pool_elts (wrk->sessions);
  return count;
}

static u32
ct_test_fifo_count (app_worker_t *wrk)
{
  segment_manager_t *sm;
  fifo_segment_t *fs;
  hash_pair_t *entry;
  u32 count = 0;

  sm = app_worker_get_connect_segment_manager (wrk);
  pool_foreach (fs, sm->segments)
    count += fifo_segment_num_fifos (fs);
  hash_foreach_pair (entry, wrk->listeners_table, ({
		       sm = segment_manager_get (entry->value[0]);
		       pool_foreach (fs, sm->segments)
			 count += fifo_segment_num_fifos (fs);
		     }));
  return count;
}

static void
ct_test_dispatch (vlib_main_t *vm)
{
  vlib_worker_thread_barrier_release (vm);
  vlib_process_suspend (vm, 10e-3);
  vlib_worker_thread_barrier_sync (vm);
}

static int
ct_test_connect (u32 client, session_endpoint_cfg_t *sep, u32 opaque)
{
  vnet_connect_args_t args = {
    .app_index = client,
    .api_context = opaque,
    .sep_ext = *sep,
  };
  return vnet_connect (&args);
}

static clib_error_t *
ct_test_listen (ct_listener_test_t *state, ct_test_app_role_t server)
{
  vnet_listen_args_t args = { .app_index = state->apps[server], .sep_ext = state->sep };

  args.sep.ip.ip4.as_u32 = 0;
  if (vnet_listen (&args))
    return clib_error_return (0, "listen server");
  state->unlisten.app_index = args.app_index;
  state->unlisten.handle = args.handle;
  return 0;
}

static clib_error_t *
ct_test_setup (ct_listener_test_t *state, u8 local)
{
  clib_error_t *error;

  state->initial_sessions = ct_test_session_count ();
  state->initial_connections = ct_connection_count ();
  if (ct_test_attach ("ct-listener-client", 1, &state->apps[CT_TEST_CLIENT]))
    return clib_error_return (0, "attach client");
  application_get (state->apps[CT_TEST_CLIENT])->flags |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  if (ct_test_attach ("ct-listener-first", local, &state->apps[CT_TEST_FIRST_SERVER]) ||
      ct_test_attach ("ct-listener-second", local, &state->apps[CT_TEST_SECOND_SERVER]))
    return clib_error_return (0, "attach server");
  state->sep = (session_endpoint_cfg_t) SESSION_ENDPOINT_CFG_NULL;
  state->sep.is_ip4 = 1;
  state->sep.transport_proto = TRANSPORT_PROTO_TCP;
  state->sep.port = clib_host_to_net_u16 (23456);
  if ((error = ct_test_listen (state, CT_TEST_FIRST_SERVER)))
    return error;
  state->old_index = session_index_from_handle (state->unlisten.handle);
  state->listening_sessions = ct_test_session_count ();
  state->listening_connections = ct_connection_count ();
  state->sep.ip.ip4.as_u32 = clib_host_to_net_u32 (local ? 0x7f000001 : 0xc0000201);
  return 0;
}

static app_worker_t *
ct_test_app_worker (ct_listener_test_t *state, ct_test_app_role_t role)
{
  return application_get_default_worker (application_get (state->apps[role]));
}

static clib_error_t *
ct_test_queue_stale (ct_listener_test_t *state)
{
  session_t *sessions = session_main.wrk[transport_cl_thread ()].sessions;
  u32 free_sessions = sessions ? pool_free_elts (sessions) : POOL_REALLOC_SAFE_ELT_THRESH;
  u32 i;

  if (pool_elts (ct_test_app_worker (state, CT_TEST_CLIENT)->half_open_table))
    return clib_error_return (0, "initial half-open table");
  /* Keep all 17 requests queued without the synchronous pool-growth barrier. */
  if (free_sessions < CT_TEST_PENDING + 1 || ct_half_open_free_count () < CT_TEST_PENDING + 1)
    return clib_error_return (0, "insufficient half-open capacity for queued burst");
  for (i = 0; i < CT_TEST_PENDING; i++)
    {
      if (ct_test_connect (state->apps[CT_TEST_CLIENT], &state->sep, i))
	return clib_error_return (0, "queue stale connect %u", i);
      state->submitted++;
    }
  state->old_id = listen_session_get (state->old_index)->ct_listener_id;
  if (!state->old_id || state->accepted || state->refused)
    return clib_error_return (0, "listener identity assigned with accepts still queued");
  return 0;
}

static clib_error_t *
ct_test_replace_listener (ct_listener_test_t *state, u8 same_endpoint, u8 same_app)
{
  ct_test_app_role_t server = same_app ? CT_TEST_FIRST_SERVER : CT_TEST_SECOND_SERVER;
  clib_error_t *error;

  if (vnet_unlisten (&state->unlisten))
    return clib_error_return (0, "unlisten first server");
  state->unlisten.handle = SESSION_INVALID_HANDLE;
  if (!same_endpoint)
    state->sep.port = clib_host_to_net_u16 (23457);
  if ((error = ct_test_listen (state, server)))
    return error;
  if (session_index_from_handle (state->unlisten.handle) != state->old_index)
    return clib_error_return (0, "same listener pool index");
  if (listen_session_get (state->old_index)->ct_listener_id)
    return clib_error_return (0, "replacement identity reset");
  if (ct_test_connect (state->apps[CT_TEST_CLIENT], &state->sep, CT_TEST_FRESH))
    return clib_error_return (0, "queue fresh connect");
  state->submitted++;
  if (listen_session_get (state->old_index)->ct_listener_id == state->old_id)
    return clib_error_return (0, "distinct listener identity");
  return 0;
}

static u8
ct_test_requests_complete (ct_listener_test_t *state)
{
  u32 i;

  if (state->apps[CT_TEST_CLIENT] == (u32) ~0)
    return 1;
  /* HALF_CLEANUP removes the entry after the RPC and callback complete. */
  if (pool_elts (ct_test_app_worker (state, CT_TEST_CLIENT)->half_open_table))
    return 0;
  /* A connected event can run after the half-open cleanup on another worker. */
  for (i = 0; i < state->submitted; i++)
    if (!state->replies[i])
      return 0;
  return 1;
}

static clib_error_t *
ct_test_wait_requests (vlib_main_t *vm, ct_listener_test_t *state)
{
  u32 attempts;

  for (attempts = 0; attempts < 500; attempts++)
    {
      if (ct_test_requests_complete (state))
	return 0;
      ct_test_dispatch (vm);
    }
  if (!ct_test_requests_complete (state))
    return clib_error_return (0, "half-open cleanup or connect reply did not complete");
  return 0;
}

static clib_error_t *
ct_test_verify_completions (ct_listener_test_t *state)
{
  u32 i;

  if (state->errors)
    return clib_error_return (0, "wrong accepts or connect errors");
  if (state->refused != CT_TEST_PENDING)
    return clib_error_return (0, "all stale connects refused");
  if (state->accepted != 1 || state->connected != 1)
    return clib_error_return (0, "only fresh connect accepted");
  for (i = 0; i <= CT_TEST_FRESH; i++)
    if (state->replies[i] != 1 || state->cleanups[i] != 1)
      return clib_error_return (0, "exactly one reply and half-open cleanup for connect %u", i);
  return 0;
}

static clib_error_t *
ct_test_close_client (ct_listener_test_t *state)
{
  vnet_disconnect_args_t args = {
    .app_index = state->apps[CT_TEST_CLIENT],
    .handle = state->client_handle,
  };

  if (args.handle == SESSION_INVALID_HANDLE)
    return 0;
  if (vnet_disconnect_session (&args))
    return clib_error_return (0, "close fresh connect");
  state->client_handle = SESSION_INVALID_HANDLE;
  return 0;
}

static clib_error_t *
ct_test_wait_baseline (vlib_main_t *vm, u32 sessions, u32 connections)
{
  u32 attempts;

  for (attempts = 0; attempts < 500; attempts++)
    {
      if (ct_test_session_count () == sessions && ct_connection_count () == connections)
	return 0;
      ct_test_dispatch (vm);
    }
  if (ct_test_session_count () != sessions || ct_connection_count () != connections)
    return clib_error_return (0, "allocation baseline not restored");
  return 0;
}

static clib_error_t *
ct_test_verify_fifos (ct_listener_test_t *state)
{
  u32 role;

  for (role = 0; role < CT_TEST_N_APPS; role++)
    if (state->apps[role] != (u32) ~0 && ct_test_fifo_count (ct_test_app_worker (state, role)))
      return clib_error_return (0, "application %u still owns FIFOs", role);
  return 0;
}

static clib_error_t *
ct_test_cleanup (vlib_main_t *vm, ct_listener_test_t *state)
{
  clib_error_t *error;
  u32 role;

  if ((error = ct_test_wait_requests (vm, state)) || (error = ct_test_close_client (state)))
    return error;
  if (state->unlisten.handle != SESSION_INVALID_HANDLE)
    {
      if (vnet_unlisten (&state->unlisten))
	return clib_error_return (0, "cleanup listener");
      state->unlisten.handle = SESSION_INVALID_HANDLE;
    }
  if ((error = ct_test_wait_baseline (vm, state->initial_sessions, state->initial_connections)) ||
      (error = ct_test_verify_fifos (state)))
    return error;
  for (role = 0; role < CT_TEST_N_APPS; role++)
    if (state->apps[role] != (u32) ~0)
      {
	vnet_app_detach_args_t args = { .app_index = state->apps[role], .api_client_index = ~0 };
	if (vnet_application_detach (&args))
	  return clib_error_return (0, "detach application %u", role);
	state->apps[role] = ~0;
      }
  if ((error = ct_test_wait_baseline (vm, state->initial_sessions, state->initial_connections)))
    return error;
  state->occupied = 0;
  return 0;
}

static clib_error_t *
ct_test_run (vlib_main_t *vm, ct_listener_test_t *state, u8 same_endpoint, u8 same_app)
{
  clib_error_t *error;

  if ((error = ct_test_queue_stale (state)) ||
      (error = ct_test_replace_listener (state, same_endpoint, same_app)) ||
      (error = ct_test_wait_requests (vm, state)) || (error = ct_test_verify_completions (state)) ||
      (error = ct_test_close_client (state)) ||
      (error =
	 ct_test_wait_baseline (vm, state->listening_sessions, state->listening_connections)) ||
      (error = ct_test_verify_fifos (state)))
    return error;
  return ct_test_verify_completions (state);
}

static clib_error_t *
ct_test_replacement (vlib_main_t *vm, u8 local, u8 same_endpoint, u8 same_app)
{
  ct_listener_test_t *state = &ct_listener_test;
  clib_error_t *error, *cleanup_error;
  u32 role;

  if (state->occupied)
    return clib_error_return (0, "CT fixture retained or running; use a fresh VPP process");
  clib_memset (state, 0, sizeof (*state));
  state->occupied = 1;
  state->client_handle = SESSION_INVALID_HANDLE;
  state->unlisten.handle = SESSION_INVALID_HANDLE;
  for (role = 0; role < CT_TEST_N_APPS; role++)
    state->apps[role] = ~0;
  error = ct_test_setup (state, local);
  if (!error)
    error = ct_test_run (vm, state, same_endpoint, same_app);
  cleanup_error = ct_test_cleanup (vm, state);
  if (cleanup_error)
    {
      error = clib_error_return (error, "%U; fixture retained until VPP process exit",
				 format_clib_error, cleanup_error);
      clib_error_free (cleanup_error);
    }
  if (error)
    error =
      clib_error_return (error, "local %u endpoint %u app %u", local, same_endpoint, same_app);
  return error;
}

static clib_error_t *
ct_listener_test_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_error_t *error;
  u8 local, same_endpoint, same_app;

  if (!session_main.is_enabled)
    return clib_error_return (0, "enable sessions before running CT listener test");
  for (local = 0; local < 2; local++)
    for (same_endpoint = 0; same_endpoint < 2; same_endpoint++)
      for (same_app = 0; same_app < 2; same_app++)
	if ((error = ct_test_replacement (vm, local, same_endpoint, same_app)))
	  return error;
  vlib_cli_output (vm, "CT listener identity SUCCESS");
  return 0;
}

VLIB_CLI_COMMAND (ct_listener_test_command, static) = {
  .path = "test session ct-listener",
  .short_help = "test session ct-listener",
  .function = ct_listener_test_command_fn,
};
