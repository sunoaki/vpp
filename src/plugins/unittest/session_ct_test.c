/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/session/application_local.h>
#include <vnet/session/session.h>

#define CT_TEST_PENDING 16
#define CT_TEST_FRESH CT_TEST_PENDING

typedef struct
{
  u32 replies[CT_TEST_PENDING + 1];
  u32 cleanups[CT_TEST_PENDING + 1];
  u32 refused;
  u32 accepted;
  u32 connected;
  u32 errors;
  session_handle_t client_handle;
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
  options[APP_OPTIONS_FLAGS] |= local ? APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE :
					    APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
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
ct_test_replacement (vlib_main_t *vm, u8 local, u8 same_endpoint, u8 same_app)
{
  ct_listener_test_t *state = &ct_listener_test;
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  vnet_listen_args_t listen_args = { 0 };
  vnet_unlisten_args_t unlisten_args = { .handle = SESSION_INVALID_HANDLE };
  vnet_disconnect_args_t disconnect_args = { 0 };
  u32 apps[3] = { ~0, ~0, ~0 }, server, old_index, sessions, connections;
  u32 attempts, i, initial_sessions = ct_test_session_count ();
  u32 initial_connections = ct_connection_count ();
  u64 old_id;
  session_t *ll;
  app_worker_t *client_wrk;
  clib_error_t *error = 0;

#define CT_CHECK(condition, text)                                             \
  do                                                                          \
    {                                                                         \
      if (!(condition))                                                       \
	{                                                                     \
	  error = clib_error_return (0, "%s (local %u endpoint %u app %u)", text, \
				     local, same_endpoint, same_app);          \
	  goto cleanup;                                                       \
	}                                                                     \
    }                                                                         \
  while (0)

  clib_memset (state, 0, sizeof (*state));
  CT_CHECK (!ct_test_attach ("ct-listener-client", 1, &apps[0]), "attach client");
  /* Global fallback is allowed after the local lookup misses. */
  application_get (apps[0])->flags |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  CT_CHECK (!ct_test_attach ("ct-listener-first", local, &apps[1]), "attach first server");
  CT_CHECK (!ct_test_attach ("ct-listener-second", local, &apps[2]), "attach second server");
  client_wrk = application_get_default_worker (application_get (apps[0]));
  CT_CHECK (!pool_elts (client_wrk->half_open_table), "initial half-open table");

  sep.is_ip4 = 1;
  sep.transport_proto = TRANSPORT_PROTO_TCP;
  sep.port = clib_host_to_net_u16 (23456);
  listen_args.app_index = apps[1];
  listen_args.sep_ext = sep;
  CT_CHECK (!vnet_listen (&listen_args), "listen first server");
  unlisten_args.app_index = apps[1];
  unlisten_args.handle = listen_args.handle;
  old_index = session_index_from_handle (listen_args.handle);
  sessions = ct_test_session_count ();
  connections = ct_connection_count ();
  sep.ip.ip4.as_u32 = clib_host_to_net_u32 (local ? 0x7f000001 : 0xc0000201);

  /* The CLI barrier keeps both deferred CT RPC stages queued until replacement. */
  for (i = 0; i < CT_TEST_PENDING; i++)
    CT_CHECK (!ct_test_connect (apps[0], &sep, i), "queue stale connect");
  ll = listen_session_get (old_index);
  old_id = ll->ct_listener_id;
  CT_CHECK (old_id != 0, "listener identity assigned");
  CT_CHECK (!state->accepted && !state->refused, "accepts remain queued");
  CT_CHECK (!vnet_unlisten (&unlisten_args), "unlisten first server");
  unlisten_args.handle = SESSION_INVALID_HANDLE;
  if (!same_endpoint)
    sep.port = clib_host_to_net_u16 (23457);
  server = apps[same_app ? 1 : 2];
  listen_args.app_index = server;
  listen_args.sep.port = sep.port;
  CT_CHECK (!vnet_listen (&listen_args), "listen replacement");
  unlisten_args.app_index = server;
  unlisten_args.handle = listen_args.handle;
  CT_CHECK (session_index_from_handle (listen_args.handle) == old_index, "same listener pool index");
  CT_CHECK (listen_session_get (old_index)->ct_listener_id == 0, "replacement identity reset");

  /* Give the replacement an identity while stale requests are still queued. */
  CT_CHECK (!ct_test_connect (apps[0], &sep, CT_TEST_FRESH), "queue fresh connect");
  CT_CHECK (listen_session_get (old_index)->ct_listener_id != old_id, "distinct listener identity");
  for (attempts = 0; attempts < 500; attempts++)
    {
      ct_test_dispatch (vm);
      if (state->refused == CT_TEST_PENDING && state->connected == 1 &&
	  !pool_elts (client_wrk->half_open_table))
	break;
    }
  CT_CHECK (state->errors == 0, "no wrong accepts or connect errors");
  CT_CHECK (state->refused == CT_TEST_PENDING, "all stale connects refused");
  CT_CHECK (state->accepted == 1 && state->connected == 1, "only fresh connect accepted");
  for (i = 0; i <= CT_TEST_FRESH; i++)
    {
      CT_CHECK (state->replies[i] == 1, "exactly one reply per connect");
      CT_CHECK (state->cleanups[i] == 1, "exactly one half-open cleanup per connect");
    }

  disconnect_args.app_index = apps[0];
  disconnect_args.handle = state->client_handle;
  CT_CHECK (!vnet_disconnect_session (&disconnect_args), "close fresh connect");
  for (attempts = 0; attempts < 500; attempts++)
    {
      ct_test_dispatch (vm);
      if (ct_test_session_count () == sessions && ct_connection_count () == connections)
	break;
    }
  CT_CHECK (ct_test_session_count () == sessions, "session pool baseline restored");
  CT_CHECK (ct_connection_count () == connections, "CT pool baseline restored");
  CT_CHECK (!pool_elts (client_wrk->half_open_table), "no half-open entries");
  CT_CHECK (!ct_test_fifo_count (client_wrk), "no client FIFOs");
  CT_CHECK (!ct_test_fifo_count (application_get_default_worker (application_get (server))),
	    "no server FIFOs");
  for (i = 0; i <= CT_TEST_FRESH; i++)
    CT_CHECK (state->replies[i] == 1 && state->cleanups[i] == 1, "no duplicate completion");

cleanup:
  if (unlisten_args.handle != SESSION_INVALID_HANDLE)
    vnet_unlisten (&unlisten_args);
  if (apps[0] != (u32) ~0)
    {
      client_wrk = application_get_default_worker (application_get (apps[0]));
      for (attempts = 0; attempts < 500 && pool_elts (client_wrk->half_open_table); attempts++)
	ct_test_dispatch (vm);
    }
  for (i = 0; i < ARRAY_LEN (apps); i++)
    if (apps[i] != (u32) ~0)
      {
	vnet_app_detach_args_t args = { .app_index = apps[i], .api_client_index = ~0 };
	vnet_application_detach (&args);
      }
  for (attempts = 0; attempts < 500; attempts++)
    {
      ct_test_dispatch (vm);
      if (ct_test_session_count () == initial_sessions &&
	  ct_connection_count () == initial_connections)
	break;
    }
  if (ct_test_session_count () != initial_sessions ||
      ct_connection_count () != initial_connections)
    {
      if (error)
	error = clib_error_return (error, "test cleanup did not restore allocation baseline");
      else
	error = clib_error_return (0, "test cleanup did not restore allocation baseline");
    }
#undef CT_CHECK
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
