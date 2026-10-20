/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2022 Cisco and/or its affiliates.
 */

#include <http_static/http_static.h>
#include <vnet/session/application.h>
#if CLIB_DEBUG > 0
#include <vnet/udp/udp.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <http/http_content_types.h>
#include <http/http_status_codes.h>

/** @file static_server.c
 *  Static http server, sufficient to serve .html / .css / .js content.
 */
/*? %%clicmd:group_label Static HTTP Server %% ?*/

#define HSS_FIFO_THRESH (16 << 10)
#define HSS_HEADER_BUF_MAX_SIZE 16192
hss_main_t hss_main;

static int file_handler_discard_body (hss_session_t *hs, session_t *ts);
static int url_handler_read_body (hss_session_t *hs, session_t *ts);

#if CLIB_DEBUG > 0
#define HSS_ASYNC_RECORDS 8
#define HSS_ASYNC_LISTENERS 32

typedef struct
{
  u64 epoch;
  u64 final_seq;
  u64 free_seq;
  u32 index;
  u32 generation;
  u32 app_index;
  u32 releases;
  u32 cache_frees;
  u32 vec_frees;
  u32 pool_puts;
  u32 recoveries;
} hss_async_listener_t;

typedef struct
{
  u64 handle;
  u64 enter_seq;
  u64 async_seq;
  u64 send_seq;
  u64 cancel_seq;
  u64 cleanup_seq;
  u32 token;
  u32 listener;
  u32 thread;
  u32 hs_index;
  u32 app_index;
  u32 app_worker;
  u32 armed;
  u32 active;
  u32 pending;
  u32 sends;
  u32 cancels;
  u32 cleanups;
  u32 duplicates;
  u32 late;
  u32 tx_before;
  u32 omitted;
  u8 *response;
} hss_async_record_t;

static struct
{
  hss_async_record_t records[HSS_ASYNC_RECORDS];
  hss_async_listener_t listeners[HSS_ASYNC_LISTENERS];
  u64 sequence;
  u64 epoch;
  u32 enabled;
  u32 overflow;
  u32 listener_count;
  u32 baseline;
} hss_async_test;

static u64
hss_async_sequence (void)
{
  return clib_atomic_add_fetch (&hss_async_test.sequence, 1);
}

static hss_async_listener_t *
hss_async_listener (u32 index)
{
  u32 i;

  if (!hss_async_test.enabled)
    return 0;
  for (i = hss_async_test.listener_count; i > 0; i--)
    if (hss_async_test.listeners[i - 1].index == index &&
        !hss_async_test.listeners[i - 1].pool_puts)
      return &hss_async_test.listeners[i - 1];
  return 0;
}

static void
hss_async_listener_added (u32 index)
{
  hss_async_listener_t *entry;

  if (!hss_async_test.enabled)
    return;
  if (hss_async_test.listener_count == HSS_ASYNC_LISTENERS)
    {
      hss_async_test.overflow = 1;
      return;
    }
  entry = &hss_async_test.listeners[hss_async_test.listener_count++];
  entry->index = index;
  entry->epoch = ++hss_async_test.epoch;
  entry->generation = hss_main.app_generation - 1;
  entry->app_index = hss_main.app_index;
}

static hss_async_record_t *
hss_async_owned_record (hss_session_t *hs)
{
  hss_async_record_t *record;
  hss_async_listener_t *entry = hss_async_listener (hs->listener_index);
  u32 i;

  if (!entry)
    return 0;
  for (i = 0; i < HSS_ASYNC_RECORDS; i++)
    {
      record = &hss_async_test.records[i];
      if (record->enter_seq && !record->cleanups &&
          record->listener == entry - hss_async_test.listeners &&
          record->thread == hs->thread_index && record->hs_index == hs->session_index &&
          record->handle == hs->vpp_session_handle && record->app_index == hs->app_index)
        return record;
    }
  return 0;
}

static u32
hss_async_cleanup_begin (hss_session_t *hs)
{
  hss_async_record_t *record = hss_async_owned_record (hs);

  if (!record)
    return ~0;
  if (record->active)
    {
      record->active = 0;
      record->cancels++;
      record->cancel_seq = hss_async_sequence ();
      vec_free (record->response);
    }
  return record - hss_async_test.records;
}

static void
hss_async_cleanup_done (u32 index)
{
  if (index == (u32) ~0)
    return;
  hss_async_test.records[index].cleanups++;
  hss_async_test.records[index].cleanup_seq = hss_async_sequence ();
}

static hss_url_handler_rc_t hss_async_handler (hss_url_handler_args_t *args);
#endif

static void
hss_listener_free_rpc (void *arg)
{
  u32 l_index = *(u32 *) arg;
  hss_listener_t *l = hss_listener_get (l_index);

  ASSERT (vlib_thread_is_main_w_barrier ());
  ASSERT (l && l->retiring && l->ref_count == 0);
#if CLIB_DEBUG > 0
  hss_async_listener_t *entry = hss_async_listener (l_index);
#endif
  if (l->cache)
    {
      hss_cache_free (l->cache);
      clib_mem_free (l->cache);
#if CLIB_DEBUG > 0
      if (entry)
        entry->cache_frees++;
#endif
    }
  vec_free (l->www_root);
  vec_free (l->max_age_formatted);
#if CLIB_DEBUG > 0
  if (entry)
    entry->vec_frees++;
#endif
  pool_put (hss_main.listeners, l);
#if CLIB_DEBUG > 0
  if (entry)
    {
      entry->pool_puts++;
      entry->free_seq = hss_async_sequence ();
    }
#endif
}

static void
hss_listener_release (u32 l_index)
{
  hss_listener_t *l = hss_listener_get (l_index);

  u32 remaining = clib_atomic_sub_fetch (&l->ref_count, 1);
#if CLIB_DEBUG > 0
  hss_async_listener_t *entry = hss_async_listener (l_index);
  if (entry)
    {
      clib_atomic_add_fetch (&entry->releases, 1);
      if (!remaining)
        entry->final_seq = hss_async_sequence ();
    }
#endif
  if (remaining == 0)
    vlib_rpc_call_main_thread (hss_listener_free_rpc, (u8 *) &l_index, sizeof (l_index));
}

static int
hss_add_header (hss_session_t *hs, http_header_name_t name, const char *value,
		uword value_len)
{
  u32 needed_size = 0;
  while (http_add_header (&hs->resp_headers, name, value, value_len) == -1)
    {
      if (needed_size)
	{
	  http_truncate_headers_list (&hs->resp_headers);
	  hs->data_len = 0;
	  return -1;
	}
      else
	needed_size = hs->resp_headers.tail_offset +
		      sizeof (http_app_header_t) + value_len;
      if (needed_size < HSS_HEADER_BUF_MAX_SIZE)
	{
	  vec_resize (hs->headers_buf, sizeof (http_app_header_t) + value_len);
	  hs->resp_headers.len = needed_size;
	  hs->resp_headers.buf = hs->headers_buf;
	}
      else
	{
	  http_truncate_headers_list (&hs->resp_headers);
	  hs->data_len = 0;
	  return -1;
	}
    }
  return 0;
}

static_always_inline void
hss_confirm_data_read (hss_session_t *hs, u32 n_last_deq)
{
  session_t *ts;

  ts = session_get (hs->vpp_session_index, hs->thread_index);
  if (svm_fifo_needs_deq_ntf (ts->rx_fifo, n_last_deq))
    {
      svm_fifo_clear_deq_ntf (ts->rx_fifo);
      session_program_transport_io_evt (ts->handle, SESSION_IO_EVT_RX);
    }
}

static hss_session_t *
hss_session_alloc (clib_thread_index_t thread_index)
{
  hss_main_t *hsm = &hss_main;
  hss_session_t *hs;

  pool_get_zero (hsm->sessions[thread_index], hs);
  hs->session_index = hs - hsm->sessions[thread_index];
  hs->thread_index = thread_index;
  hs->cache_pool_index = ~0;
  /* 1kB for headers should be enough for now */
  vec_validate (hs->headers_buf, 1023);
  return hs;
}

__clib_export hss_session_t *
hss_session_get (clib_thread_index_t thread_index, u32 hs_index)
{
  hss_main_t *hsm = &hss_main;
  if (hs_index == (u32) ~0 || pool_is_free_index (hsm->sessions[thread_index], hs_index))
    return 0;
  return pool_elt_at_index (hsm->sessions[thread_index], hs_index);
}

static void
hss_session_free (hss_session_t *hs)
{
  hss_main_t *hsm = &hss_main;

  if (CLIB_DEBUG)
    {
      u32 save_thread_index;
      save_thread_index = hs->thread_index;
      /* Poison the entry, preserve timer state and thread index */
      memset (hs, 0xfa, sizeof (*hs));
      hs->thread_index = save_thread_index;
    }

  pool_put (hsm->sessions[hs->thread_index], hs);
}

/** \brief Disconnect a session
 */
static void
hss_session_disconnect_transport (hss_session_t *hs)
{
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  a->handle = hs->vpp_session_handle;
  a->app_index = hs->app_index;
  vnet_disconnect_session (a);
}

static void
start_send_data (hss_session_t *hs, http_status_code_t status)
{
  hss_main_t *hsm = &hss_main;
  http_msg_t msg;
  session_t *ts;
  u32 n_enq;
  u64 to_send;
  int rv;

  ts = session_get (hs->vpp_session_index, hs->thread_index);

  if (hsm->debug_level > 0)
    clib_warning ("status code: %U", format_http_status_code, status);

  msg.type = HTTP_MSG_REPLY;
  msg.code = status;
  msg.data.body_len = hs->data_len;
  msg.data.headers_offset = 0;
  msg.data.headers_len = hs->resp_headers.tail_offset;
  msg.data.len = msg.data.body_len + msg.data.headers_len;

  if (msg.data.len > hs->use_ptr_thresh)
    {
      msg.data.type = HTTP_MSG_DATA_PTR;
      rv = svm_fifo_enqueue (ts->tx_fifo, sizeof (msg), (u8 *) &msg);
      ASSERT (rv == sizeof (msg));

      if (msg.data.headers_len)
	{
	  uword headers = pointer_to_uword (hs->headers_buf);
	  rv =
	    svm_fifo_enqueue (ts->tx_fifo, sizeof (headers), (u8 *) &headers);
	  ASSERT (rv == sizeof (headers));
	}

      if (!msg.data.body_len)
	goto done;

      uword data = pointer_to_uword (hs->data);
      rv = svm_fifo_enqueue (ts->tx_fifo, sizeof (data), (u8 *) &data);
      ASSERT (rv == sizeof (data));

      goto done;
    }

  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.body_offset = msg.data.headers_len;

  rv = svm_fifo_enqueue (ts->tx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  if (msg.data.headers_len)
    {
      rv =
	svm_fifo_enqueue (ts->tx_fifo, msg.data.headers_len, hs->headers_buf);
      ASSERT (rv == msg.data.headers_len);
    }

  if (!msg.data.body_len)
    goto done;

  to_send = hs->data_len;
  n_enq = clib_min (svm_fifo_size (ts->tx_fifo), to_send);

  rv = svm_fifo_enqueue (ts->tx_fifo, n_enq, hs->data);

  if (rv < to_send)
    {
      hs->data_offset = (rv > 0) ? rv : 0;
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
    }

done:

  if (svm_fifo_set_event (ts->tx_fifo))
    session_program_tx_io_evt (ts->handle, SESSION_IO_EVT_TX);
}

__clib_export void
hss_session_send_data (hss_url_handler_args_t *args)
{
  hss_session_t *hs;

  hs = hss_session_get (args->sh.thread_index, args->sh.session_index);
  if (!hs)
    return;

  if (hs->data && hs->free_data)
    vec_free (hs->data);

  hs->data = args->data;
  hs->data_len = args->data_len;
  hs->free_data = args->free_vec_data;

  /* Set content type only if we have some response data */
  if (hs->data_len)
    if (hss_add_header (hs, HTTP_HEADER_CONTENT_TYPE,
			http_content_type_token (args->ct)))
      args->sc = HTTP_STATUS_INTERNAL_ERROR;

  start_send_data (hs, args->sc);
#if CLIB_DEBUG > 0
  hss_async_record_t *record = hss_async_owned_record (hs);
  if (record)
    {
      record->sends++;
      record->send_seq = hss_async_sequence ();
    }
#endif
}

/*
 * path_has_known_suffix()
 * Returns 1 if the request ends with a known suffix, like .htm or .ico
 * Used to avoid looking for "/favicon.ico/index.html" or similar.
 */

static int
path_has_known_suffix (u8 *request)
{
  u8 *ext;
  uword *p;

  if (vec_len (request) == 0)
    {
      return 0;
    }

  ext = request + vec_len (request) - 1;

  while (ext > request && ext[0] != '.')
    ext--;

  if (ext == request)
    return 0;

  p = hash_get_mem (hss_main.mime_type_indices_by_file_extensions, ext);
  if (p)
    return 1;

  return 0;
}

/*
 * content_type_from_request
 * Returns the index of the request's suffix in the
 * http-layer http_content_type_str[] array.
 */

static http_content_type_t
content_type_from_request (u8 *request)
{
  u8 *ext;
  uword *p;
  /* default to text/html */
  http_content_type_t rv = HTTP_CONTENT_TEXT_HTML;

  ASSERT (vec_len (request) > 0);

  ext = request + vec_len (request) - 1;

  while (ext > request && ext[0] != '.')
    ext--;

  if (ext == request)
    return rv;

  p = hash_get_mem (hss_main.mime_type_indices_by_file_extensions, ext);

  if (p == 0)
    return rv;

  rv = p[0];
  return rv;
}

static int
try_url_handler (hss_session_t *hs)
{
  hss_main_t *hsm = &hss_main;
  http_status_code_t sc = HTTP_STATUS_OK;
  hss_url_handler_args_t args = {};
  uword *p, *url_table;
  session_t *ts;
  u32 max_deq;
  u8 *target_path;
  int rv;

  target_path = hs->target_path;

  if (!target_path)
    return -1;

  /* zero-length? try "index.html" */
  if (vec_len (target_path) == 0)
    {
      target_path = format (target_path, "index.html");
    }

  /* Look for built-in GET / POST handlers */
  url_table =
    (hs->rt == HTTP_REQ_GET) ? hsm->get_url_handlers : hsm->post_url_handlers;

  p = hash_get_mem (url_table, target_path);
  if (!p)
    return -1;

  hs->rx_buff = 0;

  /* Read request body */
  if (hs->left_recv)
    {
      hss_listener_t *l = hss_listener_get (hs->listener_index);
      if (hs->left_recv > l->rx_buff_thresh)
	{
	  /* TODO: large body (not buffered in memory) */
	  clib_warning ("data length %u above threshold %u", hs->left_recv,
			l->rx_buff_thresh);
	  hs->left_recv = 0;
	  start_send_data (hs, HTTP_STATUS_INTERNAL_ERROR);
	  hss_session_disconnect_transport (hs);
	  return 0;
	}
      hs->rx_buff_offset = 0;
      vec_validate (hs->rx_buff, hs->left_recv - 1);
      ts = session_get (hs->vpp_session_index, hs->thread_index);
      max_deq = svm_fifo_max_dequeue (ts->rx_fifo);
      if (max_deq < hs->left_recv)
	{
	  hs->read_body_handler = url_handler_read_body;
	  if (max_deq == 0)
	    return 0;
	  rv = svm_fifo_dequeue (ts->rx_fifo, max_deq, hs->rx_buff);
	  ASSERT (rv == max_deq);
	  hs->rx_buff_offset = max_deq;
	  hs->left_recv -= max_deq;
	  hss_confirm_data_read (hs, max_deq);
	  return 0;
	}
      rv = svm_fifo_dequeue (ts->rx_fifo, hs->left_recv,
			     hs->rx_buff + hs->rx_buff_offset);
      ASSERT (rv == hs->left_recv);
      hss_confirm_data_read (hs, hs->left_recv);
      hs->left_recv = 0;
    }

  hs->path = 0;
  hs->data_offset = 0;
  hs->cache_pool_index = ~0;

  if (hsm->debug_level > 0)
    clib_warning ("%s '%s'", (hs->rt == HTTP_REQ_GET) ? "GET" : "POST",
		  target_path);

  args.req_type = hs->rt;
  args.query = hs->target_query;
  args.req_data = hs->rx_buff;
  args.sh.thread_index = hs->thread_index;
  args.sh.session_index = hs->session_index;

  rv = ((hss_url_handler_fn) p[0]) (&args);

  vec_free (hs->rx_buff);

  /* Wait for data from handler */
  if (rv == HSS_URL_HANDLER_ASYNC)
    {
#if CLIB_DEBUG > 0
      hss_async_record_t *record = hss_async_owned_record (hs);
      if (record)
        record->async_seq = hss_async_sequence ();
#endif
      return 0;
    }

  if (rv == HSS_URL_HANDLER_ERROR)
    {
      clib_warning ("builtin handler %llx hit on %s '%s' but failed!", p[0],
		    (hs->rt == HTTP_REQ_GET) ? "GET" : "POST", target_path);
      sc = HTTP_STATUS_BAD_GATEWAY;
    }

  hs->data = args.data;
  hs->data_len = args.data_len;
  hs->free_data = args.free_vec_data;

  /* Set content type only if we have some response data */
  if (hs->data_len)
    if (hss_add_header (hs, HTTP_HEADER_CONTENT_TYPE,
			http_content_type_token (args.ct)))
      sc = HTTP_STATUS_INTERNAL_ERROR;

  start_send_data (hs, sc);

  if (!hs->data_len)
    hss_session_disconnect_transport (hs);

  return 0;
}

static u8
file_path_is_valid (u8 *path)
{
  struct stat _sb, *sb = &_sb;

  if (stat ((char *) path, sb) < 0 /* can't stat the file */
      || (sb->st_mode & S_IFMT) != S_IFREG /* not a regular file */)
    return 0;

  return 1;
}

static u32
try_index_file (hss_listener_t *l, hss_session_t *hs, u8 *path)
{
  hss_main_t *hsm = &hss_main;
  u8 *redirect;
  u32 plen;

  /* Remove the trailing space */
  vec_dec_len (path, 1);
  plen = vec_len (path);

  /* Append "index.html" */
  if (path[plen - 1] != '/')
    path = format (path, "/index.html%c", 0);
  else
    path = format (path, "index.html%c", 0);

  if (hsm->debug_level > 0)
    clib_warning ("trying to find index: %s", path);

  if (!file_path_is_valid (path))
    return HTTP_STATUS_NOT_FOUND;

  /*
   * We found an index.html file, build a redirect
   */
  vec_delete (path, vec_len (l->www_root) - 1, 0);

  redirect = format (0, "http%s://%v%s", l->flags & HSS_LISTENER_F_NEED_CRYPTO ? "s" : "",
		     hs->authority, path);

  if (hsm->debug_level > 0)
    clib_warning ("redirect: %v", redirect);

  if (hss_add_header (hs, HTTP_HEADER_LOCATION, (const char *) redirect,
		      vec_len (redirect)))
    return HTTP_STATUS_INTERNAL_ERROR;

  vec_free (redirect);
  hs->data_len = 0;
  hs->free_data = 1;

  return HTTP_STATUS_MOVED;
}

static int
try_file_handler (hss_session_t *hs)
{
  hss_main_t *hsm = &hss_main;
  http_status_code_t sc = HTTP_STATUS_OK;
  u8 *path, *sanitized_path;
  u32 ce_index, max_dequeue;
  http_content_type_t type;
  u8 *last_modified;
  hss_listener_t *l;
  session_t *ts;

  l = hss_listener_get (hs->listener_index);

  /* Feature not enabled */
  if (!l->www_root)
    return -1;

  /* Discard request body */
  if (hs->left_recv)
    {
      ts = session_get (hs->vpp_session_index, hs->thread_index);
      max_dequeue = svm_fifo_max_dequeue (ts->rx_fifo);
      if (max_dequeue < hs->left_recv)
	{
	  svm_fifo_dequeue_drop (ts->rx_fifo, max_dequeue);
	  hs->left_recv -= max_dequeue;
	  hs->read_body_handler = file_handler_discard_body;
	  hss_confirm_data_read (hs, max_dequeue);
	  return 0;
	}
      svm_fifo_dequeue_drop (ts->rx_fifo, hs->left_recv);
      hss_confirm_data_read (hs, hs->left_recv);
      hs->left_recv = 0;
    }

  /* http_path_sanitize() works on vectors and does not guarantee a
     NULL terminated result, but sanitized_path is used as a C-string
     below in content_type_from_request(), so terminate it here. */
  sanitized_path = http_path_sanitize (hs->target_path);
  if (sanitized_path)
    vec_terminate_c_string (sanitized_path);

  /*
   * Construct the file to open
   */
  if (!sanitized_path)
    path = format (0, "%s%c", l->www_root, 0);
  else
    path = format (0, "%s/%s%c", l->www_root, sanitized_path, 0);

  if (hsm->debug_level > 0)
    clib_warning ("%s '%s'", (hs->rt == HTTP_REQ_GET) ? "GET" : "POST", path);

  if (hs->data && hs->free_data)
    vec_free (hs->data);

  hs->data_offset = 0;

  ce_index = hss_cache_lookup_and_attach (l->cache, path, &hs->data, &hs->data_len, &last_modified);
  if (ce_index == ~0)
    {
      if (!file_path_is_valid (path))
	{
	  /*
	   * Generate error 404 right now if we can't find a path with
	   * a known file extension. It's silly to look for
	   * "favicon.ico/index.html" if you can't find
	   * "favicon.ico"; realistic example which used to happen.
	   */
	  if (path_has_known_suffix (path))
	    {
	      sc = HTTP_STATUS_NOT_FOUND;
	      goto done;
	    }
	  sc = try_index_file (l, hs, path);
	  goto done;
	}
      ce_index =
	hss_cache_add_and_attach (l->cache, path, &hs->data, &hs->data_len, &last_modified);
      if (ce_index == ~0)
	{
	  sc = HTTP_STATUS_INTERNAL_ERROR;
	  goto done;
	}
    }

  hs->path = path;
  hs->cache_pool_index = ce_index;

  /* Set following headers only for happy path:
   * Content-Type
   * Cache-Control max-age
   * Last-Modified
   */
  type = content_type_from_request (sanitized_path);
  if (hss_add_header (hs, HTTP_HEADER_CONTENT_TYPE,
		      http_content_type_token (type)) ||
      hss_add_header (hs, HTTP_HEADER_CACHE_CONTROL,
		      (const char *) l->max_age_formatted,
		      vec_len (l->max_age_formatted)) ||
      hss_add_header (hs, HTTP_HEADER_LAST_MODIFIED,
		      (const char *) last_modified, vec_len (last_modified)))
    {
      sc = HTTP_STATUS_INTERNAL_ERROR;
    }

done:
  vec_free (sanitized_path);
  start_send_data (hs, sc);
  if (!hs->data_len)
    hss_session_disconnect_transport (hs);

  return 0;
}

static void
handle_request (hss_session_t *hs)
{
  hss_listener_t *l;

  l = hss_listener_get (hs->listener_index);

  if (hs->left_recv > l->max_req_body_size)
    {
      start_send_data (hs, HTTP_STATUS_CONTENT_TOO_LARGE);
      hss_session_disconnect_transport (hs);
      return;
    }

  if (l->enable_url_handlers && !try_url_handler (hs))
    return;

  if (!try_file_handler (hs))
    return;

  /* Handler did not find anything return 404 */
  start_send_data (hs, HTTP_STATUS_NOT_FOUND);
  hss_session_disconnect_transport (hs);
}

static int
file_handler_discard_body (hss_session_t *hs, session_t *ts)
{
  u32 max_dequeue, to_discard;

  max_dequeue = svm_fifo_max_dequeue (ts->rx_fifo);
  to_discard = clib_min (max_dequeue, hs->left_recv);
  svm_fifo_dequeue_drop (ts->rx_fifo, to_discard);
  hs->left_recv -= to_discard;
  hss_confirm_data_read (hs, to_discard);
  if (hs->left_recv == 0)
    return try_file_handler (hs);
  return 0;
}

static int
url_handler_read_body (hss_session_t *hs, session_t *ts)
{
  u32 max_dequeue, to_read;
  int rv;

  max_dequeue = svm_fifo_max_dequeue (ts->rx_fifo);
  to_read = clib_min (max_dequeue, hs->left_recv);
  rv =
    svm_fifo_dequeue (ts->rx_fifo, to_read, hs->rx_buff + hs->rx_buff_offset);
  ASSERT (rv == to_read);
  hs->rx_buff_offset += to_read;
  hs->left_recv -= to_read;
  hss_confirm_data_read (hs, to_read);
  if (hs->left_recv == 0)
    return try_url_handler (hs);
  return 0;
}

static int
hss_ts_rx_callback (session_t *ts)
{
  hss_session_t *hs;
  http_msg_t msg;
  int rv;

  hs = hss_session_get (ts->thread_index, ts->opaque);
  if (!hs)
    return 0;
  if (hs->left_recv != 0)
    {
      ASSERT (hs->read_body_handler);
      return hs->read_body_handler (hs, ts);
    }

  if (hs->cache_pool_index != ~0)
    {
      hss_cache_detach_entry (hss_listener_get (hs->listener_index)->cache, hs->cache_pool_index);
      hs->cache_pool_index = ~0;
    }
  if (hs->free_data)
    vec_free (hs->data);
  hs->free_data = 0;
  vec_free (hs->path);
  hs->data = 0;
  hs->data_len = 0;
  vec_free (hs->target_path);
  vec_free (hs->target_query);
  vec_free (hs->authority);
  http_init_headers_ctx (&hs->resp_headers, hs->headers_buf,
			 vec_len (hs->headers_buf));

  /* Read the http message header */
  rv = svm_fifo_dequeue (ts->rx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  if (msg.type != HTTP_MSG_REQUEST ||
      (msg.method_type != HTTP_REQ_GET && msg.method_type != HTTP_REQ_POST))
    {
      if (hss_add_header (hs, HTTP_HEADER_ALLOW, http_token_lit ("GET, POST")))
	start_send_data (hs, HTTP_STATUS_INTERNAL_ERROR);
      else
	start_send_data (hs, HTTP_STATUS_METHOD_NOT_ALLOWED);
      goto err_done;
    }

  hs->rt = msg.method_type;

  /* Read authority */
  if (msg.data.target_authority_len)
    {
      vec_validate (hs->authority, msg.data.target_authority_len - 1);
      rv = svm_fifo_peek (ts->rx_fifo, msg.data.target_authority_offset,
			  msg.data.target_authority_len, hs->authority);
      ASSERT (rv == msg.data.target_authority_len);
    }
  else
    {
      /* Mandatory Host header was missing in HTTP/1.1 request */
      start_send_data (hs, HTTP_STATUS_BAD_REQUEST);
      vec_add1 (hs->authority, 0);
      goto err_done;
    }
  /* Read target path */
  if (msg.data.target_path_len)
    {
      vec_validate (hs->target_path, msg.data.target_path_len - 1);
      rv = svm_fifo_peek (ts->rx_fifo, msg.data.target_path_offset,
			  msg.data.target_path_len, hs->target_path);
      ASSERT (rv == msg.data.target_path_len);
      if (http_validate_abs_path_syntax (hs->target_path, 0))
	{
	  start_send_data (hs, HTTP_STATUS_BAD_REQUEST);
	  goto err_done;
	}
      /* Target path must be a proper C-string in addition to a vector */
      vec_add1 (hs->target_path, 0);
    }

  /* Read target query */
  if (msg.data.target_query_len)
    {
      vec_validate (hs->target_query, msg.data.target_query_len - 1);
      rv = svm_fifo_peek (ts->rx_fifo, msg.data.target_query_offset,
			  msg.data.target_query_len, hs->target_query);
      ASSERT (rv == msg.data.target_query_len);
      if (http_validate_query_syntax (hs->target_query, 0))
	{
	  start_send_data (hs, HTTP_STATUS_BAD_REQUEST);
	  goto err_done;
	}
    }

  if (msg.data.body_len && msg.method_type == HTTP_REQ_POST)
    {
      hs->left_recv = msg.data.body_len;
      /* drop everything up to body */
      svm_fifo_dequeue_drop (ts->rx_fifo, msg.data.body_offset);
    }

  /* Find and send data */
  handle_request (hs);
  goto done;

err_done:
  hss_session_disconnect_transport (hs);
done:
  svm_fifo_dequeue_drop (ts->rx_fifo, msg.data.len);
  return 0;
}

static int
hss_ts_tx_callback (session_t *ts)
{
  hss_session_t *hs;
  u32 n_enq;
  u64 to_send;
  int rv;

  hs = hss_session_get (ts->thread_index, ts->opaque);
  if (!hs || !hs->data)
    return 0;

  to_send = hs->data_len - hs->data_offset;
  n_enq = clib_min (svm_fifo_size (ts->tx_fifo), to_send);

  rv = svm_fifo_enqueue (ts->tx_fifo, n_enq, hs->data + hs->data_offset);

  if (rv <= 0)
    {
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  if (rv < to_send)
    {
      hs->data_offset += rv;
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
    }

  if (svm_fifo_set_event (ts->tx_fifo))
    session_program_tx_io_evt (ts->handle, SESSION_IO_EVT_TX);

  return 0;
}

typedef struct
{
  session_handle_t handle;
  u32 app_index;
  u32 app_wrk_index;
  u32 listener_index;
} hss_pending_accept_t;

static hss_pending_accept_t **hss_pending_accepts;

static hss_pending_accept_t *
hss_pending_accept_get (session_t *ts)
{
  hss_pending_accept_t *pending;

  if (ts->thread_index >= vec_len (hss_pending_accepts))
    return 0;
  vec_foreach (pending, hss_pending_accepts[ts->thread_index])
    if (pending->handle == session_handle (ts) && pending->app_wrk_index == ts->app_wrk_index &&
	pending->app_index == app_worker_get (ts->app_wrk_index)->app_index)
      return pending;
  return 0;
}

static u32
hss_accept_listener_index (session_t *ts)
{
  hss_pending_accept_t *pending;
  session_t *parent, *ls;
  hss_session_t *hs;

  pending = hss_pending_accept_get (ts);
  if (pending)
    return pending->listener_index;
  if (!(ts->flags & SESSION_F_STREAM))
    {
      ls = session_get_from_handle_if_valid (ts->listener_handle);
      if (!ls || ls->session_state != SESSION_STATE_LISTENING)
	return ~0;
      return ls->opaque;
    }

  parent = session_get_from_handle_if_valid (ts->listener_handle);
  if (!parent || parent->app_wrk_index != ts->app_wrk_index)
    return ~0;
  pending = hss_pending_accept_get (parent);
  if (pending)
    return pending->listener_index;
  hs = hss_session_get (parent->thread_index, parent->opaque);
  if (hs && hs->vpp_session_handle == session_handle (parent))
    return hs->listener_index;
  if (parent->session_state == SESSION_STATE_ACCEPTING)
    return hss_accept_listener_index (parent);
  return ~0;
}

static int
hss_preserve_pending_accepts (hss_listener_t *l)
{
  application_t *app = application_get (hss_main.app_index);
  app_worker_map_t *map;
  app_worker_t *app_wrk;
  hss_pending_accept_t pending;
  session_event_t *evt;
  session_t *ts;
  u32 i, j;

  ASSERT (vlib_thread_is_main_w_barrier ());
  pool_foreach (map, app->worker_maps)
    {
      app_wrk = app_worker_get (map->wrk_index);
      vec_validate (hss_pending_accepts, vec_len (app_wrk->wrk_evts) - 1);
      for (i = 0; i < vec_len (app_wrk->wrk_evts); i++)
	for (j = 0; j < clib_fifo_elts (app_wrk->wrk_evts[i]); j++)
	  {
	    evt = app_wrk->wrk_evts[i] + clib_fifo_elt_index (app_wrk->wrk_evts[i], j);
	    if (evt->event_type != SESSION_CTRL_EVT_ACCEPTED)
	      continue;
	    ts = session_get (evt->session_index, i);
	    if (ts->app_wrk_index != app_wrk->wrk_index)
	      return -1;
	    if (hss_pending_accept_get (ts))
	      continue;
	    pending.listener_index = hss_accept_listener_index (ts);
	    if (!hss_listener_get (pending.listener_index))
	      return -1;
	    if (pending.listener_index != l->l_index)
	      continue;
	    pending.handle = session_handle (ts);
	    pending.app_index = app->app_index;
	    pending.app_wrk_index = app_wrk->wrk_index;
	    clib_atomic_add_fetch (&l->ref_count, 1);
	    vec_add1 (hss_pending_accepts[i], pending);
	  }
    }
  return 0;
}

/** \brief Session accept callback
 */
static int
hss_ts_accept_callback (session_t *ts)
{
  hss_pending_accept_t *pending;
  hss_session_t *hs;
  u32 thresh, listener_index;

  listener_index = hss_accept_listener_index (ts);
  if (!hss_listener_get (listener_index))
    return -1;
  pending = hss_pending_accept_get (ts);
  if (pending)
    vec_del1 (hss_pending_accepts[ts->thread_index],
	      pending - hss_pending_accepts[ts->thread_index]);
  else
    clib_atomic_add_fetch (&hss_listener_get (listener_index)->ref_count, 1);
  hs = hss_session_alloc (ts->thread_index);

  hs->vpp_session_index = ts->session_index;
  hs->vpp_session_handle = session_handle (ts);
  hs->listener_index = listener_index;
  hs->app_index = app_worker_get (ts->app_wrk_index)->app_index;
  hs->use_ptr_thresh = hss_listener_get (listener_index)->use_ptr_thresh;

  /* The application sets a threshold for it's fifo to get notified when
   * additional data can be enqueued. We want to keep the TX fifo reasonably
   * full, however avoid entering a state where the
   * fifo is full all the time and small chunks of data are being enqueued
   * each time. If the fifo is small (under 16K) we set
   * the threshold to it's size, meaning a notification will be given when the
   * fifo empties.
   */
  thresh = clib_min (svm_fifo_size (ts->tx_fifo), HSS_FIFO_THRESH);
  svm_fifo_set_deq_thresh (ts->tx_fifo, thresh);

  ts->opaque = hs->session_index;
  ts->session_state = SESSION_STATE_READY;
  return 0;
}

static void
hss_ts_disconnect_callback (session_t *ts)
{
  hss_session_t *hs = hss_session_get (ts->thread_index, ts->opaque);

  if (hs)
    hss_session_disconnect_transport (hs);
}

static void
hss_ts_reset_callback (session_t *ts)
{
  hss_ts_disconnect_callback (ts);
}

static int
hss_ts_connected_callback (u32 app_index, u32 api_context, session_t *ts,
			   session_error_t err)
{
  clib_warning ("called...");
  return -1;
}

static int
hss_add_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static int
hss_del_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static void
hss_session_cleanup (hss_session_t *hs)
{
  u32 l_index = hs->listener_index;
#if CLIB_DEBUG > 0
  u32 record_index = hss_async_cleanup_begin (hs);
#endif

  if (hs->cache_pool_index != ~0)
    hss_cache_detach_entry (hss_listener_get (l_index)->cache, hs->cache_pool_index);
  if (hs->free_data)
    vec_free (hs->data);
  vec_free (hs->headers_buf);
  vec_free (hs->path);
  vec_free (hs->authority);
  vec_free (hs->target_path);
  vec_free (hs->target_query);
  vec_free (hs->rx_buff);
  hss_session_free (hs);
  hss_listener_release (l_index);
#if CLIB_DEBUG > 0
  hss_async_cleanup_done (record_index);
#endif
}

static void
hss_ts_transport_closed (session_t *s)
{
  hss_session_t *hs = hss_session_get (s->thread_index, s->opaque);
  app_worker_t *app_wrk;

  if (!hs || hs->vpp_session_handle != session_handle (s))
    return;
  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (!app_wrk || app_wrk->app_index != hs->app_index || !(s->flags & SESSION_F_APP_CLOSED) ||
      hs->data_len || !s->tx_fifo || svm_fifo_max_dequeue (s->tx_fifo))
    return;
  s->opaque = ~0;
  hss_session_cleanup (hs);
}

static void
hss_ts_cleanup (session_t *s, session_cleanup_ntf_t ntf)
{
  hss_session_t *hs;

  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;
  hs = hss_session_get (s->thread_index, s->opaque);
  if (!hs)
    return;
  s->opaque = ~0;
  hss_session_cleanup (hs);
}

static session_cb_vft_t hss_cb_vft = {
  .session_accept_callback = hss_ts_accept_callback,
  .session_disconnect_callback = hss_ts_disconnect_callback,
  .session_connected_callback = hss_ts_connected_callback,
  .add_segment_callback = hss_add_segment_callback,
  .del_segment_callback = hss_del_segment_callback,
  .builtin_app_rx_callback = hss_ts_rx_callback,
  .builtin_app_tx_callback = hss_ts_tx_callback,
  .session_reset_callback = hss_ts_reset_callback,
  .session_transport_closed_callback = hss_ts_transport_closed,
  .session_cleanup_callback = hss_ts_cleanup,
};

static int
hss_attach ()
{
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  hss_main_t *hsm = &hss_main;
  u64 options[APP_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;
  u64 segment_size = 128 << 20;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  if (hsm->private_segment_size)
    segment_size = hsm->private_segment_size;

  a->api_client_index = ~0;
  a->name = format (0, "http_static_server_%u", hsm->app_generation++);
  a->session_cb_vft = &hss_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] =
    hsm->fifo_size ? hsm->fifo_size : 8 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] =
    hsm->fifo_size ? hsm->fifo_size : 32 << 10;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = hsm->prealloc_fifos;
  a->options[APP_OPTIONS_TLS_ENGINE] = CRYPTO_ENGINE_OPENSSL;

  if (vnet_application_attach (a))
    {
      vec_free (a->name);
      clib_warning ("failed to attach server");
      return -1;
    }
  vec_free (a->name);
  hsm->app_index = a->app_index;

  clib_memset (ck_pair, 0, sizeof (*ck_pair));
  ck_pair->cert = (u8 *) test_srv_crt_rsa;
  ck_pair->key = (u8 *) test_srv_key_rsa;
  ck_pair->cert_len = test_srv_crt_rsa_len;
  ck_pair->key_len = test_srv_key_rsa_len;
  vnet_app_add_cert_key_pair (ck_pair);
  hsm->ckpair_index = ck_pair->index;

  return 0;
}

static int
hss_transport_needs_crypto (session_endpoint_cfg_t *sep)
{
  return sep->flags & SESSION_ENDPT_CFG_F_SECURE ||
	 sep->transport_proto == TRANSPORT_PROTO_TLS ||
	 sep->transport_proto == TRANSPORT_PROTO_DTLS ||
	 sep->transport_proto == TRANSPORT_PROTO_QUIC;
}

static int
hss_listen (hss_listener_t *l, session_handle_t *lh)
{
  hss_main_t *hsm = &hss_main;
  vnet_listen_args_t _a, *a = &_a;
  u8 need_crypto;
  transport_endpt_ext_cfg_t *ext_cfg;
  int rv;
  transport_endpt_cfg_http_t http_cfg = { l->keepalive_timeout, 0 };

  clib_memset (a, 0, sizeof (*a));
  a->app_index = hsm->app_index;

  need_crypto = hss_transport_needs_crypto (&l->sep);

  clib_memcpy (&a->sep_ext, &l->sep, sizeof (l->sep));
  a->sep_ext.transport_proto = TRANSPORT_PROTO_HTTP;

  ext_cfg = session_endpoint_add_ext_cfg (
    &a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_HTTP, sizeof (http_cfg));
  clib_memcpy (ext_cfg->data, &http_cfg, sizeof (http_cfg));

  if (need_crypto)
    {
      l->flags |= HSS_LISTENER_F_NEED_CRYPTO;
      ext_cfg = session_endpoint_add_ext_cfg (
	&a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
	sizeof (transport_endpt_crypto_cfg_t));
      ext_cfg->crypto.ckpair_index = hsm->ckpair_index;
      if (l->flags & HSS_LISTENER_F_HTTP1_ONLY)
	ext_cfg->crypto.alpn_protos[0] = TLS_ALPN_PROTO_HTTP_1_1;
      else if (l->flags & HSS_LISTENER_F_HTTP3)
	ext_cfg->crypto.alpn_protos[0] = TLS_ALPN_PROTO_HTTP_3;
    }

  if (!(rv = vnet_listen (a)))
    *lh = a->handle;

  session_endpoint_free_ext_cfgs (&a->sep_ext);

  return rv;
}

static void
hss_url_handlers_init (hss_main_t *hsm)
{
  if (hsm->get_url_handlers)
    return;

  hsm->get_url_handlers = hash_create_string (0, sizeof (uword));
  hsm->post_url_handlers = hash_create_string (0, sizeof (uword));
  hss_builtinurl_json_handlers_init ();
#if CLIB_DEBUG > 0
  hss_register_url_handler (hss_async_handler, "hss-async-test", HTTP_REQ_GET);
#endif
}

int
hss_listener_add (hss_listener_t *l_cfg)
{
  hss_main_t *hsm = &hss_main;
  session_handle_t lh;
  app_listener_t *al;
  hss_listener_t *l;
  session_t *ls;

  ASSERT (vlib_thread_is_main_w_barrier ());
  if (hss_listen (l_cfg, &lh))
    {
      clib_warning ("failed to start listening");
      return -1;
    }

  pool_get (hsm->listeners, l);
  *l = *l_cfg;
  l->cache = 0;
  l->l_index = l - hsm->listeners;
  l->session_handle = lh;
  l->ref_count = 1;
  l->retiring = 0;
  l_cfg->l_index = l->l_index;
  l_cfg->www_root = 0;

  al = app_listener_get_w_handle (lh);
  ls = app_listener_get_session (al);
  ls->opaque = l->l_index;

  if (l->www_root)
    {
      l->cache = clib_mem_alloc_aligned (sizeof (*l->cache), CLIB_CACHE_LINE_BYTES);
      clib_memset (l->cache, 0, sizeof (*l->cache));
      hss_cache_init (l->cache, l->cache_size, hsm->debug_level);
    }
  if (l->enable_url_handlers)
    hss_url_handlers_init (hsm);

  l->max_age_formatted = format (0, "max-age=%d", l->max_age);
#if CLIB_DEBUG > 0
  hss_async_listener_added (l->l_index);
#endif
  return 0;
}

int
hss_listener_del (hss_listener_t *l_cfg)
{
  hss_main_t *hsm = &hss_main;
  hss_listener_t *l;
  u8 found = 0;
  int rv;

  ASSERT (vlib_thread_is_main_w_barrier ());
  pool_foreach (l, hsm->listeners)
    {
      if (!l->retiring && clib_memcmp (&l_cfg->sep, &l->sep, sizeof (l_cfg->sep)) == 0)
	{
	  found = 1;
	  break;
	}
    }

  if (!found)
    return -1;

  if (hss_preserve_pending_accepts (l))
    return -1;
  vnet_unlisten_args_t args = { .handle = l->session_handle, .app_index = hsm->app_index };
  if ((rv = vnet_unlisten (&args)))
    return rv;

  l->retiring = 1;
  if (hsm->default_listener_index == l->l_index)
    hsm->default_listener_index = ~0;
  hss_listener_release (l->l_index);
  return 0;
}

int
hss_create (vlib_main_t *vm)
{
  hss_main_t *hsm = &hss_main;
  u32 num_threads;

  num_threads = 1 + vlib_num_workers ();
  vec_validate (hsm->sessions, num_threads - 1);

  /* Make sure session layer is enabled */
  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };
  vnet_session_enable_disable (vm, &args);

  if (hss_attach ())
    {
      clib_warning ("failed to attach server");
      return -1;
    }

  hsm->default_listener_index = ~0;
  if (hsm->have_default_listener)
    {
      if (hss_listener_add (&hsm->default_listener))
	{
	  vnet_app_detach_args_t da = { .app_index = hsm->app_index, .api_client_index = ~0 };
	  vnet_application_detach (&da);
	  vnet_app_del_cert_key_pair (hsm->ckpair_index);
	  hsm->app_index = ~0;
	  hsm->have_default_listener = 0;
	  clib_warning ("failed to start listening");
	  return -1;
	}
      hsm->default_listener_index = hsm->default_listener.l_index;
    }

  hsm->is_init = 1;

  return 0;
}

typedef struct
{
  u32 app_index;
  u32 ckpair_index;
  u32 pending_threads;
} hss_destroy_ctx_t;

static hss_destroy_ctx_t ***hss_pending_destroys;

static void
hss_detach_rpc (void *arg)
{
  hss_destroy_ctx_t *ctx = *(hss_destroy_ctx_t **) arg;
  vnet_app_detach_args_t da = { .app_index = ctx->app_index, .api_client_index = ~0 };

  ASSERT (vlib_thread_is_main_w_barrier ());
  if (vnet_application_detach (&da))
    clib_warning ("failed to detach http_static app %u", ctx->app_index);
  vnet_app_del_cert_key_pair (ctx->ckpair_index);
  clib_mem_free (ctx);
}

static int
hss_destroy_sessions (hss_destroy_ctx_t *ctx)
{
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  application_t *app = application_get (ctx->app_index);
  app_worker_map_t *map;
  app_worker_t *app_wrk;
  hss_session_t *hs;
  session_t *s;
  u8 pending = 0;

  pool_foreach (map, app->worker_maps)
    {
      app_wrk = app_worker_get (map->wrk_index);
      if (clib_fifo_elts (app_wrk->wrk_evts[thread_index]))
	app_wrk_flush_wrk_events (app_wrk, thread_index);
      pending |= clib_fifo_elts (app_wrk->wrk_evts[thread_index]) != 0;
    }
  if (pending)
    return 0;

  pool_foreach (hs, hss_main.sessions[thread_index])
    {
      if (hs->app_index != ctx->app_index)
	continue;
      s = session_get_from_handle (hs->vpp_session_handle);
      s->opaque = ~0;
      session_reset (s);
      /* A queued reset does not stop HTTP from reading response pointers. */
      if (s->session_state < SESSION_STATE_TRANSPORT_CLOSED)
	transport_reset (session_get_transport_proto (s), s->connection_index, thread_index);
      hss_session_cleanup (hs);
    }

  if (clib_atomic_sub_fetch (&ctx->pending_threads, 1) == 0)
    vlib_rpc_call_main_thread (hss_detach_rpc, (u8 *) &ctx, sizeof (ctx));
  return 1;
}

static uword
hss_destroy_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  hss_destroy_ctx_t **pending;
  hss_destroy_ctx_t **ctx;
  u32 remaining = 0;

  if (vm->thread_index >= vec_len (hss_pending_destroys))
    return 0;
  pending = hss_pending_destroys[vm->thread_index];
  vec_foreach (ctx, pending)
    if (!hss_destroy_sessions (*ctx))
      pending[remaining++] = *ctx;
  vec_set_len (pending, remaining);
  if (remaining)
    vlib_node_set_interrupt_pending (vm, node->node_index);
  return 0;
}

VLIB_REGISTER_NODE (hss_destroy_node, static) = {
  .function = hss_destroy_node_fn,
  .name = "http-static-destroy",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};

int
hss_destroy (vlib_main_t *vm)
{
  hss_main_t *hsm = &hss_main;
  hss_destroy_ctx_t *ctx;
  hss_listener_t *l;
  u32 i;
  int ret;

  ASSERT (vlib_thread_is_main_w_barrier ());
  if (!hsm->is_init)
    return 0;

  pool_foreach (l, hsm->listeners)
    {
      if (l->retiring)
	continue;
      ret = hss_listener_del (l);
      if (ret != 0)
	{
	  clib_warning ("failed to delete a listener: %d", ret);
	  return -1;
	}
    }

  ctx = clib_mem_alloc (sizeof (*ctx));
  *ctx = (hss_destroy_ctx_t) { .app_index = hsm->app_index,
			       .ckpair_index = hsm->ckpair_index,
			       .pending_threads = vec_len (hsm->sessions) };
  clib_memset (&hsm->default_listener, 0, sizeof (hsm->default_listener));
  hsm->default_listener_index = ~0;
  hsm->have_default_listener = 0;
  hsm->app_index = ~0;
  hsm->is_init = 0;

  /* The barrier serializes publication with worker consumption and vector growth. */
  vec_validate (hss_pending_destroys, vec_len (hsm->sessions) - 1);
  for (i = 0; i < vec_len (hsm->sessions); i++)
    {
      vec_add1 (hss_pending_destroys[i], ctx);
      vlib_node_set_interrupt_pending (vlib_get_main_by_index (i), hss_destroy_node.index);
    }
  return 0;
}

#if CLIB_DEBUG > 0
static hss_url_handler_rc_t
hss_async_handler (hss_url_handler_args_t *args)
{
  hss_session_t *hs = hss_session_get (args->sh.thread_index, args->sh.session_index);
  hss_async_listener_t *entry;
  hss_async_record_t *record;
  session_t *session;
  u32 i;

  args->data = 0;
  args->data_len = 0;
  args->free_vec_data = 0;
  if (!hss_async_test.enabled || !hs || hs->thread_index != 1)
    return HSS_URL_HANDLER_ERROR;
  entry = hss_async_listener (hs->listener_index);
  session = session_get_from_handle_if_valid (hs->vpp_session_handle);
  if (!entry || !session || session_get_transport_proto (session) != TRANSPORT_PROTO_HTTP)
    return HSS_URL_HANDLER_ERROR;
  for (i = 0; i < HSS_ASYNC_RECORDS; i++)
    {
      record = &hss_async_test.records[i];
      if (!record->armed || record->listener != entry - hss_async_test.listeners)
        continue;
      record->armed = 0;
      record->active = 1;
      record->thread = hs->thread_index;
      record->hs_index = hs->session_index;
      record->handle = hs->vpp_session_handle;
      record->app_index = hs->app_index;
      record->app_worker = session->app_wrk_index;
      record->tx_before = svm_fifo_max_dequeue (session->tx_fifo);
      record->enter_seq = hss_async_sequence ();
      return HSS_URL_HANDLER_ASYNC;
    }
  hss_async_test.overflow = 1;
  return HSS_URL_HANDLER_ERROR;
}

static uword
hss_async_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  hss_async_record_t *record;
  hss_async_listener_t *entry;
  hss_url_handler_args_t args = {};
  hss_session_t *hs;
  app_worker_t *worker;
  session_t *session;
  u32 i;

  for (i = 0; i < HSS_ASYNC_RECORDS; i++)
    {
      record = &hss_async_test.records[i];
      if (!record->pending || record->thread != vm->thread_index)
        continue;
      record->pending = 0;
      if (!record->active)
        {
          if (record->cancels)
            record->late++;
          else
            record->duplicates++;
          continue;
        }
      entry = &hss_async_test.listeners[record->listener];
      hs = hss_session_get (record->thread, record->hs_index);
      session = session_get_from_handle_if_valid (record->handle);
      worker = app_worker_get_if_valid (record->app_worker);
      if (!hs || !session || !worker || !record->async_seq ||
          hs->vpp_session_handle != record->handle || hs->app_index != record->app_index ||
          hs->listener_index != entry->index || hss_async_listener (entry->index) != entry ||
          session->opaque != record->hs_index || session->app_wrk_index != record->app_worker ||
          worker->app_index != record->app_index)
        {
          hss_async_test.overflow = 1;
          record->active = 0;
          record->cancels++;
          record->cancel_seq = hss_async_sequence ();
          vec_free (record->response);
          continue;
        }
      args.sh.thread_index = record->thread;
      args.sh.session_index = record->hs_index;
      args.data = record->response;
      args.data_len = vec_len (record->response);
      args.free_vec_data = 1;
      args.sc = HTTP_STATUS_OK;
      args.ct = HTTP_CONTENT_TEXT_PLAIN;
      if (hss_add_header (hs, HTTP_HEADER_CACHE_CONTROL,
                          (const char *) hss_listener_get (entry->index)->max_age_formatted,
                          vec_len (hss_listener_get (entry->index)->max_age_formatted)))
        args.sc = HTTP_STATUS_INTERNAL_ERROR;
      record->response = 0;
      record->active = 0;
      hss_session_send_data (&args);
    }
  return 0;
}

VLIB_REGISTER_NODE (hss_async_node, static) = {
  .function = hss_async_node_fn,
  .name = "http-static-test-async",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};

static clib_error_t *
hss_async_recover (hss_async_record_t *record)
{
  hss_async_listener_t *entry = &hss_async_test.listeners[record->listener];
  hss_listener_t *listener = hss_listener_get (entry->index);
  hss_session_t *hs;
  hss_pending_accept_t *pending;
  u32 i;

  if (!record->cleanup_seq || record->pending || entry->recoveries || entry->pool_puts ||
      !listener || hss_async_listener (entry->index) != entry || !listener->retiring ||
      listener->ref_count != 1 || entry->cache_frees || entry->final_seq ||
      !record->omitted)
    return clib_error_return (0, "async recovery requires one observed omitted final reference");
  for (i = 0; i < vec_len (hss_main.sessions); i++)
    {
      pool_foreach (hs, hss_main.sessions[i])
        if (hs->listener_index == entry->index)
          return clib_error_return (0, "async recovery has a live session owner");
      if (i < vec_len (hss_pending_accepts))
        vec_foreach (pending, hss_pending_accepts[i])
          if (pending->listener_index == entry->index)
            return clib_error_return (0, "async recovery has a captured owner");
    }
  if (listener->cache)
    {
      hss_cache_entry_t *cached;
      pool_foreach (cached, listener->cache->cache_pool)
        if (cached->inuse)
          return clib_error_return (0, "async recovery has a live cache owner");
    }
  if (record->token != 101 || record->sends != 1 || record->cleanups != 1)
    return clib_error_return (0, "async recovery is restricted to completed token 101");
  entry->recoveries++;
  hss_listener_release (entry->index);
  return 0;
}

static void
hss_async_status (vlib_main_t *vm)
{
  hss_async_record_t *record;
  hss_async_listener_t *entry;
  hss_listener_t *listener;
  u32 i;

  vlib_cli_output (vm, "async-ledger enabled %u overflow %u live %u baseline %u",
                   hss_async_test.enabled, hss_async_test.overflow,
                   pool_elts (hss_main.listeners), hss_async_test.baseline);
  for (i = 0; i < HSS_ASYNC_RECORDS; i++)
    {
      record = &hss_async_test.records[i];
      if (!record->token)
        continue;
      entry = &hss_async_test.listeners[record->listener];
      listener = entry->pool_puts ? 0 : hss_listener_get (entry->index);
      vlib_cli_output (vm,
                       "token %u epoch %llu generation %u app %u thread %u hs %u handle %llu "
                       "listener %u enter %llu async %llu send %llu cancel %llu cleanup %llu "
                       "sends %u cancels %u cleanups %u duplicate %u late %u pending %u "
                       "owned %u tx %u refs %u retiring %u final %llu freed %llu "
                       "releases %u cachefree %u vecfree %u poolput %u recovery %u omitted %u",
                       record->token, entry->epoch, entry->generation, record->app_index,
                       record->thread, record->hs_index, record->handle, entry->index,
                       record->enter_seq, record->async_seq, record->send_seq, record->cancel_seq,
                       record->cleanup_seq, record->sends, record->cancels, record->cleanups,
                       record->duplicates, record->late, record->pending, record->response != 0,
                       record->tx_before, listener ? listener->ref_count : 0,
                       listener ? listener->retiring : 1, entry->final_seq, entry->free_seq,
                       entry->releases, entry->cache_frees, entry->vec_frees, entry->pool_puts,
                       entry->recoveries, record->omitted);
    }
}

static clib_error_t *
hss_async_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  hss_async_record_t *record = 0;
  hss_async_listener_t *entry;
  u32 token, index, i;
  u8 *body = 0;

  ASSERT (vlib_thread_is_main_w_barrier ());
  if (unformat (input, "start"))
    {
      if (hss_async_test.enabled || pool_elts (hss_main.listeners) || vlib_num_workers () != 1)
        return clib_error_return (0, "async start requires idle listeners and one worker");
      for (i = 0; i < vec_len (hss_pending_destroys); i++)
        if (vec_len (hss_pending_destroys[i]))
          return clib_error_return (0, "async start requires completed destroys");
      for (i = 0; i < vec_len (hss_main.sessions); i++)
        if (pool_elts (hss_main.sessions[i]))
          return clib_error_return (0, "async start requires no sessions");
      clib_memset (&hss_async_test, 0, sizeof (hss_async_test));
      hss_async_test.enabled = 1;
      hss_async_test.baseline = pool_elts (hss_main.listeners);
      return 0;
    }
  if (!hss_async_test.enabled)
    return clib_error_return (0, "async ledger is disabled");
  if (unformat (input, "status"))
    {
      hss_async_status (vm);
      return 0;
    }
  if (unformat (input, "clear"))
    {
      if (pool_elts (hss_main.listeners) != hss_async_test.baseline)
        return clib_error_return (0, "async clear requires baseline listeners");
      for (i = 0; i < HSS_ASYNC_RECORDS; i++)
        if (hss_async_test.records[i].armed || hss_async_test.records[i].active ||
            hss_async_test.records[i].pending || hss_async_test.records[i].response)
          return clib_error_return (0, "async clear requires drained records");
      for (i = 0; i < hss_async_test.listener_count; i++)
        if (!hss_async_test.listeners[i].pool_puts)
          return clib_error_return (0, "async clear requires completed listener frees");
      for (i = 0; i < vec_len (hss_pending_destroys); i++)
        if (vec_len (hss_pending_destroys[i]))
          return clib_error_return (0, "async clear requires completed destroys");
      hss_async_test.enabled = 0;
      return 0;
    }
  if (unformat (input, "arm %u listener %u body %s", &token, &index, &body))
    {
      entry = hss_async_listener (index);
      if (!token || !entry || !hss_listener_get (index) || hss_listener_get (index)->retiring)
        {
          vec_free (body);
          return clib_error_return (0, "async arm listener invalid");
        }
      for (i = 0; i < HSS_ASYNC_RECORDS; i++)
        {
          if (hss_async_test.records[i].token == token ||
              (hss_async_test.records[i].armed &&
               hss_async_test.records[i].listener == entry - hss_async_test.listeners))
            {
              vec_free (body);
              return clib_error_return (0, "async token or listener already armed");
            }
          if (!record && !hss_async_test.records[i].token)
            record = &hss_async_test.records[i];
        }
      if (!record)
        {
          vec_free (body);
          return clib_error_return (0, "async records full");
        }
      record->token = token;
      record->listener = entry - hss_async_test.listeners;
      record->response = body;
      vec_set_len (body, strlen ((char *) body));
      record->armed = 1;
      return 0;
    }
  if (unformat (input, "release %u", &token))
    {
      for (i = 0; i < HSS_ASYNC_RECORDS; i++)
        if (hss_async_test.records[i].token == token)
          record = &hss_async_test.records[i];
      if (!record || !record->async_seq || record->pending)
        return clib_error_return (0, "async release token not ready");
      record->pending = 1;
      vlib_node_set_interrupt_pending (vlib_get_main_by_index (record->thread), hss_async_node.index);
      return 0;
    }
  if (unformat (input, "recover %u", &token))
    {
      for (i = 0; i < HSS_ASYNC_RECORDS; i++)
        if (hss_async_test.records[i].token == token)
          record = &hss_async_test.records[i];
      if (!record)
        return clib_error_return (0, "async recovery token missing");
      return hss_async_recover (record);
    }
  return clib_error_return (0, "unknown async command");
}

VLIB_CLI_COMMAND (hss_async_command, static) = {
  .path = "test http static async",
  .short_help = "test http static async start|status|arm <token> listener <index> body <body>|"
                "release <token>|recover <token>|clear",
  .function = hss_async_command_fn,
};

static session_handle_t
hss_test_accept_alloc (session_handle_t listener, session_handle_t parent)
{
  session_t *s = session_alloc (0);
  session_handle_t handle = session_handle (s);
  udp_connection_t *uc = udp_connection_alloc (0);
  int rv;

  uc->c_s_index = s->session_index;
  uc->c_is_ip4 = 1;
  s->connection_index = uc->c_c_index;
  s->session_type = session_type_from_proto_and_ip (TRANSPORT_PROTO_UDP, 1);
  s->session_state = SESSION_STATE_ACCEPTING;
  s->listener_handle = listener;
  s->opaque = ~0;
  rv = app_worker_init_accepted (s);
  s = session_get_from_handle (handle);
  if (rv)
    {
      udp_connection_free (udp_connection_get (s->connection_index, 0));
      session_free (s);
      return SESSION_INVALID_HANDLE;
    }
  if (parent != SESSION_INVALID_HANDLE)
    {
      s->flags |= SESSION_F_STREAM;
      s->listener_handle = parent;
    }
  return session_handle (s);
}

static clib_error_t *
hss_test_flush_init_events (app_worker_t *app_wrk, session_handle_t listener)
{
  session_t *ls = session_get_from_handle_if_valid (listener);
  segment_manager_t *sm, *expected;
  session_event_t *evt;
  u32 i, sm_index, segment_index, remaining, before;

  ASSERT (vlib_thread_is_main_w_barrier ());
  if (!ls || app_wrk->app_index != hss_main.app_index)
    return clib_error_return (0, "pending accept initialization owner invalid");
  expected = app_worker_get_listen_segment_manager (app_wrk, ls);
  if (!expected || expected->app_wrk_index != app_wrk->wrk_index)
    return clib_error_return (0, "pending accept initialization listener invalid");
  remaining = clib_fifo_elts (app_wrk->wrk_evts[0]);
  for (i = 0; i < remaining; i++)
    {
      evt = app_wrk->wrk_evts[0] + clib_fifo_elt_index (app_wrk->wrk_evts[0], i);
      if (evt->event_type != SESSION_CTRL_EVT_APP_ADD_SEGMENT)
	return clib_error_return (0, "pending accept unexpected initialization event %u",
				  evt->event_type);
      segment_manager_parse_segment_handle (evt->as_u64[1], &sm_index, &segment_index);
      sm = segment_manager_get_if_valid (sm_index);
      if (sm != expected || sm->app_wrk_index != app_wrk->wrk_index ||
	  pool_is_free_index (sm->segments, segment_index) ||
	  evt->as_u64[1] != segment_manager_make_segment_handle (sm_index, segment_index))
	return clib_error_return (0, "pending accept initialization segment invalid");
    }
  for (i = 0; i < remaining && clib_fifo_elts (app_wrk->wrk_evts[0]); i++)
    {
      before = clib_fifo_elts (app_wrk->wrk_evts[0]);
      if (app_wrk_flush_wrk_events (app_wrk, 0) || clib_fifo_elts (app_wrk->wrk_evts[0]) >= before)
	return clib_error_return (0, "pending accept initialization flush made no progress");
    }
  if (clib_fifo_elts (app_wrk->wrk_evts[0]))
    return clib_error_return (0, "pending accept initialization queue retained");
  return 0;
}

static void
hss_test_accept_free (session_handle_t handle)
{
  session_t *s = session_get_from_handle (handle);
  hss_pending_accept_t *pending = hss_pending_accept_get (s);
  hss_session_t *hs = hss_session_get (0, s->opaque);

  if (pending)
    {
      u32 listener_index = pending->listener_index;
      vec_del1 (hss_pending_accepts[0], pending - hss_pending_accepts[0]);
      hss_listener_release (listener_index);
    }
  s->opaque = ~0;
  if (hs && hs->vpp_session_handle == handle)
    hss_session_cleanup (hs);
  segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
  udp_connection_free (udp_connection_get (s->connection_index, 0));
  session_free (s);
}

static clib_error_t *
hss_test_accept_batches (app_worker_t *app_wrk, u32 old_index)
{
  app_wrk_flush_wrk_events (app_wrk, 0);
  if (clib_fifo_elts (app_wrk->wrk_evts[0]) != 1 || vec_len (hss_pending_accepts[0]) != 1)
    return clib_error_return (0, "pending accept first batch: queue %u, captures %u",
			      clib_fifo_elts (app_wrk->wrk_evts[0]),
			      vec_len (hss_pending_accepts[0]));
  app_wrk_flush_wrk_events (app_wrk, 0);
  if (clib_fifo_elts (app_wrk->wrk_evts[0]) || vec_len (hss_pending_accepts[0]) ||
      hss_listener_get (old_index)->ref_count != 130)
    return clib_error_return (0, "pending accept transfer: queue %u, captures %u, refs %u",
			      clib_fifo_elts (app_wrk->wrk_evts[0]),
			      vec_len (hss_pending_accepts[0]),
			      hss_listener_get (old_index)->ref_count);
  return 0;
}

static session_handle_t
hss_test_listener_handle (u32 index)
{
  app_listener_t *al = app_listener_get_w_handle (hss_listener_get (index)->session_handle);

  return session_handle (app_listener_get_session (al));
}

static void
hss_test_accept_recover (session_handle_t *handles, u32 count, u32 old_index)
{
  session_t *s;
  u32 i;

  /* Preserve the fixture identity only after a production-path check has failed. */
  for (i = 0; i < count; i++)
    {
      s = session_get_from_handle (handles[i]);
      if (!(s->flags & SESSION_F_RX_READY) && !hss_pending_accept_get (s))
	{
	  hss_pending_accept_t pending = { .handle = handles[i],
					   .app_index = hss_main.app_index,
					   .app_wrk_index = s->app_wrk_index,
					   .listener_index = old_index };
	  vec_validate (hss_pending_accepts, 0);
	  clib_atomic_add_fetch (&hss_listener_get (old_index)->ref_count, 1);
	  vec_add1 (hss_pending_accepts[0], pending);
	}
    }
}

static clib_error_t *
hss_test_pending_accept_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  hss_main_t *hsm = &hss_main;
  hss_listener_t cfg = { .sep = SESSION_ENDPOINT_CFG_NULL };
  vnet_app_detach_args_t da;
  session_handle_t handles[130], listener;
  app_worker_t *app_wrk;
  hss_session_t *hs;
  hss_listener_t *l;
  session_t *s;
  clib_error_t *error = 0;
  u32 old_index = ~0, new_index = ~0, count = 0, notified = 0, i;
  hss_listener_t saved_default = hsm->default_listener;
  u64 saved_segment_size = hsm->private_segment_size;
  u32 saved_fifo_size = hsm->fifo_size, saved_prealloc = hsm->prealloc_fifos;
  u8 saved_have_default = hsm->have_default_listener, guard = 0;
  int rv;

  ASSERT (vlib_thread_is_main_w_barrier ());
  if (hsm->is_init || hsm->app_index != (u32) ~0 || pool_elts (hsm->listeners))
    return clib_error_return (0, "pending accept test requires an idle HSS");
  for (i = 0; i < vec_len (hss_pending_destroys); i++)
    if (vec_len (hss_pending_destroys[i]))
      return clib_error_return (0, "pending accept test requires completed destroys");
  for (i = 0; i < vec_len (hss_pending_accepts); i++)
    if (vec_len (hss_pending_accepts[i]))
      return clib_error_return (0, "pending accept test requires released captures");
  clib_memset (&hsm->default_listener, 0, sizeof (hsm->default_listener));
  hsm->have_default_listener = 0;
  hsm->private_segment_size = 128 << 20;
  hsm->fifo_size = 8 << 10;
  hsm->prealloc_fifos = 0;
  vec_validate (hss_pending_accepts, 0);
  rv = hss_create (vm);
  hsm->default_listener = saved_default;
  hsm->have_default_listener = saved_have_default;
  hsm->private_segment_size = saved_segment_size;
  hsm->fifo_size = saved_fifo_size;
  hsm->prealloc_fifos = saved_prealloc;
  if (rv)
    return clib_error_return (0, "pending accept test attach failed");
  app_wrk = application_get_default_worker (application_get (hsm->app_index));
  if (clib_fifo_elts (app_wrk->wrk_evts[0]))
    {
      error = clib_error_return (0, "pending accept test requires an empty queue");
      goto done;
    }
  cfg.sep.is_ip4 = 1;
  cfg.sep.port = clib_host_to_net_u16 (18088);
  cfg.sep.transport_proto = TRANSPORT_PROTO_TCP;
  cfg.keepalive_timeout = HSS_DEFAULT_KEEPALIVE_TIMEOUT;
  cfg.enable_url_handlers = 1;
  if (hss_listener_add (&cfg))
    {
      error = clib_error_return (0, "pending accept test listen failed");
      goto done;
    }
  old_index = cfg.l_index;
  listener = hss_test_listener_handle (old_index);
  for (i = 0; i < 129; i++)
    {
      handles[count] =
	hss_test_accept_alloc (listener, i == 128 ? handles[0] : SESSION_INVALID_HANDLE);
      if (handles[count] == SESSION_INVALID_HANDLE)
	{
	  error = clib_error_return (0, "pending accept test allocation %u failed", i);
	  goto done;
	}
      count++;
    }
  error = hss_test_flush_init_events (app_wrk, listener);
  if (error)
    return error;
  for (i = 0; i < count; i++)
    app_worker_accept_notify (app_wrk, session_get_from_handle (handles[i]));
  notified = count;
  clib_atomic_add_fetch (&hss_listener_get (old_index)->ref_count, 1);
  guard = 1;
  vec_validate (hss_pending_accepts, 0);
  if (clib_fifo_elts (app_wrk->wrk_evts[0]) != 129 || hss_listener_del (&cfg) ||
      vec_len (hss_pending_accepts[0]) != 129 || hss_listener_get (old_index)->ref_count != 130 ||
      hss_preserve_pending_accepts (hss_listener_get (old_index)) ||
      hss_listener_get (old_index)->ref_count != 130)
    {
      error = clib_error_return (0, "pending accept snapshot/dedup failed");
      goto done;
    }
  if (hss_listener_add (&cfg))
    {
      error = clib_error_return (0, "pending accept delete/readd failed");
      goto done;
    }
  new_index = cfg.l_index;
  if (new_index == old_index || !hss_listener_get (old_index)->retiring ||
      hss_listener_get (old_index)->ref_count != 130)
    {
      error = clib_error_return (0, "pending accept old/new listener ownership failed");
      goto done;
    }
  error = hss_test_accept_batches (app_wrk, old_index);
  if (error)
    goto done;
  handles[count] = hss_test_accept_alloc (hss_test_listener_handle (new_index), handles[0]);
  if (handles[count] == SESSION_INVALID_HANDLE)
    {
      error = clib_error_return (0, "pending accept stream allocation failed");
      goto done;
    }
  count++;
  error = hss_test_flush_init_events (app_wrk, hss_test_listener_handle (new_index));
  if (error)
    return error;
  app_worker_accept_notify (app_wrk, session_get_from_handle (handles[count - 1]));
  notified = count;
  app_wrk_flush_wrk_events (app_wrk, 0);
  for (i = 0; i < count; i++)
    {
      s = session_get_from_handle (handles[i]);
      hs = hss_session_get (0, s->opaque);
      if (!hs || hs->listener_index != old_index || !(s->flags & SESSION_F_RX_READY))
	{
	  error =
	    clib_error_return (0, "pending accept session %u lost old listener %u", i, old_index);
	  goto done;
	}
    }
  if (hss_listener_get (old_index)->ref_count != count + 1)
    error = clib_error_return (0, "pending accept stream reference failed");

done:
  da = (vnet_app_detach_args_t) { .app_index = hsm->app_index, .api_client_index = ~0 };
  u32 budget = clib_fifo_elts (app_wrk->wrk_evts[0]);
  for (i = 0; i < budget; i++)
    {
      session_event_t *evt = app_wrk->wrk_evts[0] + clib_fifo_elt_index (app_wrk->wrk_evts[0], i);
      if (evt->event_type != SESSION_CTRL_EVT_ACCEPTED)
	{
	  if (!error)
	    error =
	      clib_error_return (0, "pending accept unexpected cleanup event %u", evt->event_type);
	  return error;
	}
    }
  if (error)
    hss_test_accept_recover (handles, notified, old_index);
  for (i = 0; i < budget && clib_fifo_elts (app_wrk->wrk_evts[0]); i++)
    app_wrk_flush_wrk_events (app_wrk, 0);
  if (clib_fifo_elts (app_wrk->wrk_evts[0]) || vec_len (hss_pending_accepts[0]))
    {
      if (!error)
	error = clib_error_return (0, "pending accept cleanup queue retained");
      return error;
    }
  for (i = 0; i < count; i++)
    hss_test_accept_free (handles[i]);
  if (guard)
    hss_listener_release (old_index);
  if (!error && hss_listener_get (old_index))
    error = clib_error_return (0, "pending accept old listener was not released");
  pool_foreach (l, hsm->listeners)
    if (!l->retiring && hss_listener_del (l) && !error)
      error = clib_error_return (0, "pending accept test unlisten failed");
  rv = vnet_application_detach (&da);
  if (rv)
    {
      if (!error)
	error = clib_error_return (0, "pending accept test detach failed: %d", rv);
      return error;
    }
  vnet_app_del_cert_key_pair (hsm->ckpair_index);
  hsm->app_index = ~0;
  hsm->is_init = 0;
  if (!error)
    vlib_cli_output (vm, "synthetic queued accept: 129 events, batches 128+1, "
			 "130 old owners released");
  return error;
}

VLIB_CLI_COMMAND (hss_test_pending_accept_command, static) = {
  .path = "test http static pending accept",
  .short_help = "test http static pending accept",
  .function = hss_test_pending_accept_command_fn,
};

static clib_error_t *
hss_test_cache_registry (void)
{
  hss_listener_t *l;
  u32 i, found;

  pool_foreach (l, hss_main.listeners)
    {
      if (!l->cache)
	continue;
      found = 0;
      for (i = 0; i < vec_len (clib_all_bihashes); i++)
	found += clib_all_bihashes[i] == &l->cache->name_to_data;
      if (found != 1)
	return clib_error_return (0, "listener %u cache registered %u times", l->l_index, found);
    }
  return 0;
}

static clib_error_t *
hss_test_cache_relocation_command_fn (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *cmd)
{
  hss_main_t *hsm = &hss_main;
  hss_listener_t *copy, *old, *l;
  pool_header_t *old_header, *new_header;
  clib_error_t *error;
  uword old_base, registry_count;
  u32 pass, i, moved = 0;

  ASSERT (vlib_thread_is_main_w_barrier ());
  if (!pool_elts (hsm->listeners))
    return clib_error_return (0, "cache relocation test requires live listeners");
  error = hss_test_cache_registry ();
  if (error)
    return error;
  registry_count = vec_len (clib_all_bihashes);
  pool_foreach (l, hsm->listeners)
    if (l->cache)
      vlib_cli_output (vm, "listener %u cache %llx hash %llx lock %llx retiring %u", l->l_index,
		       pointer_to_uword (l->cache), pointer_to_uword (&l->cache->name_to_data),
		       pointer_to_uword (l->cache->cache_lock), l->retiring);
  for (pass = 0; pass < 2; pass++)
    {
      old = hsm->listeners;
      old_base = pointer_to_uword (old);
      copy = pool_dup (old);
      old_header = pool_header (old);
      new_header = pool_header (copy);
      if (copy == old || vec_len (copy) != vec_len (old) ||
	  !clib_bitmap_is_equal (new_header->free_bitmap, old_header->free_bitmap) ||
	  vec_len (new_header->free_indices) != vec_len (old_header->free_indices))
	{
	  pool_free (copy);
	  return clib_error_return (0, "listener pool copy changed allocation state");
	}
      for (i = 0; i < vec_len (old_header->free_indices); i++)
	if (new_header->free_indices[i] != old_header->free_indices[i])
	  {
	    pool_free (copy);
	    return clib_error_return (0, "listener pool copy changed free-list order");
	  }
      pool_foreach (l, old)
	if (memcmp (l, pool_elt_at_index (copy, l - old), sizeof (*l)))
	  {
	    pool_free (copy);
	    return clib_error_return (0, "listener pool copy changed live ownership");
	  }
      hsm->listeners = copy;
      error = hss_test_cache_registry ();
      if (!error && vec_len (clib_all_bihashes) != registry_count)
	error = clib_error_return (0, "pool move changed hash registry count");
      if (error)
	{
	  hsm->listeners = old;
	  pool_free (copy);
	  return error;
	}
      pool_free (old);
      moved++;
      vlib_cli_output (vm, "listener pool moved %llx -> %llx", old_base, pointer_to_uword (copy));
    }
  vlib_cli_output (vm, "cache registry: %u explicit pool moves, unique stable hashes", moved);
  return 0;
}

VLIB_CLI_COMMAND (hss_test_cache_relocation_command, static) = {
  .path = "test http static cache relocation",
  .short_help = "test http static cache relocation",
  .function = hss_test_cache_relocation_command_fn,
};
#endif

static clib_error_t *
hss_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  hss_main_t *hsm = &hss_main;
  hss_listener_t *l = &hsm->default_listener;
  clib_error_t *error = 0;
  char *uri = 0;
  u64 seg_size;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      if (hsm->app_index != (u32) ~0)
	return clib_error_return (0, "http static server already initialized...");
      clib_memset (l, 0, sizeof (*l));
      goto no_input;
    }

  if (unformat (line_input, "disable"))
    {
      rv = hss_destroy (vm);
      unformat_free (line_input);
      if (rv != 0)
	return clib_error_return (0, "failed to disable server %d", rv);
      return 0;
    }

  if (hsm->app_index != (u32) ~0)
    {
      unformat_free (line_input);
      return clib_error_return (0, "http static server already initialized...");
    }

  clib_memset (l, 0, sizeof (*l));
  hsm->have_default_listener = 0;
  hsm->prealloc_fifos = 0;
  hsm->private_segment_size = 0;
  hsm->fifo_size = 0;

  l->cache_size = 10 << 20;
  l->max_age = HSS_DEFAULT_MAX_AGE;
  l->max_req_body_size = HSS_DEFAULT_MAX_BODY_SIZE;
  l->rx_buff_thresh = HSS_DEFAULT_RX_BUFFER_THRESH;
  l->keepalive_timeout = HSS_DEFAULT_KEEPALIVE_TIMEOUT;
  l->flags = 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      /* Server config */
      if (unformat (line_input, "private-segment-size %U",
		    unformat_memory_size, &seg_size))
	hsm->private_segment_size = seg_size;
      else if (unformat (line_input, "fifo-size %U", unformat_memory_size,
			 &hsm->fifo_size))
	;
      else if (unformat (line_input, "prealloc-fifos %d",
			 &hsm->prealloc_fifos))
	;
      else if (unformat (line_input, "debug %d", &hsm->debug_level))
	;
      else if (unformat (line_input, "debug"))
	hsm->debug_level = 1;
      /* Default listener parameters */
      else if (unformat (line_input, "uri %s", &uri))
	;
      else if (unformat (line_input, "www-root %s", &l->www_root))
	;
      else if (unformat (line_input, "url-handlers"))
	l->enable_url_handlers = 1;
      else if (unformat (line_input, "cache-size %U", unformat_memory_size,
			 &l->cache_size))
	;
      else if (unformat (line_input, "max-age %d", &l->max_age))
	;
      else if (unformat (line_input, "max-req-body-size %U",
			 unformat_memory_size, &l->max_req_body_size))
	;
      else if (unformat (line_input, "rx-buff-thresh %U", unformat_memory_size,
			 &l->rx_buff_thresh))
	;
      else if (unformat (line_input, "keepalive-timeout %d",
			 &l->keepalive_timeout))
	;
      else if (unformat (line_input, "ptr-thresh %U", unformat_memory_size,
			 &l->use_ptr_thresh))
	;
      else if (unformat (line_input, "http1-only"))
	l->flags |= HSS_LISTENER_F_HTTP1_ONLY;
      else if (unformat (line_input, "http3"))
	l->flags |= HSS_LISTENER_F_HTTP3;
      /* Deprecated */
      else if (unformat (line_input, "max-body-size %U", unformat_memory_size,
			 &l->max_req_body_size))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  break;
	}
    }

  unformat_free (line_input);

  if (l->flags & HSS_LISTENER_F_HTTP1_ONLY && l->flags & HSS_LISTENER_F_HTTP3)
    {
      error = clib_error_return (0, "conflicting flags ('http1-only' and 'http3')");
      goto done;
    }

no_input:

  if (error)
    goto done;

  if (l->www_root)
    {
      /* Maintain legacy default uri behavior */
      if (!uri)
	uri = "tcp://0.0.0.0:80";
      if (l->cache_size < (128 << 10))
	{
	  error = clib_error_return (0, "cache-size must be at least 128kb");
	  vec_free (l->www_root);
	  goto done;
	}
    }

  if (uri)
    {
      if (parse_uri (uri, &l->sep))
	{
	  error = clib_error_return (0, "failed to parse uri %s", uri);
	  goto done;
	}
      hsm->have_default_listener = 1;
    }

  if ((rv = hss_create (vm)))
    {
      error = clib_error_return (0, "server_create returned %d", rv);
      vec_free (l->www_root);
    }

done:

  return error;
}

/*?
 * Enable the static http server
 *
 * @cliexpar
 * This command enables the static http server. Listeners can be added later
 * @clistart
 * http static server www-root /tmp/www uri tcp://0.0.0.0/80 cache-size 2m
 * @cliend
 * @cliexcmd{http static server [private-segment-size <nnMG>]
 * [fifo-size <nbytes>] [prealloc-fifos <nn>] [debug <nn>] [uri <uri>]
 * [www-root <path>] [url-handlers] [cache-size <nn>] [max-age <nseconds>]
 * [max-req-body-size <nn>] [rx-buff-thresh <nn>] [keepalive-timeout <nn>]
 * [ptr-thresh <nn>] [http1-only] [http3] [disable]}
?*/
VLIB_CLI_COMMAND (hss_create_command, static) = {
  .path = "http static server",
  .short_help = "http static server [private-segment-size <nnMG>] [fifo-size <nbytes>]\n"
		"[prealloc-fifos <nn>] [debug <nn>] [uri <uri>] [www-root <path>]\n"
		"[url-handlers] [cache-size <nn>] [max-age <nseconds>]\n"
		"[max-req-body-size <nn>] [rx-buff-thresh <nn>] [keepalive-timeout <nn>]\n"
		"[ptr-thresh <nn>] [http1-only] [http3]\n",
  .function = hss_create_command_fn,
};

static clib_error_t *
hss_add_del_listener_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  hss_main_t *hsm = &hss_main;
  clib_error_t *error = 0;
  hss_listener_t _l = {}, *l = &_l;
  u8 is_add = 1;
  char *uri = 0;

  if (!hsm->is_init)
    return clib_error_return (0, "Static server not initialized");

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "No input provided");

  l->cache_size = 10 << 20;
  l->max_age = HSS_DEFAULT_MAX_AGE;
  l->max_req_body_size = HSS_DEFAULT_MAX_BODY_SIZE;
  l->rx_buff_thresh = HSS_DEFAULT_RX_BUFFER_THRESH;
  l->keepalive_timeout = HSS_DEFAULT_KEEPALIVE_TIMEOUT;
  l->flags = 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "uri %s", &uri))
	;
      else if (unformat (line_input, "www-root %s", &l->www_root))
	;
      else if (unformat (line_input, "url-handlers"))
	l->enable_url_handlers = 1;
      else if (unformat (line_input, "cache-size %U", unformat_memory_size,
			 &l->cache_size))
	;
      else if (unformat (line_input, "max-age %d", &l->max_age))
	;
      else if (unformat (line_input, "max-req-body-size %U",
			 unformat_memory_size, &l->max_req_body_size))
	;
      else if (unformat (line_input, "rx-buff-thresh %U", unformat_memory_size,
			 &l->rx_buff_thresh))
	;
      else if (unformat (line_input, "keepalive-timeout %d",
			 &l->keepalive_timeout))
	;
      else if (unformat (line_input, "ptr-thresh %U", unformat_memory_size,
			 &l->use_ptr_thresh))
	;
      else if (unformat (line_input, "http1-only"))
	l->flags |= HSS_LISTENER_F_HTTP1_ONLY;
      else if (unformat (line_input, "http3"))
	l->flags |= HSS_LISTENER_F_HTTP3;
      /* Deprecated */
      else if (unformat (line_input, "max-body-size %U", unformat_memory_size,
			 &l->max_req_body_size))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  break;
	}
    }
  unformat_free (line_input);

  if (l->flags & HSS_LISTENER_F_HTTP1_ONLY && l->flags & HSS_LISTENER_F_HTTP3)
    {
      error = clib_error_return (0, "conflicting flags ('http1-only' and 'http3')");
      goto done;
    }

  if (!uri)
    {
      error = clib_error_return (0, "Must set uri");
      goto done;
    }

  if (parse_uri (uri, &l->sep))
    {
      error = clib_error_return (0, "failed to parse uri %s", uri);
      goto done;
    }

  if (!is_add)
    {
      if (hss_listener_del (l))
	error = clib_error_return (0, "Listener with given endpoint not found");
      goto done;
    }

  if (l->www_root == 0 && !l->enable_url_handlers)
    {
      error = clib_error_return (0, "Must set www-root or url-handlers");
      goto done;
    }

  if (l->cache_size < (128 << 10))
    {
      error = clib_error_return (0, "cache-size must be at least 128kb");
      goto done;
    }

  if (hss_listener_add (l))
    {
      error = clib_error_return (0, "failed to create listener");
      goto done;
    }

done:

  vec_free (l->www_root);
  vec_free (uri);
  return error;
}

/*?
 * Add static http server listener
 *
 * @cliexpar
 * Add a static http server listener. The listener can be used to
 * serve static files from the www-root directory or to handle
 * requests using url handlers. Deleting a listener stops new connections;
 * accepted sessions retain its configuration until they close. Disabling the
 * server terminates accepted sessions and releases their listener resources.
 * @clistart
 * http static listener www-root /tmp/www uri tcp://0.0.0.0/80 cache-size 2m
 * @cliend
 * @cliexcmd{http static listener [uri <uri>] [www-root <path>] [url-handlers]
 * [cache-size <nn>] [max-age <nseconds>] [max-req-body-size <nn>]
 * [rx-buff-thresh <nn>] [keepalive-timeout <nn>] [ptr-thresh <nn>]
 * [http1-only] [http3]}
?*/
VLIB_CLI_COMMAND (hss_add_del_listener_command, static) = {
  .path = "http static listener",
  .short_help = "http static listener [add|del] [uri <uri>] [www-root <path>]\n"
		"[url-handlers] [cache-size <nn>] [max-age <nseconds>]\n"
		"[max-req-body-size <nn>] [rx-buff-thresh <nn>] [keepalive-timeout <nn>]\n"
		"[ptr-thresh <nn>] [http1-only] [http3]\n",
  .function = hss_add_del_listener_command_fn,
};

static u8 *
format_hss_session (u8 *s, va_list *args)
{
  hss_session_t *hs = va_arg (*args, hss_session_t *);
  int __clib_unused verbose = va_arg (*args, int);

  s = format (s, "\n path %s, data length %llu, data_offset %llu",
	      hs->path ? hs->path : (u8 *) "[none]", hs->data_len,
	      hs->data_offset);
  return s;
}

static u8 *
format_hss_listener (u8 *s, va_list *args)
{
  hss_listener_t *l = va_arg (*args, hss_listener_t *);
  int __clib_unused verbose = va_arg (*args, int);

  s = format (s, "listener %d, uri %U:%u, www-root %s, cache-size %U url-handlers %d retiring %d",
	      l->l_index, format_ip46_address, &l->sep.ip, l->sep.is_ip4,
	      clib_net_to_host_u16 (l->sep.port), l->www_root ? (char *) l->www_root : "",
	      format_memory_size, l->cache_size, l->enable_url_handlers, l->retiring);
  return s;
}

static clib_error_t *
hss_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  int verbose = 0, show_cache = 0, show_sessions = 0, show_listeners = 0;
  hss_main_t *hsm = &hss_main;
  u32 l_index = hsm->default_listener_index;

  if (!hsm->is_init)
    return clib_error_return (0, "Static server disabled");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose %d", &verbose))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "cache %u", &l_index))
	show_cache = 1;
      else if (unformat (input, "cache"))
	show_cache = 1;
      else if (unformat (input, "sessions"))
	show_sessions = 1;
      else if (unformat (input, "listeners"))
	show_listeners = 1;
      else
	break;
    }

  if ((show_cache + show_sessions + show_listeners) == 0)
    return clib_error_return (0, "specify one or more of cache, sessions");

  if (show_cache)
    {
      hss_listener_t *l;
      if (l_index == (u32) ~0)
	return clib_error_return (0, "no cache listener selected; specify an index");
      l = hss_listener_get (l_index);
      if (l == 0)
	return clib_error_return (0, "listener %u not found", l_index);
      if (l->cache)
	vlib_cli_output (vm, "%U", format_hss_cache, l->cache, verbose);
      else
	vlib_cli_output (vm, "listener %d has no file cache", l_index);
    }

  if (show_sessions)
    {
      u32 *session_indices = 0;
      hss_session_t *hs;
      int i, j;


      for (i = 0; i < vec_len (hsm->sessions); i++)
	{
	  pool_foreach (hs, hsm->sessions[i])
            vec_add1 (session_indices, hs - hsm->sessions[i]);

	  for (j = 0; j < vec_len (session_indices); j++)
	    {
	      vlib_cli_output (
		vm, "%U", format_hss_session,
		pool_elt_at_index (hsm->sessions[i], session_indices[j]),
		verbose);
	    }
	  vec_reset_length (session_indices);
	}
      vec_free (session_indices);
    }

  if (show_listeners)
    {
      hss_listener_t *l;
      pool_foreach (l, hsm->listeners)
	{
	  vlib_cli_output (vm, "%U", format_hss_listener, l, verbose);
	}
    }
  return 0;
}

/*?
 * Display static http server cache statistics
 *
 * @cliexpar
 * This command shows the contents of the static http server cache.
 * Cache commands use the default listener unless an index is supplied.
 * @clistart
 * show http static server
 * @cliend
 * @cliexcmd{show http static server sessions cache [<index>] [verbose [nn]]}
?*/
VLIB_CLI_COMMAND (hss_show_command, static) = {
  .path = "show http static server",
  .short_help = "show http static server [sessions] [cache [<index>]] [listeners] "
		"[verbose [<nn>]]",
  .function = hss_show_command_fn,
};

static clib_error_t *
hss_clear_cache_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  hss_main_t *hsm = &hss_main;
  u32 busy_items = 0, l_index = hsm->default_listener_index;
  hss_listener_t *l;

  if (!hsm->is_init)
    return clib_error_return (0, "Static server disabled");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "index %u", &l_index))
	;
      else
	{
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, input);
	}
    }

  if (l_index == (u32) ~0)
    return clib_error_return (0, "no cache listener selected; specify an index");
  l = hss_listener_get (l_index);
  if (l == 0)
    return clib_error_return (0, "listener %u not found", l_index);

  if (l->cache)
    busy_items = hss_cache_clear (l->cache);

  if (busy_items > 0)
    vlib_cli_output (vm, "Note: %d busy items still in cache...", busy_items);
  else
    vlib_cli_output (vm, "Cache cleared...");
  return 0;
}

/*?
 * Clear the static http server cache, to force the server to
 * reload content from backing files
 *
 * @cliexpar
 * This command clears the default listener's cache unless an index is supplied.
 * @clistart
 * clear http static cache
 * @cliend
 * @cliexcmd{clear http static cache [index <index>]}
?*/
VLIB_CLI_COMMAND (clear_hss_cache_command, static) = {
  .path = "clear http static cache",
  .short_help = "clear http static cache [index <index>]",
  .function = hss_clear_cache_command_fn,
};

static clib_error_t *
hss_main_init (vlib_main_t *vm)
{
  hss_main_t *hsm = &hss_main;

  hsm->app_index = ~0;
  hsm->default_listener_index = ~0;
  hsm->vlib_main = vm;

  /* Set up file extension to mime type index map */
  hsm->mime_type_indices_by_file_extensions =
    hash_create_string (0, sizeof (uword));

#define _(def, ext, str)                                                      \
  hash_set_mem (hsm->mime_type_indices_by_file_extensions, ext,               \
		HTTP_CONTENT_##def);
  foreach_http_content_type;
#undef _

  return 0;
}

VLIB_INIT_FUNCTION (hss_main_init);
