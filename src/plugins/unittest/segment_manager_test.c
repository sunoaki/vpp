#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/session/session.h>
#include <vnet/session/segment_manager.h>
#include <vnet/session/application.h>

#define SEG_MGR_TEST_I(_cond, _comment, _args...)               \
({                                                              \
  int _evald = (_cond);                                         \
  if (!(_evald)) {                                              \
    fformat(stderr, "FAIL:%d: " _comment "\n",                  \
            __LINE__, ##_args);                                 \
  } else {                                                      \
    fformat(stderr, "PASS:%d: " _comment "\n",                  \
            __LINE__, ##_args);                                 \
  }                                                             \
  _evald;                                                       \
})

#define SEG_MGR_TEST(_cond, _comment, _args...)                 \
{                                                               \
    if (!SEG_MGR_TEST_I(_cond, _comment, ##_args)) {            \
        return 1;                                               \
    }                                                           \
}

#define ST_DBG(_comment, _args...)                              \
    fformat(stderr,  _comment "\n",  ##_args);                  \

#define SEGMENT_MANAGER_GET_INDEX_FROM_HANDLE(x) (x >> 32)

/* placeholder callback functions */
static void
placeholder_session_reset_callback (session_t * s)
{
  clib_warning ("called...");
}

static int
placeholder_session_connected_callback (u32 app_index, u32 api_context,
					session_t * s, session_error_t err)
{
  clib_warning ("called...");
  return 0;
}

static int
placeholder_add_segment_callback (u32 client_index, u64 segment_handle)
{
  clib_warning ("called...");
  return 0;
}

static int
placeholder_del_segment_callback (u32 client_index, u64 segment_handle)
{
  clib_warning ("called...");
  return 0;
}

static void
placeholder_session_disconnect_callback (session_t * s)
{
  clib_warning ("called...");
}

static int
placeholder_session_accept_callback (session_t * s)
{
  clib_warning ("called...");
  return 0;
}

static int
placeholder_server_rx_callback (session_t * s)
{
  clib_warning ("called...");
  return -1;
}

static session_cb_vft_t placeholder_session_cbs = {
  .session_reset_callback = placeholder_session_reset_callback,
  .session_connected_callback = placeholder_session_connected_callback,
  .session_accept_callback = placeholder_session_accept_callback,
  .session_disconnect_callback = placeholder_session_disconnect_callback,
  .builtin_app_rx_callback = placeholder_server_rx_callback,
  .add_segment_callback = placeholder_add_segment_callback,
  .del_segment_callback = placeholder_del_segment_callback,
};

static char *states_str[] = {
#define _(sym,str) str,
  foreach_segment_mem_status
#undef _
};

static u32 size_4KB = 4 << 10;
static u32 size_8KB = 8 << 10;
static u32 size_12KB = 12 << 10;
static u32 size_16KB = 16 << 10;
static u32 size_20KB = 20 << 10;
static u32 size_32KB = 32 << 10;
static u32 size_52KB = 52 << 10;
static u32 size_64KB = 64 << 10;
static u32 size_128KB = 128 << 10;
static u32 size_1MB = 1 << 20;
static u32 size_2MB = 2 << 20;


static int
segment_manager_test_pressure_1 (vlib_main_t * vm, unformat_input_t * input)
{
  int rv;
  segment_manager_t *sm;
  fifo_segment_t *fs0, *fs;
  svm_fifo_t *rx_fifo, *tx_fifo;
  uword app_seg_size = size_2MB;
  u32 fifo_size = size_128KB;
  u64 options[APP_OPTIONS_N_OPTIONS];
  u8 data[size_128KB];

  memset (&options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "segment_manager_test_pressure_1"),
  };

  attach_args.options[APP_OPTIONS_SEGMENT_SIZE] = app_seg_size;
  attach_args.options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  attach_args.options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  attach_args.options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  rv = vnet_application_attach (&attach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_attach %d", rv);

  sm =
    segment_manager_get (SEGMENT_MANAGER_GET_INDEX_FROM_HANDLE
			 (attach_args.segment_handle));
  SEG_MGR_TEST ((sm != 0), "segment_manager_get %p", sm);

  /* initial status : (0 / 2MB) */
  fs0 = segment_manager_get_segment (sm, 0);
  rv = fifo_segment_get_mem_status (fs0);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);


  /* allocate a fifo : 128KB x2 */
  rv = segment_manager_alloc_session_fifos (sm,
					    vlib_get_thread_index (),
					    &rx_fifo, &tx_fifo);
  SEG_MGR_TEST ((rv == 0), "segment_manager_alloc_session_fifos %d", rv);

  svm_fifo_set_size (rx_fifo, size_1MB);
  svm_fifo_set_size (tx_fifo, size_1MB);

  fs = segment_manager_get_segment (sm, rx_fifo->segment_index);
  SEG_MGR_TEST ((fs == fs0), "fs %p", fs);

  /* fill fifos (but not add chunks) */
  svm_fifo_enqueue (rx_fifo, fifo_size - 1, data);
  svm_fifo_enqueue (tx_fifo, fifo_size - 1, data);

  /* 256KB+ / 2048KB+ => ~12% */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* grow fifos */
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);

  /* 7 chunks : ~44% */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* grow fifos */
  svm_fifo_enqueue (tx_fifo, fifo_size, data);
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);

  /* 10 chunks : 61% */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_LOW_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* grow fifos */
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);

  /* 14 chunks : 85% */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_HIGH_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);


  /* shrink fifos */
  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);

  /* 10 chunks : 63% */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_LOW_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);


  /* grow fifos */
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);

  /* 14 chunks : 88% */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_HIGH_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);

  /* 10 chunks : 63% */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_LOW_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* shrink fifos */
  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);

  /* 2 chunks : 12% */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);


  vnet_app_detach_args_t detach_args = {
    .app_index = attach_args.app_index,
    .api_client_index = ~0,
  };
  rv = vnet_application_detach (&detach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_detach %d", rv);

  return 0;
}

static int
segment_manager_test_pressure_2 (vlib_main_t * vm, unformat_input_t * input)
{
  int rv, i;
  segment_manager_t *sm;
  fifo_segment_t *fs0, *fs;
  svm_fifo_t *rx_fifo, *tx_fifo;
  uword app_seg_size = size_2MB;
  u32 fifo_size = size_4KB;
  u64 options[APP_OPTIONS_N_OPTIONS];
  u8 data[size_4KB];

  memset (&options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "segment_manager_test_pressure_2"),
  };

  attach_args.options[APP_OPTIONS_SEGMENT_SIZE] = app_seg_size;
  attach_args.options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  attach_args.options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  attach_args.options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  rv = vnet_application_attach (&attach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_attach %d", rv);

  sm =
    segment_manager_get (SEGMENT_MANAGER_GET_INDEX_FROM_HANDLE
			 (attach_args.segment_handle));
  SEG_MGR_TEST ((sm != 0), "segment_manager_get %p", sm);

  /* initial status : (0 / 2MB) */
  fs0 = segment_manager_get_segment (sm, 0);
  rv = fifo_segment_get_mem_status (fs0);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);


  /* allocate fifos : 4KB x2 */
  rv = segment_manager_alloc_session_fifos (sm,
					    vlib_get_thread_index (),
					    &rx_fifo, &tx_fifo);
  SEG_MGR_TEST ((rv == 0), "segment_manager_alloc_session_fifos %d", rv);

  svm_fifo_set_size (rx_fifo, size_1MB);
  svm_fifo_set_size (tx_fifo, size_1MB);

  /* fill fifos (but not add chunks) */
  svm_fifo_enqueue (rx_fifo, fifo_size - 1, data);
  svm_fifo_enqueue (tx_fifo, fifo_size - 1, data);

  fs = segment_manager_get_segment (sm, rx_fifo->segment_index);

  /* grow fifos */
  for (i = 0; i < 509; ++i)
    {
      svm_fifo_enqueue (rx_fifo, fifo_size, data);
      svm_fifo_enqueue (tx_fifo, fifo_size, data);
    }

  /* 100% of 2MB */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_HIGH_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* this fifo growth is expected to fail */
  rv = svm_fifo_enqueue (rx_fifo, fifo_size, data);
  SEG_MGR_TEST ((rv == SVM_FIFO_EGROW), "svm_fifo_enqueue %d", rv);

  /* shrink fifos */
  for (i = 0; i < 20; ++i)
    {
      svm_fifo_dequeue_drop (rx_fifo, fifo_size);
      svm_fifo_dequeue_drop (tx_fifo, fifo_size);
    }

  /* 489 chunks : 96%, it is high-pressure level
   * but the reached-mem-limit record is not reset
   * so the no-memory state lasts.
   */
  /*
   rv = fifo_segment_get_mem_status (fs);
   SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_MEMORY),
		 "fifo_segment_get_mem_status %s", states_str[rv]);
  */

  /* shrink fifos */
  for (i = 0; i < 133; ++i)
    {
      svm_fifo_dequeue_drop (rx_fifo, fifo_size);
    }

  /* 356 chunks : 70% of 2MB */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_LOW_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* shrink fifos */
  for (i = 0; i < 360; ++i)
    {
      svm_fifo_dequeue_drop (rx_fifo, fifo_size);
      svm_fifo_dequeue_drop (tx_fifo, fifo_size);
    }

  /* 2 chunks : 3% of 2MB */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);


  vnet_app_detach_args_t detach_args = {
    .app_index = attach_args.app_index,
    .api_client_index = ~0,
  };
  rv = vnet_application_detach (&detach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_detach %d", rv);

  return 0;
}

static int
segment_manager_test_fifo_balanced_alloc (vlib_main_t * vm,
					  unformat_input_t * input)
{
  int rv, i, fs_index;
  segment_manager_t *sm;
  fifo_segment_t *fs[4];
  svm_fifo_t *rx_fifo[4], *tx_fifo[4];
  uword app_seg_size = size_2MB;
  u32 fifo_size = size_4KB;
  u64 options[APP_OPTIONS_N_OPTIONS];
  u8 data[size_4KB];

  memset (&options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "segment_manager_test_fifo_balanced_alloc"),
  };

  attach_args.options[APP_OPTIONS_SEGMENT_SIZE] = app_seg_size;
  attach_args.options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  attach_args.options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  attach_args.options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  rv = vnet_application_attach (&attach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_attach %d", rv);

  sm =
    segment_manager_get (SEGMENT_MANAGER_GET_INDEX_FROM_HANDLE
			 (attach_args.segment_handle));
  SEG_MGR_TEST ((sm != 0), "segment_manager_get %p", sm);

  /* initial status : (0 / 2MB) */
  fs[0] = segment_manager_get_segment (sm, 0);
  rv = fifo_segment_get_mem_status (fs[0]);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* allocate fifos : 4KB x2 */
  rv = segment_manager_alloc_session_fifos (sm,
					    vlib_get_thread_index (),
					    &rx_fifo[0], &tx_fifo[0]);
  SEG_MGR_TEST ((rv == 0), "segment_manager_alloc_session_fifos %d", rv);
  SEG_MGR_TEST ((rx_fifo[0]->segment_index == 0),
		"segment_index %d", rx_fifo[0]->segment_index);
  SEG_MGR_TEST ((tx_fifo[0]->segment_index == 0),
		"segment_index %d", tx_fifo[0]->segment_index);

  /* grow fifos */
  svm_fifo_set_size (rx_fifo[0], size_1MB);
  for (i = 0; i < 200; ++i)
    {
      svm_fifo_enqueue (rx_fifo[0], fifo_size, data);
    }

  /* add another 2MB segment */
  fs_index = segment_manager_add_segment (sm, size_2MB, 0);
  SEG_MGR_TEST ((fs_index == 1), "fs_index %d", fs_index);

  /* allocate fifos : 4KB x2
   * expected to be allocated on the newer segment,
   * because the usage of the first segment is high.
   */
  rv = segment_manager_alloc_session_fifos (sm,
					    vlib_get_thread_index (),
					    &rx_fifo[1], &tx_fifo[1]);
  SEG_MGR_TEST ((rv == 0), "segment_manager_alloc_session_fifos %d", rv);
  SEG_MGR_TEST ((rx_fifo[1]->segment_index == 1),
		"segment_index %d", rx_fifo[1]->segment_index);
  SEG_MGR_TEST ((tx_fifo[1]->segment_index == 1),
		"segment_index %d", tx_fifo[1]->segment_index);

  /* allocate fifos : 4KB x2
   * expected to be allocated on the newer segment.
   */
  rv = segment_manager_alloc_session_fifos (sm,
					    vlib_get_thread_index (),
					    &rx_fifo[2], &tx_fifo[2]);
  SEG_MGR_TEST ((rv == 0), "segment_manager_alloc_session_fifos %d", rv);
  SEG_MGR_TEST ((rx_fifo[2]->segment_index == 1),
		"segment_index %d", rx_fifo[2]->segment_index);
  SEG_MGR_TEST ((tx_fifo[2]->segment_index == 1),
		"segment_index %d", tx_fifo[2]->segment_index);

  /* grow fifos, so the usage of the secong segment becomes
   * higher than the first one.
   */
  svm_fifo_set_size (rx_fifo[1], size_1MB);
  for (i = 0; i < 400; ++i)
    {
      svm_fifo_enqueue (rx_fifo[1], fifo_size, data);
    }

  /* allocate fifos : 4KB x2
   * expected to be allocated on the first segment.
   */
  rv = segment_manager_alloc_session_fifos (sm,
					    vlib_get_thread_index (),
					    &rx_fifo[3], &tx_fifo[3]);
  SEG_MGR_TEST ((rv == 0), "segment_manager_alloc_session_fifos %d", rv);
  SEG_MGR_TEST ((rx_fifo[3]->segment_index == 0),
		"segment_index %d", rx_fifo[3]->segment_index);
  SEG_MGR_TEST ((tx_fifo[3]->segment_index == 0),
		"segment_index %d", tx_fifo[3]->segment_index);



  vnet_app_detach_args_t detach_args = {
    .app_index = attach_args.app_index,
    .api_client_index = ~0,
  };
  rv = vnet_application_detach (&detach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_detach %d", rv);

  return 0;
}

/* disabled until fifo tuning and memory pressure are properly working */
__clib_unused static int
segment_manager_test_fifo_ops (vlib_main_t *vm, unformat_input_t *input)
{
  int rv, i;
  segment_manager_t *sm;
  fifo_segment_t *fs;
  svm_fifo_t *rx_fifo, *tx_fifo;
  uword app_seg_size = size_2MB, most_grown = 0;
  u32 fifo_size = size_4KB;
  u32 max_dequeue = 0;
  u64 options[APP_OPTIONS_N_OPTIONS];
  u8 data[size_128KB];

  memset (&options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "segment_manager_test_pressure_1"),
  };

  attach_args.options[APP_OPTIONS_SEGMENT_SIZE] = app_seg_size;
  attach_args.options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  attach_args.options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  attach_args.options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  rv = vnet_application_attach (&attach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_attach %d", rv);

  sm =
    segment_manager_get (SEGMENT_MANAGER_GET_INDEX_FROM_HANDLE
			 (attach_args.segment_handle));
  SEG_MGR_TEST ((sm != 0), "segment_manager_get %p", sm);

  /* initial status : (0 / 2MB) */
  fs = segment_manager_get_segment (sm, 0);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* allocate fifos : 4KB x2 */
  rv = segment_manager_alloc_session_fifos (sm,
					    vlib_get_thread_index (),
					    &rx_fifo, &tx_fifo);
  SEG_MGR_TEST ((rv == 0), "segment_manager_alloc_session_fifos %d", rv);

  /* check the initial fifo size : 4KB */
  rv = svm_fifo_size (rx_fifo);
  SEG_MGR_TEST ((rv == size_4KB), "svm_fifo_size %d", rv);

  /* fill 4KB */
  rv = svm_fifo_enqueue (rx_fifo, size_4KB, data);
  SEG_MGR_TEST ((rv == size_4KB), "svm_fifo_enqueue %d", rv);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == size_4KB), "max_dequeue %u", max_dequeue);

  /* grow the fifo size : 4KB -> 8KB */
  svm_fifo_set_size (rx_fifo, size_8KB);
  rv = svm_fifo_size (rx_fifo);
  SEG_MGR_TEST ((rv == size_8KB), "svm_fifo_size %d", rv);

  /* verify that fifo cannot grow larger than the fifo size */
  /* 4KB + 8KB > 8KB, so only 4KB is queued */
  rv = svm_fifo_enqueue (rx_fifo, size_8KB, data);
  SEG_MGR_TEST ((rv == size_4KB), "svm_fifo_enqueue %d", rv);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == size_8KB), "max_dequeue %u", max_dequeue);

  /* grow the fifo size : 8KB -> 16KB */
  svm_fifo_set_size (rx_fifo, size_16KB);

  /* 8KB + 4KB = 12KB */
  svm_fifo_enqueue (rx_fifo, size_4KB, data);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == size_12KB), "max_dequeue %u", max_dequeue);

  /* grow the fifo size : 16KB -> 32KB */
  svm_fifo_set_size (rx_fifo, size_32KB);

  /* 12KB + 8KB = 20KB */
  svm_fifo_enqueue (rx_fifo, size_8KB, data);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == size_20KB), "max_dequeue %u", max_dequeue);

  /* grow the fifo size : 32KB -> 64KB */
  svm_fifo_set_size (rx_fifo, size_64KB);

  /* 20KB + 32KB = 52KB */
  svm_fifo_enqueue (rx_fifo, size_32KB, data);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == size_52KB), "max_dequeue %u", max_dequeue);

  /* bulk enqueue */
  for (i = 0; i < 55; ++i)
    {
      svm_fifo_set_size (rx_fifo, svm_fifo_size (rx_fifo) + size_32KB);
      svm_fifo_enqueue (rx_fifo, size_32KB, data);
    }
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == (size_52KB + size_32KB * 55)),
		"max_dequeue %u", max_dequeue);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_HIGH_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);
  most_grown = svm_fifo_size (rx_fifo);

  /* dequeue */
  svm_fifo_dequeue_drop (rx_fifo, size_20KB);
  svm_fifo_dequeue_drop (rx_fifo, size_32KB);

  /* bulk dequeue */
  for (i = 0; i < 20; ++i)
    svm_fifo_dequeue_drop (rx_fifo, size_32KB);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == (size_32KB * 35)), "max_dequeue %u",
		max_dequeue);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_LOW_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* bulk dequeue */
  for (i = 0; i < 10; ++i)
    svm_fifo_dequeue_drop (rx_fifo, size_32KB);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == (size_32KB * 25)), "max_dequeue %u",
		max_dequeue);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* bulk enqueue */
  for (i = 0; i < 30; ++i)
    svm_fifo_enqueue (rx_fifo, size_32KB, data);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == (size_32KB * 55)), "max_dequeue %u",
		max_dequeue);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_HIGH_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* bulk dequeue */
  for (i = 0; i < 20; ++i)
    svm_fifo_dequeue_drop (rx_fifo, size_32KB);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == (size_32KB * 35)), "max_dequeue %u",
		max_dequeue);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_LOW_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* bulk dequeue */
  for (i = 0; i < 35; ++i)
    svm_fifo_dequeue_drop (rx_fifo, size_32KB);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == 0), "max_dequeue %u", max_dequeue);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* (virtual) fifo size is still large as it is not updated */
  SEG_MGR_TEST ((rx_fifo->shr->size == most_grown), "rx_fifo->size %u",
		rx_fifo->shr->size);

  vnet_app_detach_args_t detach_args = {
    .app_index = attach_args.app_index,
    .api_client_index = ~0,
  };
  rv = vnet_application_detach (&detach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_detach %d", rv);

  return 0;
}

static int
segment_manager_test_prealloc_hdrs (vlib_main_t * vm,
				    unformat_input_t * input)
{
  u32 fifo_size = size_4KB, prealloc_hdrs, sm_index, fs_index;
  u64 options[APP_OPTIONS_N_OPTIONS];
  uword app_seg_size = size_2MB * 2;
  segment_manager_t *sm;
  fifo_segment_t *fs;
  int rv;

  memset (&options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "segment_manager_test_prealloc_hdrs"),
  };

  prealloc_hdrs = 64;

  attach_args.options[APP_OPTIONS_SEGMENT_SIZE] = app_seg_size;
  attach_args.options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  attach_args.options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  attach_args.options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  attach_args.options[APP_OPTIONS_PREALLOC_FIFO_HDRS] = prealloc_hdrs;

  rv = vnet_application_attach (&attach_args);
  vec_free (attach_args.name);

  SEG_MGR_TEST ((rv == 0), "vnet_application_attach %d", rv);

  segment_manager_parse_segment_handle (attach_args.segment_handle, &sm_index,
					&fs_index);
  sm = segment_manager_get (sm_index);

  SEG_MGR_TEST ((sm != 0), "seg manager is valid", sm);

  fs = segment_manager_get_segment (sm, fs_index);
  SEG_MGR_TEST (fifo_segment_num_free_fifos (fs) == prealloc_hdrs,
		"prealloc should be %u", prealloc_hdrs);

  vnet_app_detach_args_t detach_args = {
    .app_index = attach_args.app_index,
    .api_client_index = ~0,
  };
  rv = vnet_application_detach (&detach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_detach %d", rv);
  return 0;
}

typedef enum
{
  ATTACH_PAIR_SUCCESS,
  ATTACH_RX_HEADER_FAILURE,
  ATTACH_TX_HEADER_FAILURE,
  ATTACH_TX_FIRST_CHUNK_FAILURE,
  ATTACH_TX_LATER_CHUNK_FAILURE,
  ATTACH_N_SCENARIOS,
} attach_test_scenario_t;

typedef struct
{
  segment_manager_t *sm;
  fifo_segment_t *fs;
  svm_fifo_t *rx, *tx, *new_rx, *new_tx;
  svm_fifo_t *held_fifos[2];
  svm_fifo_chunk_t *held_chunks[2];
  svm_fifo_shared_t rx_shared, tx_shared;
  session_t target;
  u8 data[4097], output[4097];
  u8 *private_before, *private_after;
  uword old_vm, new_vm, cached, chunk_bytes, byte_index;
  u32 free_hdrs, free_chunks, active, n_held_fifos, n_held_chunks;
  attach_test_scenario_t scenario;
  u8 mapped, initialized;
} attach_test_t;

static void
segment_manager_test_attach_cleanup (attach_test_t *test)
{
  vec_free (test->private_before);
  vec_free (test->private_after);
  if (test->fs)
    {
      /* Destroy the owned arenas even if an unexpected attach left OLD and NEW
       * sharing a FIFO. Error cleanup must not depend on the failed operation. */
      if (test->initialized)
	fifo_segment_cleanup (test->fs);
      if (test->mapped)
	ssvm_delete (&test->fs->ssvm);
      else
	vec_free (test->fs->ssvm.name);
      pool_put (test->sm->segments, test->fs);
    }
  if (test->sm)
    {
      segment_manager_app_detach (test->sm);
      segment_manager_free (test->sm);
    }
}

static int
segment_manager_test_attach_segment (attach_test_t *test)
{
  fifo_segment_t *fs;
  int rv;

  test->sm = segment_manager_alloc ();
  pool_get_zero (test->sm->segments, fs);
  test->fs = fs;
  fs->ssvm.ssvm_size = 1 << 20;
  fs->ssvm.name = format (0, "attach-abort%c", 0);
  fs->ssvm.requested_va = ~0ULL;
  rv = ssvm_server_init (&fs->ssvm, SSVM_SEGMENT_PRIVATE);
  test->mapped = rv == 0;
  SEG_MGR_TEST (!rv, "create private segment for case %u", test->scenario);
  fs->n_slices = 2;
  fifo_segment_init (fs);
  test->initialized = 1;
  fs->sm_index = segment_manager_index (test->sm);
  fs->fs_index = fs - test->sm->segments;
  test->target.thread_index = 1;
  test->target.session_index = 53;
  return 0;
}

static int
segment_manager_test_attach_pair (attach_test_t *test)
{
  fifo_segment_t *fs = test->fs;

  test->rx = fifo_segment_alloc_fifo_w_slice (fs, 0, 4096, FIFO_SEGMENT_RX_FIFO);
  test->tx = fifo_segment_alloc_fifo_w_slice (fs, 0, 8192, FIFO_SEGMENT_TX_FIFO);
  SEG_MGR_TEST (test->rx && test->tx, "allocate original pair");
  test->rx->vpp_session_index = test->tx->vpp_session_index = 37;
  clib_memset (test->data, 0xa5, sizeof (test->data));
  SEG_MGR_TEST (svm_fifo_enqueue (test->rx, 128, test->data) == 128, "seed RX payload");
  SEG_MGR_TEST (svm_fifo_enqueue (test->tx, sizeof (test->data), test->data) ==
		  sizeof (test->data), "seed two-chunk TX payload");
  SEG_MGR_TEST (f_start_cptr (test->tx)->length == 4096 &&
		  f_start_cptr (test->tx)->next &&
		  !f_cptr (test->tx, f_start_cptr (test->tx)->next)->next,
		"TX has exactly two 4KiB chunks");
  test->new_rx = test->rx;
  test->new_tx = test->tx;
  return 0;
}

static int
segment_manager_test_attach_pressure (attach_test_t *test)
{
  fifo_segment_t *fs = test->fs;
  u32 i;

  SEG_MGR_TEST (!fifo_segment_prealloc_fifo_hdrs (fs, 1, 2),
		"reserve two destination headers");
  SEG_MGR_TEST (!fifo_segment_prealloc_fifo_chunks (fs, 1, 4096, 3),
		"reserve three destination chunks");
  SEG_MGR_TEST (fifo_segment_free_bytes (fs) > 64, "space for bump reservation");
  SEG_MGR_TEST (fifo_segment_alloc (fs, fifo_segment_free_bytes (fs) - 64) != 0,
		"hold remaining bump space");
  SEG_MGR_TEST (fifo_segment_free_bytes (fs) <= 64,
		"bump space cannot supply a header batch or chunk");
  switch (test->scenario)
    {
    case ATTACH_RX_HEADER_FAILURE:
      test->n_held_fifos = 2;
      break;
    case ATTACH_TX_HEADER_FAILURE:
      test->n_held_fifos = 1;
      break;
    case ATTACH_TX_FIRST_CHUNK_FAILURE:
      test->n_held_chunks = 2;
      break;
    case ATTACH_TX_LATER_CHUNK_FAILURE:
      test->n_held_chunks = 1;
      break;
    default:
      break;
    }
  for (i = 0; i < test->n_held_fifos; i++)
    {
      test->held_fifos[i] =
	fifo_segment_alloc_fifo_w_slice (fs, 1, 4096, FIFO_SEGMENT_RX_FIFO);
      SEG_MGR_TEST (test->held_fifos[i] != 0, "hold destination header %u", i);
    }
  for (i = 0; i < test->n_held_chunks; i++)
    {
      test->held_chunks[i] = fifo_segment_alloc_chunk_w_slice (fs, 1, 4096);
      SEG_MGR_TEST (test->held_chunks[i] != 0, "hold destination chunk %u", i);
    }
  SEG_MGR_TEST (fs->h->slices[1].n_fl_chunk_bytes ==
		  (3 - test->n_held_fifos - test->n_held_chunks) * 4096,
		"exact destination chunk availability");
  return 0;
}

static void
segment_manager_test_attach_snapshot (attach_test_t *test)
{
  fifo_segment_t *fs = test->fs;

  test->old_vm = fs->h->slices[0].virtual_mem;
  test->new_vm = fs->h->slices[1].virtual_mem;
  test->cached = fifo_segment_cached_bytes (fs);
  test->chunk_bytes = fifo_segment_fl_chunk_bytes (fs);
  test->free_hdrs = fifo_segment_num_free_fifos (fs);
  test->free_chunks = fifo_segment_num_free_chunks (fs, ~0);
  test->active = fifo_segment_num_fifos (fs);
  test->byte_index = fs->h->byte_index;
  test->private_before = format (0, "%U", format_clib_mem_bulk, fs->slices[1].fifos);
  clib_memcpy (&test->rx_shared, test->rx->shr, sizeof (test->rx_shared));
  clib_memcpy (&test->tx_shared, test->tx->shr, sizeof (test->tx_shared));
}

static int
segment_manager_test_attach_attempt (attach_test_t *test)
{
  fifo_segment_t *fs = test->fs;
  svm_fifo_t *rx = test->rx;
  int rv;

  rv = segment_manager_attach_fifo (&test->new_rx, &test->target);
  if (test->scenario == ATTACH_RX_HEADER_FAILURE)
    {
      SEG_MGR_TEST (rv == -1 && test->new_rx == rx, "first RX attach fails");
      return 0;
    }
  SEG_MGR_TEST (rv == 0 && test->new_rx && test->new_rx != rx, "RX attach succeeds");
  SEG_MGR_TEST (test->new_rx->vpp_sh == test->target.handle &&
		  rx->vpp_session_index == 37 && rx->master_thread_index == 0 &&
		  test->new_rx->shr == rx->shr,
		"new owner published; original private owner preserved");
  SEG_MGR_TEST (svm_fifo_hdr_at_attach (rx) && svm_fifo_chunks_at_attach (rx) &&
		  !svm_fifo_hdr_at_attach (test->new_rx) &&
		  !svm_fifo_chunks_at_attach (test->new_rx), "compensation belongs to old RX");
  SEG_MGR_TEST ((fs->h->slices[1].free_fifos != 0) ==
		  (test->scenario != ATTACH_TX_HEADER_FAILURE) &&
		  fs->h->slices[1].n_fl_chunk_bytes ==
		    (2 - test->n_held_fifos - test->n_held_chunks) * 4096,
		"TX header/first/later chunk branch preconditions");
  rv = segment_manager_attach_fifo (&test->new_tx, &test->target);
  if (test->scenario == ATTACH_PAIR_SUCCESS)
    {
      SEG_MGR_TEST (!rv && test->new_tx && test->new_tx != test->tx,
		    "TX attach succeeds");
      return 0;
    }
  SEG_MGR_TEST (rv == -1 && test->new_tx == test->tx, "TX attach fails");
  segment_manager_abort_fifo_attach (rx, &test->new_rx, 0);
  return 0;
}

static int
segment_manager_test_attach_restored_state (attach_test_t *test)
{
  fifo_segment_t *fs = test->fs;
  svm_fifo_t *rx = test->rx, *tx = test->tx;

  SEG_MGR_TEST (test->new_rx == rx && test->new_tx == tx &&
		  !memcmp (&test->rx_shared, rx->shr, sizeof (test->rx_shared)) &&
		  !memcmp (&test->tx_shared, tx->shr, sizeof (test->tx_shared)),
		"rollback restores pointers and shared metadata");
  SEG_MGR_TEST (!svm_fifo_hdr_at_attach (rx) && !svm_fifo_chunks_at_attach (rx) &&
		  !svm_fifo_hdr_at_attach (tx) && !svm_fifo_chunks_at_attach (tx),
		"rollback clears compensation aliases");
  SEG_MGR_TEST (fs->slices[0].active_fifos == rx && !rx->next && !rx->prev &&
		  fs->slices[1].active_fifos ==
		    (test->n_held_fifos ? test->held_fifos[test->n_held_fifos - 1] : 0),
		"rollback preserves both active lists");
  if (test->n_held_fifos)
    SEG_MGR_TEST (!test->held_fifos[test->n_held_fifos - 1]->prev,
		  "destination list head has no stale predecessor");
  SEG_MGR_TEST (svm_fifo_max_dequeue (rx) == 128 &&
		  !memcmp (test->data, f_start_cptr (rx)->data, 128), "RX payload survives abort");
  SEG_MGR_TEST (svm_fifo_max_dequeue (tx) == sizeof (test->data) &&
		  !memcmp (test->data, f_start_cptr (tx)->data, 4096) &&
		  f_cptr (tx, f_start_cptr (tx)->next)->data[0] == test->data[4096],
		"TX payload survives failure");
  return 0;
}

static int
segment_manager_test_attach_restored_resources (attach_test_t *test)
{
  fifo_segment_t *fs = test->fs;

  SEG_MGR_TEST (fs->h->slices[0].virtual_mem == test->old_vm &&
		  fs->h->slices[1].virtual_mem == test->new_vm &&
		  fifo_segment_cached_bytes (fs) == test->cached &&
		  fifo_segment_fl_chunk_bytes (fs) == test->chunk_bytes &&
		  fifo_segment_num_free_fifos (fs) == test->free_hdrs &&
		  fifo_segment_num_free_chunks (fs, ~0) == test->free_chunks &&
		  fifo_segment_num_fifos (fs) == test->active &&
		  fs->h->byte_index == test->byte_index,
		"rollback restores accounting and all reserved resources");
  test->private_after = format (0, "%U", format_clib_mem_bulk, fs->slices[1].fifos);
  SEG_MGR_TEST (vec_len (test->private_before) == vec_len (test->private_after) &&
		  !memcmp (test->private_before, test->private_after,
			   vec_len (test->private_before)),
		"rollback restores destination private allocator");
  return 0;
}

static void
segment_manager_test_attach_release_held (attach_test_t *test)
{
  u32 i;

  for (i = 0; i < test->n_held_fifos; i++)
    {
      fifo_segment_free_fifo (test->fs, test->held_fifos[i]);
      test->held_fifos[i] = 0;
    }
  for (i = 0; i < test->n_held_chunks; i++)
    {
      fifo_segment_collect_chunk (test->fs, 1, test->held_chunks[i]);
      test->held_chunks[i] = 0;
    }
}

static int
segment_manager_test_attach_success (attach_test_t *test)
{
  fifo_segment_t *fs = test->fs;
  svm_fifo_t *rx = test->new_rx, *tx = test->new_tx;

  SEG_MGR_TEST (rx && tx && rx != test->rx && tx != test->tx,
		"both private FIFOs attached before detach");
  SEG_MGR_TEST (fs->slices[1].active_fifos == rx && !rx->next && !rx->prev &&
		  rx->shr->slice_index == 1 && tx->shr->slice_index == 1,
		"successful migration owns destination list and slices");
  segment_manager_detach_fifo (&test->rx);
  segment_manager_detach_fifo (&test->tx);
  SEG_MGR_TEST (!test->rx && !test->tx && !fs->slices[0].active_fifos &&
		  fs->h->slices[0].virtual_mem == 0 &&
		  fs->h->slices[1].virtual_mem == 12288 && fifo_segment_num_fifos (fs) == 2,
		"normal detach preserves live pair and active count");
  SEG_MGR_TEST (svm_fifo_dequeue (rx, 128, test->output) == 128 &&
		  !memcmp (test->data, test->output, 128), "migrated RX payload");
  SEG_MGR_TEST (svm_fifo_dequeue (tx, sizeof (test->data), test->output) ==
		  sizeof (test->data) && !memcmp (test->data, test->output, sizeof (test->data)),
		"migrated TX payload");
  fifo_segment_free_fifo (fs, rx);
  test->new_rx = 0;
  fifo_segment_free_fifo (fs, tx);
  test->new_tx = 0;
  SEG_MGR_TEST (!fifo_segment_num_fifos (fs) && !fs->slices[1].active_fifos &&
		  !fs->h->slices[1].virtual_mem, "final pair cleanup");
  return 0;
}

static int
segment_manager_test_attach_run (attach_test_t *test)
{
  int rv;

  if ((rv = segment_manager_test_attach_segment (test)) ||
      (rv = segment_manager_test_attach_pair (test)) ||
      (rv = segment_manager_test_attach_pressure (test)))
    return rv;
  segment_manager_test_attach_snapshot (test);
  if ((rv = segment_manager_test_attach_attempt (test)))
    return rv;
  if (test->scenario != ATTACH_PAIR_SUCCESS)
    {
      if ((rv = segment_manager_test_attach_restored_state (test)) ||
	  (rv = segment_manager_test_attach_restored_resources (test)))
	return rv;
    }
  segment_manager_test_attach_release_held (test);
  if (test->scenario != ATTACH_PAIR_SUCCESS)
    {
      SEG_MGR_TEST (!segment_manager_attach_fifo (&test->new_rx, &test->target),
		    "retry RX attach");
      SEG_MGR_TEST (!segment_manager_attach_fifo (&test->new_tx, &test->target),
		    "retry TX attach");
    }
  return segment_manager_test_attach_success (test);
}

static int
segment_manager_test_attach_abort (void)
{
  attach_test_scenario_t scenario;
  int rv;

  for (scenario = ATTACH_PAIR_SUCCESS; scenario < ATTACH_N_SCENARIOS; scenario++)
    {
      attach_test_t test = { .scenario = scenario };
      rv = segment_manager_test_attach_run (&test);
      segment_manager_test_attach_cleanup (&test);
      if (rv)
	return rv;
    }
  return 0;
}

static clib_error_t *
segment_manager_test (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  int res = 0;
  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };

  vnet_session_enable_disable (vm, &args);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "pressure_levels_1"))
	res = segment_manager_test_pressure_1 (vm, input);
      else if (unformat (input, "pressure_levels_2"))
	res = segment_manager_test_pressure_2 (vm, input);
      else if (unformat (input, "alloc"))
	res = segment_manager_test_fifo_balanced_alloc (vm, input);
      else if (unformat (input, "prealloc_hdrs"))
	res = segment_manager_test_prealloc_hdrs (vm, input);
      else if (unformat (input, "attach_abort"))
	res = segment_manager_test_attach_abort ();
      else if (unformat (input, "all"))
	{
	  if ((res = segment_manager_test_attach_abort ()))
	    goto done;
	  if ((res = segment_manager_test_pressure_1 (vm, input)))
	    goto done;
	  if ((res = segment_manager_test_pressure_2 (vm, input)))
	    goto done;
	  if ((res = segment_manager_test_fifo_balanced_alloc (vm, input)))
	    goto done;
	  if ((res = segment_manager_test_prealloc_hdrs (vm, input)))
	    goto done;
	}
      else
	break;
    }

done:
  if (res)
    return clib_error_return (0, "Segment manager unit test failed.");
  return 0;
}

VLIB_CLI_COMMAND (tcp_test_command, static) = {
  .path = "test segment-manager",
  .short_help = "test segment manager [pressure_levels_1]"
		"[pressure_level_2][alloc][fifo_ops][prealloc_hdrs][attach_abort][all]",
  .function = segment_manager_test,
};
