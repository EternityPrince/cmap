#include "cmaper/scan/detail.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "cmaper/platform/terminal.h"
#include "cmaper/scan/internal/detail_internal.h"

typedef struct {
  const cmaper_scan_detail_request_t *request;
  cmaper_scan_detail_result_t *result;
  cmaper_scan_detail_progress_state_t *progress_state;
  size_t next_index;
  pthread_mutex_t index_lock;
} cmaper_scan_detail_pool_t;

static void *cmaper_scan_detail_worker_entry(void *arg) {
  cmaper_scan_detail_pool_t *pool = (cmaper_scan_detail_pool_t *)arg;

  while (true) {
    size_t index;
    const cmaper_scan_detail_target_t *target;
    cmaper_scan_detail_host_result_t *host_result;

    pthread_mutex_lock(&pool->index_lock);
    index = pool->next_index;
    if (index < pool->request->targets->count) {
      pool->next_index += 1U;
    }
    pthread_mutex_unlock(&pool->index_lock);

    if (index >= pool->request->targets->count) {
      break;
    }

    target = &pool->request->targets->items[index];
    host_result = &pool->result->hosts[index];
    cmaper_scan_detail_execute_for_target(pool->request, target, index,
                                          host_result, pool->progress_state);
  }

  return NULL;
}

void cmaper_scan_detail_result_init(cmaper_scan_detail_result_t *result) {
  if (result == NULL) {
    return;
  }

  result->hosts = NULL;
  result->host_count = 0;
  result->successful_hosts = 0;
  result->failed_hosts = 0;
  result->degraded_hosts = 0;
}

void cmaper_scan_detail_result_dispose(cmaper_scan_detail_result_t *result) {
  if (result == NULL) {
    return;
  }

  if (result->hosts != NULL) {
    free(result->hosts);
    result->hosts = NULL;
  }

  result->host_count = 0;
  result->successful_hosts = 0;
  result->failed_hosts = 0;
  result->degraded_hosts = 0;
}

cmaper_err_t
cmaper_scan_detail_execute(const cmaper_scan_detail_request_t *request,
                           cmaper_scan_detail_result_t *result) {
  pthread_t *threads = NULL;
  pthread_t progress_thread;
  bool progress_thread_started = false;
  cmaper_scan_detail_progress_state_t progress_state;
  size_t thread_count;
  size_t i;
  cmaper_scan_detail_pool_t pool;

  if (request == NULL || request->plan == NULL || request->paths == NULL ||
      request->targets == NULL || request->artifact_policy == NULL ||
      request->logger == NULL || result == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  memset(&progress_thread, 0, sizeof(progress_thread));
  memset(&progress_state, 0, sizeof(progress_state));

  cmaper_scan_detail_result_dispose(result);
  cmaper_scan_detail_result_init(result);

  result->host_count = request->targets->count;
  if (result->host_count == 0) {
    return CMAPER_OK;
  }

  result->hosts = (cmaper_scan_detail_host_result_t *)calloc(
      result->host_count, sizeof(cmaper_scan_detail_host_result_t));
  if (result->hosts == NULL) {
    return CMAPER_ERR_OOM;
  }

  thread_count = (size_t)request->worker_limit;
  if (thread_count == 0) {
    thread_count = 1;
  }
  if (thread_count > result->host_count) {
    thread_count = result->host_count;
  }

  threads = (pthread_t *)calloc(thread_count, sizeof(pthread_t));
  if (threads == NULL) {
    cmaper_scan_detail_result_dispose(result);
    cmaper_scan_detail_result_init(result);
    return CMAPER_ERR_OOM;
  }

  pool.request = request;
  pool.result = result;
  pool.progress_state = NULL;
  pool.next_index = 0;
  if (pthread_mutex_init(&pool.index_lock, NULL) != 0) {
    free(threads);
    cmaper_scan_detail_result_dispose(result);
    cmaper_scan_detail_result_init(result);
    return CMAPER_ERR_INTERNAL;
  }

  if (request->logger->level <= CMAPER_LOG_INFO &&
      cmaper_terminal_is_tty(request->logger->stream)) {
    progress_state.request = request;
    progress_state.host_count = result->host_count;
    progress_state.hosts = (cmaper_scan_detail_host_progress_t *)calloc(
        progress_state.host_count, sizeof(cmaper_scan_detail_host_progress_t));
    if (progress_state.hosts != NULL &&
        pthread_mutex_init(&progress_state.lock, NULL) == 0) {
      progress_state.lock_initialized = true;
      progress_state.dynamic_render = true;
      for (i = 0; i < progress_state.host_count; ++i) {
        snprintf(progress_state.hosts[i].ip, sizeof(progress_state.hosts[i].ip),
                 "%s", request->targets->items[i].ip);
        progress_state.hosts[i].stage = CMAPER_SCAN_DETAIL_STAGE_QUEUED;
      }
      pool.progress_state = &progress_state;

      if (pthread_create(&progress_thread, NULL,
                         cmaper_scan_detail_progress_thread,
                         &progress_state) == 0) {
        progress_thread_started = true;
        cmaper_log(request->logger, CMAPER_LOG_INFO,
                   "scan/detail-progress: live table enabled (interval=%llds, "
                   "heartbeat logs suppressed)",
                   CMAPER_SCAN_DETAIL_PROGRESS_INTERVAL_MS / 1000LL);
      } else {
        pool.progress_state = NULL;
        cmaper_scan_detail_progress_shutdown(
            &progress_state, &progress_thread_started, &progress_thread, false);
      }
    } else {
      if (progress_state.hosts != NULL) {
        free(progress_state.hosts);
        progress_state.hosts = NULL;
      }
    }
  }

  for (i = 0; i < thread_count; ++i) {
    if (pthread_create(&threads[i], NULL, cmaper_scan_detail_worker_entry,
                       &pool) != 0) {
      size_t j;

      for (j = 0; j < i; ++j) {
        pthread_join(threads[j], NULL);
      }
      cmaper_scan_detail_progress_shutdown(
          &progress_state, &progress_thread_started, &progress_thread, false);
      pthread_mutex_destroy(&pool.index_lock);
      free(threads);
      cmaper_scan_detail_result_dispose(result);
      cmaper_scan_detail_result_init(result);
      return CMAPER_ERR_INTERNAL;
    }
  }

  for (i = 0; i < thread_count; ++i) {
    pthread_join(threads[i], NULL);
  }

  cmaper_scan_detail_progress_shutdown(
      &progress_state, &progress_thread_started, &progress_thread, true);

  pthread_mutex_destroy(&pool.index_lock);
  free(threads);

  for (i = 0; i < result->host_count; ++i) {
    cmaper_scan_detail_host_result_t *host = &result->hosts[i];

    if (host->success) {
      result->successful_hosts += 1U;
      if (host->used_probe_xml_as_final ||
          (host->enrichment_attempted && !host->enrichment_success)) {
        result->degraded_hosts += 1U;
        cmaper_log(request->logger, CMAPER_LOG_WARN,
                   "scan/detail[%s]: degraded result (%s)",
                   host->ip[0] != '\0' ? host->ip : "(unknown)",
                   host->message[0] != '\0' ? host->message
                                            : "fallback xml used");
      }
    } else {
      result->failed_hosts += 1U;
      cmaper_log(
          request->logger, CMAPER_LOG_WARN, "scan/detail[%s]: host failed (%s)",
          host->ip[0] != '\0' ? host->ip : "(unknown)",
          host->message[0] != '\0' ? host->message : "no successful xml");
    }
  }

  if (result->failed_hosts > 0) {
    cmaper_log(request->logger, CMAPER_LOG_WARN,
               "scan/detail: %zu hosts failed, %zu succeeded",
               result->failed_hosts, result->successful_hosts);
  } else {
    cmaper_log(request->logger, CMAPER_LOG_OK,
               "scan/detail: all %zu hosts completed successfully",
               result->successful_hosts);
  }

  return CMAPER_OK;
}
