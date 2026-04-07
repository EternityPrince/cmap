#include "cmaper/scan/internal/detail_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cmaper/scan/heartbeat.h"

static int cmaper_scan_detail_stage_sort_key(cmaper_scan_detail_stage_t stage) {
  switch (stage) {
  case CMAPER_SCAN_DETAIL_STAGE_QUEUED:
    return 0;
  case CMAPER_SCAN_DETAIL_STAGE_DIRECT:
    return 1;
  case CMAPER_SCAN_DETAIL_STAGE_PROBE:
    return 2;
  case CMAPER_SCAN_DETAIL_STAGE_ENRICHMENT:
    return 3;
  case CMAPER_SCAN_DETAIL_STAGE_DONE:
    return 4;
  case CMAPER_SCAN_DETAIL_STAGE_DEGRADED:
    return 5;
  case CMAPER_SCAN_DETAIL_STAGE_FAILED:
    return 6;
  }

  return 7;
}

static const char *
cmaper_scan_detail_stage_name(cmaper_scan_detail_stage_t stage) {
  switch (stage) {
  case CMAPER_SCAN_DETAIL_STAGE_QUEUED:
    return "queued";
  case CMAPER_SCAN_DETAIL_STAGE_DIRECT:
    return "direct";
  case CMAPER_SCAN_DETAIL_STAGE_PROBE:
    return "probe";
  case CMAPER_SCAN_DETAIL_STAGE_ENRICHMENT:
    return "enrich";
  case CMAPER_SCAN_DETAIL_STAGE_DONE:
    return "done";
  case CMAPER_SCAN_DETAIL_STAGE_DEGRADED:
    return "degraded";
  case CMAPER_SCAN_DETAIL_STAGE_FAILED:
    return "failed";
  }

  return "queued";
}

static const char *
cmaper_scan_detail_stage_color(cmaper_scan_detail_stage_t stage) {
  switch (stage) {
  case CMAPER_SCAN_DETAIL_STAGE_QUEUED:
    return "\033[0;37m";
  case CMAPER_SCAN_DETAIL_STAGE_DIRECT:
  case CMAPER_SCAN_DETAIL_STAGE_PROBE:
    return "\033[0;36m";
  case CMAPER_SCAN_DETAIL_STAGE_ENRICHMENT:
    return "\033[0;34m";
  case CMAPER_SCAN_DETAIL_STAGE_DONE:
    return "\033[0;32m";
  case CMAPER_SCAN_DETAIL_STAGE_DEGRADED:
    return "\033[0;33m";
  case CMAPER_SCAN_DETAIL_STAGE_FAILED:
    return "\033[0;31m";
  }

  return "";
}

static bool
cmaper_scan_detail_stage_is_terminal(cmaper_scan_detail_stage_t stage) {
  return stage == CMAPER_SCAN_DETAIL_STAGE_DONE ||
         stage == CMAPER_SCAN_DETAIL_STAGE_DEGRADED ||
         stage == CMAPER_SCAN_DETAIL_STAGE_FAILED;
}

static long long cmaper_scan_detail_progress_elapsed_seconds(
    const cmaper_scan_detail_host_progress_t *host, long long now_ms) {
  long long end_ms;

  if (host == NULL || !host->started || host->started_ms <= 0) {
    return 0;
  }

  end_ms = now_ms;
  if (host->finished && host->finished_ms > 0) {
    end_ms = host->finished_ms;
  }
  if (end_ms < host->started_ms) {
    return 0;
  }
  return (end_ms - host->started_ms) / 1000LL;
}

static bool cmaper_scan_detail_progress_host_before(
    const cmaper_scan_detail_progress_state_t *state, size_t left_index,
    size_t right_index) {
  int left_rank;
  int right_rank;
  const char *left_ip;
  const char *right_ip;
  int ip_cmp;

  if (state == NULL || state->hosts == NULL) {
    return false;
  }

  left_rank = cmaper_scan_detail_stage_sort_key(state->hosts[left_index].stage);
  right_rank =
      cmaper_scan_detail_stage_sort_key(state->hosts[right_index].stage);
  if (left_rank != right_rank) {
    return left_rank < right_rank;
  }

  left_ip = state->hosts[left_index].ip[0] != '\0' ? state->hosts[left_index].ip
                                                   : "(unknown)";
  right_ip = state->hosts[right_index].ip[0] != '\0'
                 ? state->hosts[right_index].ip
                 : "(unknown)";
  ip_cmp = strcmp(left_ip, right_ip);
  if (ip_cmp != 0) {
    return ip_cmp < 0;
  }

  return left_index < right_index;
}

static void cmaper_scan_detail_progress_build_sorted_indices(
    const cmaper_scan_detail_progress_state_t *state, size_t *indices) {
  size_t i;

  if (state == NULL || indices == NULL) {
    return;
  }

  for (i = 0; i < state->host_count; ++i) {
    indices[i] = i;
  }

  for (i = 1; i < state->host_count; ++i) {
    size_t key = indices[i];
    size_t j = i;

    while (j > 0 && !cmaper_scan_detail_progress_host_before(
                        state, indices[j - 1], key)) {
      indices[j] = indices[j - 1];
      j -= 1U;
    }
    indices[j] = key;
  }
}

void cmaper_scan_detail_progress_mark_stage(
    cmaper_scan_detail_progress_state_t *state, size_t index,
    cmaper_scan_detail_stage_t stage) {
  long long now_ms;

  if (state == NULL || state->hosts == NULL || index >= state->host_count) {
    return;
  }

  now_ms = cmaper_scan_now_ms();
  pthread_mutex_lock(&state->lock);
  if (!state->hosts[index].started) {
    state->hosts[index].started = true;
    state->hosts[index].started_ms = now_ms;
  }
  state->hosts[index].stage = stage;
  if (cmaper_scan_detail_stage_is_terminal(stage) &&
      !state->hosts[index].finished) {
    state->hosts[index].finished = true;
    state->hosts[index].finished_ms = now_ms;
  }
  pthread_mutex_unlock(&state->lock);
}

void cmaper_scan_detail_progress_set_open_ports(
    cmaper_scan_detail_progress_state_t *state, size_t index,
    size_t open_ports) {
  if (state == NULL || state->hosts == NULL || index >= state->host_count) {
    return;
  }

  pthread_mutex_lock(&state->lock);
  state->hosts[index].open_ports_known = true;
  state->hosts[index].open_ports = open_ports;
  pthread_mutex_unlock(&state->lock);
}

void cmaper_scan_detail_progress_set_scripts(
    cmaper_scan_detail_progress_state_t *state, size_t index,
    size_t scripts_count) {
  if (state == NULL || state->hosts == NULL || index >= state->host_count) {
    return;
  }

  pthread_mutex_lock(&state->lock);
  state->hosts[index].scripts_known = true;
  state->hosts[index].scripts_count = scripts_count;
  pthread_mutex_unlock(&state->lock);
}

static void cmaper_scan_detail_progress_render_dynamic(
    cmaper_scan_detail_progress_state_t *state, const size_t *sorted_indices,
    char spinner, size_t queued, size_t running, size_t done, size_t degraded,
    size_t failed, long long now_ms) {
  FILE *stream;
  size_t i;
  bool use_color;

  if (state == NULL || state->request == NULL ||
      state->request->logger == NULL) {
    return;
  }

  stream = state->request->logger->stream != NULL
               ? state->request->logger->stream
               : stderr;
  use_color = state->request->logger->use_color;

  if (state->rendered_lines > 0) {
    fprintf(stream, "\033[%zuA", state->rendered_lines);
  }
  fputs("\033[J", stream);

  fprintf(stream,
          "scan/detail-progress [%c] queued=%zu running=%zu done=%zu "
          "degraded=%zu failed=%zu\n",
          spinner, queued, running, done, degraded, failed);
  fputs("+-----------------+------------+------------+---------------+---------"
        "+\n",
        stream);
  fputs("| ip              | stage      | ports-open | scripts(-sC)  | elapsed "
        "|\n",
        stream);
  fputs("+-----------------+------------+------------+---------------+---------"
        "+\n",
        stream);

  for (i = 0; i < state->host_count; ++i) {
    size_t host_index = sorted_indices != NULL ? sorted_indices[i] : i;
    const char *stage_name;
    const char *stage_color;
    char ports_text[24];
    char scripts_text[24];
    long long elapsed_seconds = 0;

    if (state->hosts[host_index].open_ports_known) {
      snprintf(ports_text, sizeof(ports_text), "%zu",
               state->hosts[host_index].open_ports);
    } else {
      snprintf(ports_text, sizeof(ports_text), "-");
    }

    if (state->hosts[host_index].scripts_known) {
      snprintf(scripts_text, sizeof(scripts_text), "%zu",
               state->hosts[host_index].scripts_count);
    } else {
      snprintf(scripts_text, sizeof(scripts_text), "-");
    }

    stage_name = cmaper_scan_detail_stage_name(state->hosts[host_index].stage);
    stage_color =
        cmaper_scan_detail_stage_color(state->hosts[host_index].stage);
    elapsed_seconds = cmaper_scan_detail_progress_elapsed_seconds(
        &state->hosts[host_index], now_ms);

    if (use_color) {
      fprintf(
          stream, "| %-15s | %s%-10s\033[0m | %-10s | %-13s | %6llds |\n",
          state->hosts[host_index].ip[0] != '\0' ? state->hosts[host_index].ip
                                                 : "(unknown)",
          stage_color, stage_name, ports_text, scripts_text, elapsed_seconds);
    } else {
      fprintf(stream, "| %-15s | %-10s | %-10s | %-13s | %6llds |\n",
              state->hosts[host_index].ip[0] != '\0'
                  ? state->hosts[host_index].ip
                  : "(unknown)",
              stage_name, ports_text, scripts_text, elapsed_seconds);
    }
  }
  fputs("+-----------------+------------+------------+---------------+---------"
        "+\n",
        stream);

  fflush(stream);
  state->rendered_lines = state->host_count + 5U;
}

static void
cmaper_scan_detail_progress_emit(cmaper_scan_detail_progress_state_t *state) {
  static const char spinner_frames[] = {'|', '/', '-', '\\'};
  size_t queued = 0;
  size_t running = 0;
  size_t done = 0;
  size_t degraded = 0;
  size_t failed = 0;
  size_t i;
  long long now_ms;
  char spinner;
  size_t *sorted_indices = NULL;

  if (state == NULL || state->request == NULL ||
      state->request->logger == NULL || state->hosts == NULL) {
    return;
  }

  now_ms = cmaper_scan_now_ms();

  pthread_mutex_lock(&state->lock);
  spinner = spinner_frames[state->spinner_index % (sizeof(spinner_frames) /
                                                   sizeof(spinner_frames[0]))];
  state->spinner_index += 1U;

  for (i = 0; i < state->host_count; ++i) {
    switch (state->hosts[i].stage) {
    case CMAPER_SCAN_DETAIL_STAGE_QUEUED:
      queued += 1U;
      break;
    case CMAPER_SCAN_DETAIL_STAGE_DIRECT:
    case CMAPER_SCAN_DETAIL_STAGE_PROBE:
    case CMAPER_SCAN_DETAIL_STAGE_ENRICHMENT:
      running += 1U;
      break;
    case CMAPER_SCAN_DETAIL_STAGE_DONE:
      done += 1U;
      break;
    case CMAPER_SCAN_DETAIL_STAGE_DEGRADED:
      degraded += 1U;
      break;
    case CMAPER_SCAN_DETAIL_STAGE_FAILED:
      failed += 1U;
      break;
    }
  }

  if (state->host_count > 0) {
    sorted_indices = malloc(state->host_count * sizeof(*sorted_indices));
    if (sorted_indices != NULL) {
      cmaper_scan_detail_progress_build_sorted_indices(state, sorted_indices);
    }
  }

  if (state->dynamic_render) {
    cmaper_scan_detail_progress_render_dynamic(state, sorted_indices, spinner,
                                               queued, running, done, degraded,
                                               failed, now_ms);
  } else {
    cmaper_log(state->request->logger, CMAPER_LOG_INFO,
               "scan/detail-progress [%c] queued=%zu running=%zu done=%zu "
               "degraded=%zu failed=%zu",
               spinner, queued, running, done, degraded, failed);
    cmaper_log(state->request->logger, CMAPER_LOG_INFO,
               "scan/detail-progress | ip | stage | ports-open | scripts(-sC) "
               "| elapsed |");
    for (i = 0; i < state->host_count; ++i) {
      size_t host_index = sorted_indices != NULL ? sorted_indices[i] : i;
      char ports_text[24];
      char scripts_text[24];
      long long elapsed_seconds = 0;

      if (state->hosts[host_index].open_ports_known) {
        snprintf(ports_text, sizeof(ports_text), "%zu",
                 state->hosts[host_index].open_ports);
      } else {
        snprintf(ports_text, sizeof(ports_text), "-");
      }

      if (state->hosts[host_index].scripts_known) {
        snprintf(scripts_text, sizeof(scripts_text), "%zu",
                 state->hosts[host_index].scripts_count);
      } else {
        snprintf(scripts_text, sizeof(scripts_text), "-");
      }

      elapsed_seconds = cmaper_scan_detail_progress_elapsed_seconds(
          &state->hosts[host_index], now_ms);

      cmaper_log(state->request->logger, CMAPER_LOG_INFO,
                 "scan/detail-progress | %s | %s | %s | %s | %llds |",
                 state->hosts[host_index].ip[0] != '\0'
                     ? state->hosts[host_index].ip
                     : "(unknown)",
                 cmaper_scan_detail_stage_name(state->hosts[host_index].stage),
                 ports_text, scripts_text, elapsed_seconds);
    }
  }

  free(sorted_indices);
  pthread_mutex_unlock(&state->lock);
}

void *cmaper_scan_detail_progress_thread(void *arg) {
  cmaper_scan_detail_progress_state_t *state =
      (cmaper_scan_detail_progress_state_t *)arg;
  long long next_emit_ms;

  if (state == NULL) {
    return NULL;
  }

  next_emit_ms = cmaper_scan_now_ms() + CMAPER_SCAN_DETAIL_PROGRESS_INTERVAL_MS;
  while (true) {
    struct timespec delay;
    long long now_ms;
    bool should_stop = false;

    delay.tv_sec = 0;
    delay.tv_nsec = CMAPER_SCAN_DETAIL_PROGRESS_SLEEP_NS;
    (void)nanosleep(&delay, NULL);

    pthread_mutex_lock(&state->lock);
    should_stop = state->stop_requested;
    pthread_mutex_unlock(&state->lock);
    if (should_stop) {
      break;
    }

    now_ms = cmaper_scan_now_ms();
    if (now_ms >= next_emit_ms) {
      cmaper_scan_detail_progress_emit(state);
      next_emit_ms = now_ms + CMAPER_SCAN_DETAIL_PROGRESS_INTERVAL_MS;
    }
  }

  return NULL;
}

void cmaper_scan_detail_progress_shutdown(
    cmaper_scan_detail_progress_state_t *state, bool *thread_started,
    pthread_t *thread, bool emit_final_snapshot) {
  if (state == NULL || thread_started == NULL || thread == NULL) {
    return;
  }

  if (*thread_started && state->lock_initialized) {
    pthread_mutex_lock(&state->lock);
    state->stop_requested = true;
    pthread_mutex_unlock(&state->lock);
    pthread_join(*thread, NULL);
    *thread_started = false;
    if (emit_final_snapshot) {
      cmaper_scan_detail_progress_emit(state);
    }
  }

  if (state->lock_initialized) {
    pthread_mutex_destroy(&state->lock);
    state->lock_initialized = false;
  }

  if (state->hosts != NULL) {
    free(state->hosts);
    state->hosts = NULL;
  }
  state->host_count = 0;
  state->request = NULL;
  state->stop_requested = false;
}
