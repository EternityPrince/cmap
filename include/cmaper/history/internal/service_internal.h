#ifndef CMAPER_HISTORY_INTERNAL_SERVICE_INTERNAL_H
#define CMAPER_HISTORY_INTERNAL_SERVICE_INTERNAL_H

#include <stdbool.h>
#include <stdio.h>

#include <sqlite3.h>

#include "cmaper/history/alerts.h"
#include "cmaper/history/delete.h"
#include "cmaper/history/diff.h"
#include "cmaper/history/query.h"
#include "cmaper/history/render.h"
#include "cmaper/history/service.h"

static inline void cmaper_history_copy_string(char *out, size_t out_cap,
                                              const char *value) {
  if (out == NULL || out_cap == 0) {
    return;
  }

  out[0] = '\0';
  if (value == NULL) {
    return;
  }

  (void)snprintf(out, out_cap, "%s", value);
}

cmaper_err_t
cmaper_history_run_delete_session(const cmaper_cli_config_t *config,
                                  const cmaper_runtime_paths_t *paths,
                                  FILE *report_stream);

cmaper_err_t cmaper_history_run_delete_all(const cmaper_cli_config_t *config,
                                           const cmaper_runtime_paths_t *paths,
                                           FILE *report_stream);

sqlite3_int64 cmaper_history_resolve_filter_device_id(sqlite3 *db,
                                                      const char *device_token,
                                                      bool *out_has_filter,
                                                      bool *out_found);

cmaper_err_t cmaper_history_run_sessions(
    sqlite3 *db, bool db_available, const cmaper_cli_config_t *config,
    FILE *report_stream, const cmaper_history_render_options_t *render_options);

cmaper_err_t cmaper_history_run_session_detail(
    sqlite3 *db, bool db_available, const cmaper_cli_config_t *config,
    FILE *report_stream, const cmaper_history_render_options_t *render_options);

cmaper_err_t cmaper_history_run_devices(
    sqlite3 *db, bool db_available, const cmaper_cli_config_t *config,
    FILE *report_stream, const cmaper_history_render_options_t *render_options);

cmaper_err_t cmaper_history_run_device(
    sqlite3 *db, bool db_available, const cmaper_cli_config_t *config,
    FILE *report_stream, const cmaper_history_render_options_t *render_options);

cmaper_err_t cmaper_history_run_timeline(
    sqlite3 *db, bool db_available, const cmaper_cli_config_t *config,
    FILE *report_stream, const cmaper_history_render_options_t *render_options);

cmaper_err_t
cmaper_history_run_diff(sqlite3 *db, bool db_available,
                        const cmaper_cli_config_t *config, FILE *report_stream,
                        const cmaper_history_render_options_t *render_options,
                        bool summary_only);

cmaper_err_t cmaper_history_run_posture(
    sqlite3 *db, bool db_available, const cmaper_cli_config_t *config,
    FILE *report_stream, const cmaper_history_render_options_t *render_options);

#endif
