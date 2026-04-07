#include "cmaper/history/internal/service_internal.h"

#include <stdio.h>

cmaper_err_t
cmaper_history_run_diff(sqlite3 *db, bool db_available,
                        const cmaper_cli_config_t *config, FILE *report_stream,
                        const cmaper_history_render_options_t *render_options,
                        bool summary_only) {
  cmaper_history_diff_report_t report;
  cmaper_history_session_ref_t from_ref;
  cmaper_history_session_ref_t to_ref;
  cmaper_history_host_snapshot_t *from_hosts = NULL;
  cmaper_history_host_snapshot_t *to_hosts = NULL;
  size_t from_count = 0;
  size_t to_count = 0;
  cmaper_err_t rc = CMAPER_OK;

  cmaper_history_diff_report_init(&report);
  cmaper_history_session_ref_init(&from_ref);
  cmaper_history_session_ref_init(&to_ref);

  if (db_available) {
    report.db_available = true;
    rc = cmaper_history_query_resolve_session(
        db, config->history.from_session_id, &from_ref);
    if (rc != CMAPER_OK) {
      goto cleanup;
    }
    rc = cmaper_history_query_resolve_session(db, config->history.to_session_id,
                                              &to_ref);
    if (rc != CMAPER_OK) {
      goto cleanup;
    }

    report.from_found = from_ref.found;
    report.to_found = to_ref.found;
    if (from_ref.found) {
      cmaper_history_copy_string(report.from_session_id,
                                 sizeof(report.from_session_id),
                                 from_ref.session_uid);
    } else {
      cmaper_history_copy_string(report.from_session_id,
                                 sizeof(report.from_session_id),
                                 config->history.from_session_id);
    }
    if (to_ref.found) {
      cmaper_history_copy_string(report.to_session_id,
                                 sizeof(report.to_session_id),
                                 to_ref.session_uid);
    } else {
      cmaper_history_copy_string(report.to_session_id,
                                 sizeof(report.to_session_id),
                                 config->history.to_session_id);
    }

    if (from_ref.found && to_ref.found) {
      rc = cmaper_history_query_host_snapshots(db, from_ref.id, &from_hosts,
                                               &from_count);
      if (rc != CMAPER_OK) {
        goto cleanup;
      }
      rc = cmaper_history_query_host_snapshots(db, to_ref.id, &to_hosts,
                                               &to_count);
      if (rc != CMAPER_OK) {
        goto cleanup;
      }

      rc = cmaper_history_diff_build(from_hosts, from_count, to_hosts, to_count,
                                     &report);
      if (rc != CMAPER_OK) {
        goto cleanup;
      }
      rc = cmaper_history_alerts_build_for_diff(&report);
      if (rc != CMAPER_OK) {
        goto cleanup;
      }
    }
  } else {
    report.db_available = false;
    cmaper_history_copy_string(report.from_session_id,
                               sizeof(report.from_session_id),
                               config->history.from_session_id);
    cmaper_history_copy_string(report.to_session_id,
                               sizeof(report.to_session_id),
                               config->history.to_session_id);
  }

  cmaper_history_render_diff(report_stream, render_options, &report,
                             summary_only);
  rc = CMAPER_OK;

cleanup:
  if (from_hosts != NULL) {
    cmaper_history_host_snapshots_dispose(from_hosts, from_count);
  }
  if (to_hosts != NULL) {
    cmaper_history_host_snapshots_dispose(to_hosts, to_count);
  }
  cmaper_history_diff_report_dispose(&report);
  return rc;
}
