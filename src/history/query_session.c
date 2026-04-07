#include "cmaper/history/internal/query_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static cmaper_err_t
cmaper_history_fill_session_row(sqlite3 *db, sqlite3_int64 session_id,
                                cmaper_history_session_row_t *row,
                                bool *out_found) {
  static const char *SQL =
      "SELECT s.session_uid, s.status, s.target, s.profile, "
      "       COALESCE(s.started_at,''), COALESCE(s.completed_at,''), "
      "       s.detail_targets_total, s.detail_hosts_success, "
      "s.detail_hosts_failed, s.detail_hosts_degraded, "
      "       COALESCE((SELECT COUNT(*) FROM host_observations ho WHERE "
      "ho.session_id=s.id), 0), "
      "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
      "                 JOIN host_observations ho ON "
      "ho.id=vf.host_observation_id "
      "                 WHERE ho.session_id=s.id), 0), "
      "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
      "                 JOIN host_observations ho ON "
      "ho.id=vf.host_observation_id "
      "                 WHERE ho.session_id=s.id AND vf.state='open'), 0), "
      "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
      "                 JOIN host_observations ho ON "
      "ho.id=vf.host_observation_id "
      "                 WHERE ho.session_id=s.id AND vf.state='open' "
      "                   AND vf.severity IN ('high','critical')), 0), "
      "       COALESCE((SELECT COUNT(*) FROM management_surfaces ms "
      "                 JOIN host_observations ho ON "
      "ho.id=ms.host_observation_id "
      "                 WHERE ho.session_id=s.id), 0) "
      "FROM scan_sessions s "
      "WHERE s.id=?;";
  sqlite3_stmt *stmt = NULL;
  cmaper_err_t rc;
  int step_rc;

  if (db == NULL || row == NULL || out_found == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_found = false;
  cmaper_history_session_row_init(row);

  rc = cmaper_history_prepare(db, SQL, &stmt);
  if (rc != CMAPER_OK) {
    return rc;
  }
  rc = cmaper_history_bind_int64(stmt, 1, session_id);
  if (rc != CMAPER_OK) {
    cmaper_history_finalize(&stmt);
    return rc;
  }

  step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_DONE) {
    cmaper_history_finalize(&stmt);
    return CMAPER_OK;
  }
  if (step_rc != SQLITE_ROW) {
    cmaper_history_finalize(&stmt);
    return CMAPER_ERR_IO;
  }

  cmaper_history_copy_column_text(row->session_id, sizeof(row->session_id),
                                  stmt, 0);
  cmaper_history_copy_column_text(row->status, sizeof(row->status), stmt, 1);
  cmaper_history_copy_column_text(row->target, sizeof(row->target), stmt, 2);
  cmaper_history_copy_column_text(row->profile, sizeof(row->profile), stmt, 3);
  cmaper_history_copy_column_text(row->started_at, sizeof(row->started_at),
                                  stmt, 4);
  cmaper_history_copy_column_text(row->completed_at, sizeof(row->completed_at),
                                  stmt, 5);
  row->detail_targets_total = sqlite3_column_int(stmt, 6);
  row->detail_hosts_success = sqlite3_column_int(stmt, 7);
  row->detail_hosts_failed = sqlite3_column_int(stmt, 8);
  row->detail_hosts_degraded = sqlite3_column_int(stmt, 9);
  row->host_count = cmaper_history_column_size(stmt, 10);
  row->findings_total = cmaper_history_column_size(stmt, 11);
  row->findings_open = cmaper_history_column_size(stmt, 12);
  row->findings_high_or_worse = cmaper_history_column_size(stmt, 13);
  row->management_surfaces_total = cmaper_history_column_size(stmt, 14);

  *out_found = true;
  cmaper_history_finalize(&stmt);
  return CMAPER_OK;
}

static void cmaper_history_session_host_set_defaults(
    cmaper_history_session_host_row_t *row) {
  if (row == NULL) {
    return;
  }

  (void)snprintf(row->open_tcp_list, sizeof(row->open_tcp_list), "none");
  (void)snprintf(row->scripts_used, sizeof(row->scripts_used), "none");
  (void)snprintf(row->script_results, sizeof(row->script_results), "none");
  (void)snprintf(row->script_signals, sizeof(row->script_signals), "none");
  (void)snprintf(row->findings_detail, sizeof(row->findings_detail), "none");
  (void)snprintf(row->surfaces_detail, sizeof(row->surfaces_detail), "none");
  row->scripts_used_count = 0U;
  row->script_result_count = 0U;
  row->script_signal_count = 0U;
}

static void cmaper_history_session_host_apply_snapshot(
    cmaper_history_session_host_row_t *row,
    const cmaper_history_host_snapshot_t *snapshot) {
  size_t i;

  if (row == NULL || snapshot == NULL) {
    return;
  }

  cmaper_history_detail_text_clear(row->open_tcp_list,
                                   sizeof(row->open_tcp_list));
  for (i = 0; i < snapshot->port_count; ++i) {
    char token[48];
    (void)snprintf(token, sizeof(token), "%d/%s", snapshot->ports[i].port,
                   snapshot->ports[i].protocol[0] != '\0'
                       ? snapshot->ports[i].protocol
                       : "-");
    cmaper_history_detail_text_append(row->open_tcp_list,
                                      sizeof(row->open_tcp_list), token);
  }
  if (row->open_tcp_list[0] == '\0') {
    (void)snprintf(row->open_tcp_list, sizeof(row->open_tcp_list), "none");
  }

  row->scripts_used_count = snapshot->script_result_count;
  row->script_result_count = snapshot->script_result_count;
  cmaper_history_detail_text_clear(row->scripts_used,
                                   sizeof(row->scripts_used));
  cmaper_history_detail_text_clear(row->script_results,
                                   sizeof(row->script_results));
  for (i = 0; i < snapshot->script_result_count; ++i) {
    char token_used[192];
    char token_result[256];
    char token_target[32];
    char compact_output[96];
    const cmaper_history_script_result_signal_t *script =
        &snapshot->script_results[i];

    if (script->script_id[0] == '\0') {
      continue;
    }

    if (script->has_service_context) {
      (void)snprintf(token_used, sizeof(token_used), "%s@%s/%d",
                     script->script_id, script->protocol, script->port);
    } else {
      (void)snprintf(token_used, sizeof(token_used), "%s", script->script_id);
    }
    cmaper_history_detail_text_append(row->scripts_used,
                                      sizeof(row->scripts_used), token_used);

    cmaper_history_detail_text_compact_copy(
        compact_output, sizeof(compact_output), script->output, 72U);
    if (compact_output[0] == '\0') {
      (void)snprintf(compact_output, sizeof(compact_output), "-");
    }

    if (script->has_service_context) {
      (void)snprintf(token_target, sizeof(token_target), "%s/%d",
                     script->protocol, script->port);
      (void)snprintf(token_result, sizeof(token_result), "%s\t%s\t%s",
                     script->script_id, token_target, compact_output);
    } else {
      (void)snprintf(token_target, sizeof(token_target), "host");
      (void)snprintf(token_result, sizeof(token_result), "%s\t%s\t%s",
                     script->script_id, token_target, compact_output);
    }
    cmaper_history_detail_text_append_line(
        row->script_results, sizeof(row->script_results), token_result);
  }
  if (row->scripts_used[0] == '\0') {
    (void)snprintf(row->scripts_used, sizeof(row->scripts_used), "none");
  }
  if (row->script_results[0] == '\0') {
    (void)snprintf(row->script_results, sizeof(row->script_results), "none");
  }

  row->script_signal_count = snapshot->fingerprint_count;
  cmaper_history_detail_text_clear(row->script_signals,
                                   sizeof(row->script_signals));
  for (i = 0; i < snapshot->fingerprint_count; ++i) {
    char token[160];
    const cmaper_history_fingerprint_signal_t *signal =
        &snapshot->fingerprints[i];
    if (signal->has_service_context) {
      (void)snprintf(token, sizeof(token), "%s@%s/%d=%.*s", signal->kind,
                     signal->protocol, signal->port, 48, signal->value);
    } else {
      (void)snprintf(token, sizeof(token), "%s=%.*s", signal->kind, 48,
                     signal->value);
    }
    cmaper_history_detail_text_append(row->script_signals,
                                      sizeof(row->script_signals), token);
  }
  if (row->script_signals[0] == '\0') {
    (void)snprintf(row->script_signals, sizeof(row->script_signals), "none");
  }

  cmaper_history_detail_text_clear(row->findings_detail,
                                   sizeof(row->findings_detail));
  for (i = 0; i < snapshot->finding_count; ++i) {
    char token[192];
    const cmaper_history_finding_signal_t *finding = &snapshot->findings[i];
    if (finding->has_service_context) {
      (void)snprintf(token, sizeof(token), "%s:%s(%s)@%s/%d", finding->severity,
                     finding->key, finding->state, finding->protocol,
                     finding->port);
    } else {
      (void)snprintf(token, sizeof(token), "%s:%s(%s)", finding->severity,
                     finding->key, finding->state);
    }
    cmaper_history_detail_text_append(row->findings_detail,
                                      sizeof(row->findings_detail), token);
  }
  if (row->findings_detail[0] == '\0') {
    (void)snprintf(row->findings_detail, sizeof(row->findings_detail), "none");
  }

  cmaper_history_detail_text_clear(row->surfaces_detail,
                                   sizeof(row->surfaces_detail));
  for (i = 0; i < snapshot->surface_count; ++i) {
    char token[192];
    const cmaper_history_surface_signal_t *surface = &snapshot->surfaces[i];
    if (surface->has_service_context) {
      (void)snprintf(token, sizeof(token), "%s@%s/%d:%.*s", surface->type,
                     surface->protocol, surface->port, 48, surface->detail);
    } else {
      (void)snprintf(token, sizeof(token), "%s:%.*s", surface->type, 48,
                     surface->detail);
    }
    cmaper_history_detail_text_append(row->surfaces_detail,
                                      sizeof(row->surfaces_detail), token);
  }
  if (row->surfaces_detail[0] == '\0') {
    (void)snprintf(row->surfaces_detail, sizeof(row->surfaces_detail), "none");
  }
}

static void cmaper_history_session_hosts_apply_snapshots(
    cmaper_history_session_host_row_t *rows, size_t row_count,
    const cmaper_history_host_snapshot_t *snapshots, size_t snapshot_count) {
  size_t i;
  size_t j;

  if (rows == NULL || row_count == 0U) {
    return;
  }

  for (i = 0; i < row_count; ++i) {
    const cmaper_history_host_snapshot_t *best = NULL;

    cmaper_history_session_host_set_defaults(&rows[i]);

    for (j = 0; j < snapshot_count; ++j) {
      if (strcmp(rows[i].device_id, snapshots[j].device_id) != 0) {
        continue;
      }
      if (rows[i].primary_ip[0] != '\0' && snapshots[j].primary_ip[0] != '\0' &&
          strcmp(rows[i].primary_ip, snapshots[j].primary_ip) == 0) {
        best = &snapshots[j];
        break;
      }
      if (best == NULL) {
        best = &snapshots[j];
      }
    }

    if (best != NULL) {
      cmaper_history_session_host_apply_snapshot(&rows[i], best);
    }
  }
}

cmaper_err_t
cmaper_history_query_resolve_session(sqlite3 *db, const char *session_token,
                                     cmaper_history_session_ref_t *out_ref) {
  static const char *SQL =
      "SELECT s.id, s.session_uid, s.status, "
      "       COALESCE(s.started_at,''), COALESCE(s.completed_at,'') "
      "FROM scan_sessions s "
      "WHERE s.session_uid=?1 OR CAST(s.id AS TEXT)=?1 "
      "ORDER BY CASE WHEN s.session_uid=?1 THEN 0 ELSE 1 END, s.id DESC "
      "LIMIT 1;";
  sqlite3_stmt *stmt = NULL;
  cmaper_err_t rc;
  int step_rc;

  if (db == NULL || session_token == NULL || session_token[0] == '\0' ||
      out_ref == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_history_session_ref_init(out_ref);

  rc = cmaper_history_prepare(db, SQL, &stmt);
  if (rc != CMAPER_OK) {
    return rc;
  }
  rc = cmaper_history_bind_text(stmt, 1, session_token);
  if (rc != CMAPER_OK) {
    cmaper_history_finalize(&stmt);
    return rc;
  }

  step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_DONE) {
    cmaper_history_finalize(&stmt);
    return CMAPER_OK;
  }
  if (step_rc != SQLITE_ROW) {
    cmaper_history_finalize(&stmt);
    return CMAPER_ERR_IO;
  }

  out_ref->id = sqlite3_column_int64(stmt, 0);
  out_ref->found = out_ref->id > 0;
  cmaper_history_copy_column_text(out_ref->session_uid,
                                  sizeof(out_ref->session_uid), stmt, 1);
  cmaper_history_copy_column_text(out_ref->status, sizeof(out_ref->status),
                                  stmt, 2);
  cmaper_history_copy_column_text(out_ref->started_at,
                                  sizeof(out_ref->started_at), stmt, 3);
  cmaper_history_copy_column_text(out_ref->completed_at,
                                  sizeof(out_ref->completed_at), stmt, 4);

  cmaper_history_finalize(&stmt);
  return CMAPER_OK;
}

cmaper_err_t
cmaper_history_query_sessions(sqlite3 *db, int limit,
                              cmaper_history_sessions_report_t *out_report) {
  static const char *SQL_TOTAL = "SELECT COUNT(*) FROM scan_sessions;";
  static const char *SQL_LIST =
      "SELECT s.session_uid, s.status, s.target, s.profile, "
      "       COALESCE(s.started_at,''), COALESCE(s.completed_at,''), "
      "       s.detail_targets_total, s.detail_hosts_success, "
      "s.detail_hosts_failed, s.detail_hosts_degraded, "
      "       COALESCE((SELECT COUNT(*) FROM host_observations ho WHERE "
      "ho.session_id=s.id), 0), "
      "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
      "                 JOIN host_observations ho ON "
      "ho.id=vf.host_observation_id "
      "                 WHERE ho.session_id=s.id), 0), "
      "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
      "                 JOIN host_observations ho ON "
      "ho.id=vf.host_observation_id "
      "                 WHERE ho.session_id=s.id AND vf.state='open'), 0), "
      "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
      "                 JOIN host_observations ho ON "
      "ho.id=vf.host_observation_id "
      "                 WHERE ho.session_id=s.id AND vf.state='open' "
      "                   AND vf.severity IN ('high','critical')), 0), "
      "       COALESCE((SELECT COUNT(*) FROM management_surfaces ms "
      "                 JOIN host_observations ho ON "
      "ho.id=ms.host_observation_id "
      "                 WHERE ho.session_id=s.id), 0) "
      "FROM scan_sessions s "
      "ORDER BY s.started_at DESC, s.id DESC "
      "LIMIT ?;";
  sqlite3_stmt *stmt_total = NULL;
  sqlite3_stmt *stmt_list = NULL;
  cmaper_history_buffer_t rows;
  cmaper_err_t rc;
  int step_rc;

  if (db == NULL || out_report == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_history_sessions_report_dispose(out_report);
  cmaper_history_sessions_report_init(out_report);
  out_report->db_available = true;
  out_report->limit = limit > 0 ? limit : 20;

  rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_session_row_t));
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_history_prepare(db, SQL_TOTAL, &stmt_total);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  step_rc = sqlite3_step(stmt_total);
  if (step_rc != SQLITE_ROW) {
    rc = CMAPER_ERR_IO;
    goto cleanup;
  }
  out_report->total_sessions = cmaper_history_column_size(stmt_total, 0);

  rc = cmaper_history_prepare(db, SQL_LIST, &stmt_list);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_history_bind_int(stmt_list, 1, out_report->limit);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  while ((step_rc = sqlite3_step(stmt_list)) == SQLITE_ROW) {
    cmaper_history_session_row_t *row =
        (cmaper_history_session_row_t *)cmaper_history_buffer_push(&rows);
    if (row == NULL) {
      rc = CMAPER_ERR_OOM;
      goto cleanup;
    }

    cmaper_history_session_row_init(row);
    cmaper_history_copy_column_text(row->session_id, sizeof(row->session_id),
                                    stmt_list, 0);
    cmaper_history_copy_column_text(row->status, sizeof(row->status), stmt_list,
                                    1);
    cmaper_history_copy_column_text(row->target, sizeof(row->target), stmt_list,
                                    2);
    cmaper_history_copy_column_text(row->profile, sizeof(row->profile),
                                    stmt_list, 3);
    cmaper_history_copy_column_text(row->started_at, sizeof(row->started_at),
                                    stmt_list, 4);
    cmaper_history_copy_column_text(row->completed_at,
                                    sizeof(row->completed_at), stmt_list, 5);
    row->detail_targets_total = sqlite3_column_int(stmt_list, 6);
    row->detail_hosts_success = sqlite3_column_int(stmt_list, 7);
    row->detail_hosts_failed = sqlite3_column_int(stmt_list, 8);
    row->detail_hosts_degraded = sqlite3_column_int(stmt_list, 9);
    row->host_count = cmaper_history_column_size(stmt_list, 10);
    row->findings_total = cmaper_history_column_size(stmt_list, 11);
    row->findings_open = cmaper_history_column_size(stmt_list, 12);
    row->findings_high_or_worse = cmaper_history_column_size(stmt_list, 13);
    row->management_surfaces_total = cmaper_history_column_size(stmt_list, 14);
  }
  if (step_rc != SQLITE_DONE) {
    rc = CMAPER_ERR_IO;
    goto cleanup;
  }

  out_report->items = (cmaper_history_session_row_t *)rows.items;
  out_report->count = rows.count;
  out_report->truncated = out_report->total_sessions > out_report->count;
  rows.items = NULL;
  rc = CMAPER_OK;

cleanup:
  cmaper_history_finalize(&stmt_total);
  cmaper_history_finalize(&stmt_list);
  cmaper_history_buffer_dispose(&rows);
  return rc;
}

cmaper_err_t cmaper_history_query_session_detail(
    sqlite3 *db, const cmaper_history_session_ref_t *session_ref,
    cmaper_history_session_report_t *out_report) {
  static const char *SQL_HOSTS =
      "SELECT CAST(d.id AS TEXT), ho.primary_ip, COALESCE(ho.status,''), "
      "       COALESCE(ho.hostname_primary,''), COALESCE(ho.mac_address,''), "
      "COALESCE(ho.mac_vendor,''), "
      "       COALESCE((SELECT COUNT(*) FROM service_observations so "
      "                 JOIN ports p ON p.id=so.port_id "
      "                 WHERE so.host_observation_id=ho.id AND so.state='open' "
      "AND p.protocol='tcp'), 0), "
      "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
      "                 WHERE vf.host_observation_id=ho.id AND "
      "vf.state='open'), 0), "
      "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
      "                 WHERE vf.host_observation_id=ho.id AND vf.state='open' "
      "                   AND vf.severity IN ('high','critical')), 0), "
      "       COALESCE((SELECT COUNT(*) FROM management_surfaces ms "
      "                 WHERE ms.host_observation_id=ho.id), 0) "
      "FROM host_observations ho "
      "JOIN devices d ON d.id=ho.device_id "
      "WHERE ho.session_id=?;";
  sqlite3_stmt *stmt_hosts = NULL;
  cmaper_history_buffer_t host_rows;
  cmaper_history_host_snapshot_t *snapshots = NULL;
  size_t snapshot_count = 0U;
  cmaper_err_t rc;
  bool found = false;
  int step_rc;

  if (db == NULL || session_ref == NULL || out_report == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_history_session_report_dispose(out_report);
  cmaper_history_session_report_init(out_report);
  out_report->db_available = true;

  if (!session_ref->found || session_ref->id <= 0) {
    return CMAPER_OK;
  }

  rc = cmaper_history_fill_session_row(db, session_ref->id,
                                       &out_report->summary, &found);
  if (rc != CMAPER_OK) {
    return rc;
  }
  if (!found) {
    return CMAPER_OK;
  }

  out_report->found = true;

  rc = cmaper_history_buffer_init(&host_rows,
                                  sizeof(cmaper_history_session_host_row_t));
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_history_prepare(db, SQL_HOSTS, &stmt_hosts);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_history_bind_int64(stmt_hosts, 1, session_ref->id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  while ((step_rc = sqlite3_step(stmt_hosts)) == SQLITE_ROW) {
    cmaper_history_session_host_row_t *row =
        (cmaper_history_session_host_row_t *)cmaper_history_buffer_push(
            &host_rows);
    if (row == NULL) {
      rc = CMAPER_ERR_OOM;
      goto cleanup;
    }

    cmaper_history_session_host_row_init(row);
    cmaper_history_copy_column_text(row->device_id, sizeof(row->device_id),
                                    stmt_hosts, 0);
    cmaper_history_copy_column_text(row->primary_ip, sizeof(row->primary_ip),
                                    stmt_hosts, 1);
    cmaper_history_copy_column_text(row->status, sizeof(row->status),
                                    stmt_hosts, 2);
    cmaper_history_copy_column_text(row->hostname, sizeof(row->hostname),
                                    stmt_hosts, 3);
    cmaper_history_copy_column_text(row->mac_address, sizeof(row->mac_address),
                                    stmt_hosts, 4);
    cmaper_history_copy_column_text(row->mac_vendor, sizeof(row->mac_vendor),
                                    stmt_hosts, 5);
    row->open_tcp_ports = cmaper_history_column_size(stmt_hosts, 6);
    row->findings_open = cmaper_history_column_size(stmt_hosts, 7);
    row->findings_high_or_worse = cmaper_history_column_size(stmt_hosts, 8);
    row->management_surfaces = cmaper_history_column_size(stmt_hosts, 9);
  }
  if (step_rc != SQLITE_DONE) {
    rc = CMAPER_ERR_IO;
    goto cleanup;
  }

  if (host_rows.count > 1U) {
    qsort(host_rows.items, host_rows.count,
          sizeof(cmaper_history_session_host_row_t),
          cmaper_history_session_host_row_compare);
  }

  cmaper_history_session_hosts_apply_snapshots(
      (cmaper_history_session_host_row_t *)host_rows.items, host_rows.count,
      NULL, 0U);
  rc = cmaper_history_query_host_snapshots(db, session_ref->id, &snapshots,
                                           &snapshot_count);
  if (rc == CMAPER_OK) {
    cmaper_history_session_hosts_apply_snapshots(
        (cmaper_history_session_host_row_t *)host_rows.items, host_rows.count,
        snapshots, snapshot_count);
  } else {
    /* Keep base session rows usable even when deep snapshot tables are
     * unavailable. */
    rc = CMAPER_OK;
  }

  out_report->hosts = (cmaper_history_session_host_row_t *)host_rows.items;
  out_report->host_count = host_rows.count;
  host_rows.items = NULL;
  rc = CMAPER_OK;

cleanup:
  cmaper_history_finalize(&stmt_hosts);
  if (snapshots != NULL) {
    cmaper_history_host_snapshots_dispose(snapshots, snapshot_count);
  }
  cmaper_history_buffer_dispose(&host_rows);
  return rc;
}

cmaper_err_t cmaper_history_query_previous_completed_session(
    sqlite3 *db, sqlite3_int64 anchor_session_id,
    cmaper_history_session_ref_t *out_previous) {
  static const char *SQL =
      "SELECT s.id, s.session_uid, s.status, "
      "       COALESCE(s.started_at,''), COALESCE(s.completed_at,'') "
      "FROM scan_sessions s "
      "WHERE s.status='completed' "
      "  AND s.id<>?1 "
      "  AND s.started_at < (SELECT started_at FROM scan_sessions WHERE id=?1) "
      "ORDER BY s.started_at DESC, s.id DESC "
      "LIMIT 1;";
  sqlite3_stmt *stmt = NULL;
  cmaper_err_t rc;
  int step_rc;

  if (db == NULL || out_previous == NULL || anchor_session_id <= 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_history_session_ref_init(out_previous);

  rc = cmaper_history_prepare(db, SQL, &stmt);
  if (rc != CMAPER_OK) {
    return rc;
  }
  rc = cmaper_history_bind_int64(stmt, 1, anchor_session_id);
  if (rc != CMAPER_OK) {
    cmaper_history_finalize(&stmt);
    return rc;
  }

  step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_DONE) {
    cmaper_history_finalize(&stmt);
    return CMAPER_OK;
  }
  if (step_rc != SQLITE_ROW) {
    cmaper_history_finalize(&stmt);
    return CMAPER_ERR_IO;
  }

  out_previous->id = sqlite3_column_int64(stmt, 0);
  out_previous->found = out_previous->id > 0;
  cmaper_history_copy_column_text(out_previous->session_uid,
                                  sizeof(out_previous->session_uid), stmt, 1);
  cmaper_history_copy_column_text(out_previous->status,
                                  sizeof(out_previous->status), stmt, 2);
  cmaper_history_copy_column_text(out_previous->started_at,
                                  sizeof(out_previous->started_at), stmt, 3);
  cmaper_history_copy_column_text(out_previous->completed_at,
                                  sizeof(out_previous->completed_at), stmt, 4);

  cmaper_history_finalize(&stmt);
  return CMAPER_OK;
}
