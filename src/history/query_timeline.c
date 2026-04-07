#include "cmaper/history/internal/query_internal.h"

#include <stdio.h>
#include <string.h>

static cmaper_err_t cmaper_history_query_timeline_presence(
    sqlite3 *db, sqlite3_int64 session_id, sqlite3_int64 device_id,
    bool *out_present, char *out_ip, size_t out_ip_cap, char *out_status,
    size_t out_status_cap) {
  static const char *SQL = "SELECT ho.primary_ip, COALESCE(ho.status,'') "
                           "FROM host_observations ho "
                           "WHERE ho.session_id=? AND ho.device_id=? "
                           "ORDER BY ho.primary_ip ASC "
                           "LIMIT 1;";
  sqlite3_stmt *stmt = NULL;
  cmaper_err_t rc;
  int step_rc;

  if (db == NULL || out_present == NULL || out_ip == NULL ||
      out_status == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_present = false;
  out_ip[0] = '\0';
  out_status[0] = '\0';

  rc = cmaper_history_prepare(db, SQL, &stmt);
  if (rc != CMAPER_OK) {
    return rc;
  }
  rc = cmaper_history_bind_int64(stmt, 1, session_id);
  if (rc != CMAPER_OK) {
    cmaper_history_finalize(&stmt);
    return rc;
  }
  rc = cmaper_history_bind_int64(stmt, 2, device_id);
  if (rc != CMAPER_OK) {
    cmaper_history_finalize(&stmt);
    return rc;
  }

  step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_ROW) {
    *out_present = true;
    cmaper_history_copy_column_text(out_ip, out_ip_cap, stmt, 0);
    cmaper_history_copy_column_text(out_status, out_status_cap, stmt, 1);
    cmaper_history_finalize(&stmt);
    return CMAPER_OK;
  }
  if (step_rc == SQLITE_DONE) {
    cmaper_history_finalize(&stmt);
    return CMAPER_OK;
  }

  cmaper_history_finalize(&stmt);
  return CMAPER_ERR_IO;
}

cmaper_err_t cmaper_history_query_posture_counters(
    sqlite3 *db, sqlite3_int64 session_id, sqlite3_int64 device_id,
    cmaper_history_posture_counters_t *out_counters) {
  static const char *SQL =
      "WITH host_scope AS ("
      "  SELECT ho.id, ho.device_id, COALESCE(ho.status,'') AS status "
      "  FROM host_observations ho "
      "  WHERE ho.session_id=?1 AND (?2<=0 OR ho.device_id=?2)"
      ") "
      "SELECT "
      "  COALESCE((SELECT COUNT(*) FROM host_scope), 0), "
      "  COALESCE((SELECT COUNT(*) FROM host_scope WHERE lower(status)='up'), "
      "0), "
      "  COALESCE((SELECT COUNT(DISTINCT device_id) FROM host_scope), 0), "
      "  COALESCE((SELECT COUNT(*) "
      "            FROM service_observations so "
      "            JOIN ports p ON p.id=so.port_id "
      "            WHERE so.host_observation_id IN (SELECT id FROM host_scope) "
      "              AND so.state='open' AND p.protocol='tcp'), 0), "
      "  COALESCE((SELECT COUNT(*) "
      "            FROM vulnerability_findings vf "
      "            WHERE vf.host_observation_id IN (SELECT id FROM "
      "host_scope)), 0), "
      "  COALESCE((SELECT COUNT(*) "
      "            FROM vulnerability_findings vf "
      "            WHERE vf.host_observation_id IN (SELECT id FROM host_scope) "
      "              AND vf.state='open'), 0), "
      "  COALESCE((SELECT COUNT(*) "
      "            FROM vulnerability_findings vf "
      "            WHERE vf.host_observation_id IN (SELECT id FROM host_scope) "
      "              AND vf.state='open' AND vf.severity IN "
      "('high','critical')), 0), "
      "  COALESCE((SELECT COUNT(*) "
      "            FROM management_surfaces ms "
      "            WHERE ms.host_observation_id IN (SELECT id FROM "
      "host_scope)), 0), "
      "  COALESCE((SELECT COUNT(DISTINCT ms.host_observation_id) "
      "            FROM management_surfaces ms "
      "            WHERE ms.host_observation_id IN (SELECT id FROM "
      "host_scope)), 0);";
  sqlite3_stmt *stmt = NULL;
  cmaper_err_t rc;
  int step_rc;

  if (db == NULL || out_counters == NULL || session_id <= 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_history_posture_counters_init(out_counters);

  rc = cmaper_history_prepare(db, SQL, &stmt);
  if (rc != CMAPER_OK) {
    return rc;
  }
  rc = cmaper_history_bind_int64(stmt, 1, session_id);
  if (rc != CMAPER_OK) {
    cmaper_history_finalize(&stmt);
    return rc;
  }
  rc = cmaper_history_bind_int64(stmt, 2, device_id);
  if (rc != CMAPER_OK) {
    cmaper_history_finalize(&stmt);
    return rc;
  }

  step_rc = sqlite3_step(stmt);
  if (step_rc != SQLITE_ROW) {
    cmaper_history_finalize(&stmt);
    return CMAPER_ERR_IO;
  }

  out_counters->hosts_total = cmaper_history_column_size(stmt, 0);
  out_counters->hosts_up = cmaper_history_column_size(stmt, 1);
  out_counters->devices_total = cmaper_history_column_size(stmt, 2);
  out_counters->open_tcp_ports = cmaper_history_column_size(stmt, 3);
  out_counters->findings_total = cmaper_history_column_size(stmt, 4);
  out_counters->findings_open = cmaper_history_column_size(stmt, 5);
  out_counters->findings_high_or_worse = cmaper_history_column_size(stmt, 6);
  out_counters->management_surfaces_total = cmaper_history_column_size(stmt, 7);
  out_counters->hosts_with_management_surfaces =
      cmaper_history_column_size(stmt, 8);

  cmaper_history_finalize(&stmt);
  return CMAPER_OK;
}

cmaper_err_t
cmaper_history_query_timeline(sqlite3 *db,
                              const cmaper_history_session_ref_t *anchor_ref,
                              sqlite3_int64 device_id, int limit,
                              cmaper_history_timeline_report_t *out_report) {
  static const char *SQL =
      "SELECT s.id, s.session_uid, s.status, COALESCE(s.started_at,''), "
      "COALESCE(s.completed_at,'') "
      "FROM scan_sessions s "
      "WHERE s.started_at <= (SELECT started_at FROM scan_sessions WHERE "
      "id=?1) "
      "ORDER BY s.started_at DESC, s.id DESC "
      "LIMIT ?2;";
  sqlite3_stmt *stmt = NULL;
  cmaper_history_buffer_t rows;
  cmaper_err_t rc;
  int step_rc;

  if (db == NULL || anchor_ref == NULL || out_report == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_history_timeline_report_dispose(out_report);
  cmaper_history_timeline_report_init(out_report);
  out_report->db_available = true;
  out_report->limit = limit > 0 ? limit : 20;
  out_report->has_device_filter = device_id > 0;
  if (anchor_ref->session_uid[0] != '\0') {
    cmaper_history_copy_string(out_report->anchor_session_id,
                               sizeof(out_report->anchor_session_id),
                               anchor_ref->session_uid);
  }
  if (device_id > 0) {
    (void)snprintf(out_report->device_id, sizeof(out_report->device_id), "%lld",
                   (long long)device_id);
  }

  if (!anchor_ref->found || anchor_ref->id <= 0) {
    return CMAPER_OK;
  }
  out_report->anchor_found = true;

  rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_timeline_row_t));
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_history_prepare(db, SQL, &stmt);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_history_bind_int64(stmt, 1, anchor_ref->id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_history_bind_int(stmt, 2, out_report->limit);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
    cmaper_history_timeline_row_t *row =
        (cmaper_history_timeline_row_t *)cmaper_history_buffer_push(&rows);
    sqlite3_int64 session_id;

    if (row == NULL) {
      rc = CMAPER_ERR_OOM;
      goto cleanup;
    }
    cmaper_history_timeline_row_init(row);

    session_id = sqlite3_column_int64(stmt, 0);
    cmaper_history_copy_column_text(row->session_id, sizeof(row->session_id),
                                    stmt, 1);
    cmaper_history_copy_column_text(row->status, sizeof(row->status), stmt, 2);
    cmaper_history_copy_column_text(row->started_at, sizeof(row->started_at),
                                    stmt, 3);
    cmaper_history_copy_column_text(row->completed_at,
                                    sizeof(row->completed_at), stmt, 4);

    {
      cmaper_history_posture_counters_t counters;
      cmaper_history_posture_counters_init(&counters);
      rc = cmaper_history_query_posture_counters(db, session_id, device_id,
                                                 &counters);
      if (rc != CMAPER_OK) {
        goto cleanup;
      }
      row->hosts_total = counters.hosts_total;
      row->findings_open = counters.findings_open;
      row->findings_high_or_worse = counters.findings_high_or_worse;
      row->management_surfaces = counters.management_surfaces_total;
    }

    if (device_id > 0) {
      rc = cmaper_history_query_timeline_presence(
          db, session_id, device_id, &row->device_present, row->device_ip,
          sizeof(row->device_ip), row->device_status,
          sizeof(row->device_status));
      if (rc != CMAPER_OK) {
        goto cleanup;
      }
    }
  }
  if (step_rc != SQLITE_DONE) {
    rc = CMAPER_ERR_IO;
    goto cleanup;
  }

  out_report->items = (cmaper_history_timeline_row_t *)rows.items;
  out_report->count = rows.count;
  rows.items = NULL;
  rc = CMAPER_OK;

cleanup:
  cmaper_history_finalize(&stmt);
  cmaper_history_buffer_dispose(&rows);
  return rc;
}
