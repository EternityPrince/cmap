#include "cmaper/history/internal/query_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

cmaper_err_t cmaper_history_query_resolve_device(sqlite3 *db,
                                                 const char *device_token,
                                                 sqlite3_int64 *out_device_id) {
  static const char *SQL = "SELECT d.id "
                           "FROM devices d "
                           "WHERE CAST(d.id AS TEXT)=?1 "
                           "   OR lower(d.stable_key)=lower(?1) "
                           "   OR lower(d.fallback_key)=lower(?1) "
                           "   OR "
                           "replace(lower(COALESCE(d.mac_address,'')),'-',':')="
                           "replace(lower(?1),'-',':') "
                           "LIMIT 1;";
  sqlite3_stmt *stmt = NULL;
  cmaper_err_t rc;
  int step_rc;

  if (db == NULL || device_token == NULL || device_token[0] == '\0' ||
      out_device_id == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_device_id = 0;

  rc = cmaper_history_prepare(db, SQL, &stmt);
  if (rc != CMAPER_OK) {
    return rc;
  }
  rc = cmaper_history_bind_text(stmt, 1, device_token);
  if (rc != CMAPER_OK) {
    cmaper_history_finalize(&stmt);
    return rc;
  }

  step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_ROW) {
    *out_device_id = sqlite3_column_int64(stmt, 0);
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

cmaper_err_t cmaper_history_query_devices(
    sqlite3 *db, const cmaper_history_session_ref_t *session_ref, int limit,
    cmaper_history_devices_report_t *out_report) {
  static const char *SQL_TOTAL = "SELECT COUNT(DISTINCT ho.device_id) "
                                 "FROM host_observations ho "
                                 "WHERE ho.session_id=?;";
  static const char *SQL_LIST =
      "SELECT CAST(d.id AS TEXT), d.stable_key, d.fallback_key, "
      "       COALESCE(d.mac_address,''), COALESCE(d.mac_vendor,''), "
      "       COALESCE((SELECT ho2.primary_ip "
      "                 FROM host_observations ho2 "
      "                 WHERE ho2.session_id=?1 AND ho2.device_id=d.id "
      "                 ORDER BY ho2.primary_ip ASC LIMIT 1), ''), "
      "       COALESCE((SELECT ho2.hostname_primary "
      "                 FROM host_observations ho2 "
      "                 WHERE ho2.session_id=?1 AND ho2.device_id=d.id "
      "                 ORDER BY ho2.primary_ip ASC LIMIT 1), ''), "
      "       COALESCE((SELECT ho2.status "
      "                 FROM host_observations ho2 "
      "                 WHERE ho2.session_id=?1 AND ho2.device_id=d.id "
      "                 ORDER BY ho2.primary_ip ASC LIMIT 1), ''), "
      "       COALESCE((SELECT COUNT(*) "
      "                 FROM host_observations ho3 "
      "                 WHERE ho3.session_id=?1 AND ho3.device_id=d.id), 0), "
      "       COALESCE((SELECT COUNT(*) "
      "                 FROM service_observations so "
      "                 JOIN host_observations ho ON "
      "ho.id=so.host_observation_id "
      "                 JOIN ports p ON p.id=so.port_id "
      "                 WHERE ho.session_id=?1 AND ho.device_id=d.id "
      "                   AND so.state='open' AND p.protocol='tcp'), 0), "
      "       COALESCE((SELECT COUNT(*) "
      "                 FROM vulnerability_findings vf "
      "                 JOIN host_observations ho ON "
      "ho.id=vf.host_observation_id "
      "                 WHERE ho.session_id=?1 AND ho.device_id=d.id AND "
      "vf.state='open'), 0), "
      "       COALESCE((SELECT COUNT(*) "
      "                 FROM vulnerability_findings vf "
      "                 JOIN host_observations ho ON "
      "ho.id=vf.host_observation_id "
      "                 WHERE ho.session_id=?1 AND ho.device_id=d.id AND "
      "vf.state='open' "
      "                   AND vf.severity IN ('high','critical')), 0), "
      "       COALESCE((SELECT COUNT(*) "
      "                 FROM management_surfaces ms "
      "                 JOIN host_observations ho ON "
      "ho.id=ms.host_observation_id "
      "                 WHERE ho.session_id=?1 AND ho.device_id=d.id), 0) "
      "FROM devices d "
      "WHERE EXISTS (SELECT 1 FROM host_observations ho WHERE ho.session_id=?1 "
      "AND ho.device_id=d.id) "
      "ORDER BY COALESCE(d.mac_address,''), d.id "
      "LIMIT ?2;";
  sqlite3_stmt *stmt_total = NULL;
  sqlite3_stmt *stmt_list = NULL;
  cmaper_history_buffer_t rows;
  cmaper_err_t rc;
  int step_rc;

  if (db == NULL || session_ref == NULL || out_report == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_history_devices_report_dispose(out_report);
  cmaper_history_devices_report_init(out_report);
  out_report->db_available = true;
  out_report->limit = limit > 0 ? limit : 50;
  cmaper_history_copy_string(out_report->session_id,
                             sizeof(out_report->session_id),
                             session_ref->session_uid);

  if (!session_ref->found || session_ref->id <= 0) {
    return CMAPER_OK;
  }
  out_report->session_found = true;

  rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_device_row_t));
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_history_prepare(db, SQL_TOTAL, &stmt_total);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_history_bind_int64(stmt_total, 1, session_ref->id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  step_rc = sqlite3_step(stmt_total);
  if (step_rc != SQLITE_ROW) {
    rc = CMAPER_ERR_IO;
    goto cleanup;
  }
  out_report->total_devices = cmaper_history_column_size(stmt_total, 0);

  rc = cmaper_history_prepare(db, SQL_LIST, &stmt_list);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_history_bind_int64(stmt_list, 1, session_ref->id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_history_bind_int(stmt_list, 2, out_report->limit);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  while ((step_rc = sqlite3_step(stmt_list)) == SQLITE_ROW) {
    cmaper_history_device_row_t *row =
        (cmaper_history_device_row_t *)cmaper_history_buffer_push(&rows);
    if (row == NULL) {
      rc = CMAPER_ERR_OOM;
      goto cleanup;
    }

    cmaper_history_device_row_init(row);
    cmaper_history_copy_column_text(row->device_id, sizeof(row->device_id),
                                    stmt_list, 0);
    cmaper_history_copy_column_text(row->stable_key, sizeof(row->stable_key),
                                    stmt_list, 1);
    cmaper_history_copy_column_text(row->fallback_key,
                                    sizeof(row->fallback_key), stmt_list, 2);
    cmaper_history_copy_column_text(row->mac_address, sizeof(row->mac_address),
                                    stmt_list, 3);
    cmaper_history_copy_column_text(row->mac_vendor, sizeof(row->mac_vendor),
                                    stmt_list, 4);
    cmaper_history_copy_column_text(row->primary_ip, sizeof(row->primary_ip),
                                    stmt_list, 5);
    cmaper_history_copy_column_text(row->hostname, sizeof(row->hostname),
                                    stmt_list, 6);
    cmaper_history_copy_column_text(row->status, sizeof(row->status), stmt_list,
                                    7);
    row->host_observations = cmaper_history_column_size(stmt_list, 8);
    row->open_tcp_ports = cmaper_history_column_size(stmt_list, 9);
    row->findings_open = cmaper_history_column_size(stmt_list, 10);
    row->findings_high_or_worse = cmaper_history_column_size(stmt_list, 11);
    row->management_surfaces = cmaper_history_column_size(stmt_list, 12);
  }
  if (step_rc != SQLITE_DONE) {
    rc = CMAPER_ERR_IO;
    goto cleanup;
  }

  if (rows.count > 1U) {
    qsort(rows.items, rows.count, sizeof(cmaper_history_device_row_t),
          cmaper_history_device_row_compare);
  }

  out_report->items = (cmaper_history_device_row_t *)rows.items;
  out_report->count = rows.count;
  out_report->truncated = out_report->total_devices > out_report->count;
  rows.items = NULL;
  rc = CMAPER_OK;

cleanup:
  cmaper_history_finalize(&stmt_total);
  cmaper_history_finalize(&stmt_list);
  cmaper_history_buffer_dispose(&rows);
  return rc;
}

typedef struct {
  int *items;
  size_t count;
} cmaper_history_tcp_ports_t;

static void cmaper_history_tcp_ports_dispose(cmaper_history_tcp_ports_t *ports) {
  if (ports == NULL) {
    return;
  }

  if (ports->items != NULL) {
    free(ports->items);
  }
  ports->items = NULL;
  ports->count = 0;
}

static bool cmaper_history_tcp_ports_contains(
    const cmaper_history_tcp_ports_t *ports, int port) {
  size_t i;

  if (ports == NULL || ports->items == NULL) {
    return false;
  }

  for (i = 0; i < ports->count; ++i) {
    if (ports->items[i] == port) {
      return true;
    }
  }
  return false;
}

static cmaper_err_t cmaper_history_query_open_tcp_ports(
    sqlite3 *db, long long host_observation_id,
    cmaper_history_tcp_ports_t *out_ports) {
  static const char *SQL =
      "SELECT p.port_number "
      "FROM service_observations so "
      "JOIN ports p ON p.id=so.port_id "
      "WHERE so.host_observation_id=? "
      "  AND so.state='open' AND p.protocol='tcp' "
      "ORDER BY p.port_number ASC;";
  sqlite3_stmt *stmt = NULL;
  cmaper_err_t rc;
  int step_rc;

  if (db == NULL || out_ports == NULL || host_observation_id <= 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  out_ports->items = NULL;
  out_ports->count = 0;

  rc = cmaper_history_prepare(db, SQL, &stmt);
  if (rc != CMAPER_OK) {
    return rc;
  }
  rc = cmaper_history_bind_int64(stmt, 1, (sqlite3_int64)host_observation_id);
  if (rc != CMAPER_OK) {
    cmaper_history_finalize(&stmt);
    return rc;
  }

  while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
    int port = sqlite3_column_int(stmt, 0);
    int *next;
    if (port <= 0) {
      continue;
    }
    if (out_ports->count > 0 && out_ports->items[out_ports->count - 1U] == port) {
      continue;
    }
    next = (int *)realloc(out_ports->items, (out_ports->count + 1U) * sizeof(int));
    if (next == NULL) {
      cmaper_history_finalize(&stmt);
      cmaper_history_tcp_ports_dispose(out_ports);
      return CMAPER_ERR_OOM;
    }
    out_ports->items = next;
    out_ports->items[out_ports->count] = port;
    out_ports->count += 1U;
  }
  cmaper_history_finalize(&stmt);
  if (step_rc != SQLITE_DONE) {
    cmaper_history_tcp_ports_dispose(out_ports);
    return CMAPER_ERR_IO;
  }

  return CMAPER_OK;
}

static cmaper_err_t cmaper_history_append_device_change_event(
    cmaper_history_device_report_t *report, const char *session_id,
    const char *started_at, const char *event_type, const char *detail) {
  static const size_t CMAPER_HISTORY_CHANGE_EVENT_CAP = 512U;
  cmaper_history_device_change_event_t *next;
  cmaper_history_device_change_event_t *slot;

  if (report == NULL || event_type == NULL || detail == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (report->change_event_count >= CMAPER_HISTORY_CHANGE_EVENT_CAP) {
    report->changes_truncated = true;
    return CMAPER_OK;
  }

  next = (cmaper_history_device_change_event_t *)realloc(
      report->change_events, (report->change_event_count + 1U) *
                                 sizeof(cmaper_history_device_change_event_t));
  if (next == NULL) {
    return CMAPER_ERR_OOM;
  }
  report->change_events = next;
  slot = &report->change_events[report->change_event_count];
  cmaper_history_device_change_event_init(slot);
  cmaper_history_copy_string(slot->session_id, sizeof(slot->session_id), session_id);
  cmaper_history_copy_string(slot->started_at, sizeof(slot->started_at), started_at);
  cmaper_history_copy_string(slot->event_type, sizeof(slot->event_type), event_type);
  cmaper_history_copy_string(slot->detail, sizeof(slot->detail), detail);
  report->change_event_count += 1U;
  return CMAPER_OK;
}

static bool cmaper_history_text_changed(const char *left, const char *right) {
  if (left == NULL) {
    return right != NULL && right[0] != '\0';
  }
  if (right == NULL) {
    return left[0] != '\0';
  }
  return strcmp(left, right) != 0;
}

static cmaper_err_t cmaper_history_build_device_change_events(
    sqlite3 *db, cmaper_history_device_report_t *report) {
  size_t i;
  cmaper_err_t rc = CMAPER_OK;

  if (db == NULL || report == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (report->observation_count < 2U) {
    return CMAPER_OK;
  }

  for (i = 0; i + 1U < report->observation_count; ++i) {
    const cmaper_history_device_observation_row_t *newer = &report->observations[i];
    const cmaper_history_device_observation_row_t *older = &report->observations[i + 1U];
    char detail[CMAPER_HISTORY_DETAIL_CAP];
    long findings_delta;
    cmaper_history_tcp_ports_t newer_ports;
    cmaper_history_tcp_ports_t older_ports;
    size_t j;

    if (cmaper_history_text_changed(older->primary_ip, newer->primary_ip)) {
      (void)snprintf(detail, sizeof(detail), "IP changed: %s -> %s",
                     older->primary_ip[0] != '\0' ? older->primary_ip : "-",
                     newer->primary_ip[0] != '\0' ? newer->primary_ip : "-");
      rc = cmaper_history_append_device_change_event(
          report, newer->session_id, newer->started_at, "ip-changed", detail);
      if (rc != CMAPER_OK) {
        return rc;
      }
    }

    if (cmaper_history_text_changed(older->hostname, newer->hostname)) {
      (void)snprintf(detail, sizeof(detail), "Hostname changed: %s -> %s",
                     older->hostname[0] != '\0' ? older->hostname : "-",
                     newer->hostname[0] != '\0' ? newer->hostname : "-");
      rc = cmaper_history_append_device_change_event(
          report, newer->session_id, newer->started_at, "hostname-changed", detail);
      if (rc != CMAPER_OK) {
        return rc;
      }
    }

    if (cmaper_history_text_changed(older->host_status, newer->host_status)) {
      (void)snprintf(detail, sizeof(detail), "Host status changed: %s -> %s",
                     older->host_status[0] != '\0' ? older->host_status : "-",
                     newer->host_status[0] != '\0' ? newer->host_status : "-");
      rc = cmaper_history_append_device_change_event(
          report, newer->session_id, newer->started_at, "host-status-changed",
          detail);
      if (rc != CMAPER_OK) {
        return rc;
      }
    }

    findings_delta = (long)newer->findings_open - (long)older->findings_open;
    if (findings_delta > 0L) {
      (void)snprintf(detail, sizeof(detail), "Opened findings: +%ld (now %zu)",
                     findings_delta, newer->findings_open);
      rc = cmaper_history_append_device_change_event(
          report, newer->session_id, newer->started_at, "findings-opened", detail);
      if (rc != CMAPER_OK) {
        return rc;
      }
    } else if (findings_delta < 0L) {
      (void)snprintf(detail, sizeof(detail), "Resolved findings: %ld (now %zu)",
                     -findings_delta, newer->findings_open);
      rc = cmaper_history_append_device_change_event(
          report, newer->session_id, newer->started_at, "findings-resolved",
          detail);
      if (rc != CMAPER_OK) {
        return rc;
      }
    }

    memset(&newer_ports, 0, sizeof(newer_ports));
    memset(&older_ports, 0, sizeof(older_ports));
    rc = cmaper_history_query_open_tcp_ports(db, newer->host_observation_id, &newer_ports);
    if (rc != CMAPER_OK) {
      cmaper_history_tcp_ports_dispose(&newer_ports);
      cmaper_history_tcp_ports_dispose(&older_ports);
      return rc;
    }
    rc = cmaper_history_query_open_tcp_ports(db, older->host_observation_id, &older_ports);
    if (rc != CMAPER_OK) {
      cmaper_history_tcp_ports_dispose(&newer_ports);
      cmaper_history_tcp_ports_dispose(&older_ports);
      return rc;
    }

    for (j = 0; j < newer_ports.count; ++j) {
      if (cmaper_history_tcp_ports_contains(&older_ports, newer_ports.items[j])) {
        continue;
      }
      (void)snprintf(detail, sizeof(detail), "Port opened: %d/tcp",
                     newer_ports.items[j]);
      rc = cmaper_history_append_device_change_event(
          report, newer->session_id, newer->started_at, "port-opened", detail);
      if (rc != CMAPER_OK) {
        cmaper_history_tcp_ports_dispose(&newer_ports);
        cmaper_history_tcp_ports_dispose(&older_ports);
        return rc;
      }
    }

    for (j = 0; j < older_ports.count; ++j) {
      if (cmaper_history_tcp_ports_contains(&newer_ports, older_ports.items[j])) {
        continue;
      }
      (void)snprintf(detail, sizeof(detail), "Port closed: %d/tcp",
                     older_ports.items[j]);
      rc = cmaper_history_append_device_change_event(
          report, newer->session_id, newer->started_at, "port-closed", detail);
      if (rc != CMAPER_OK) {
        cmaper_history_tcp_ports_dispose(&newer_ports);
        cmaper_history_tcp_ports_dispose(&older_ports);
        return rc;
      }
    }

    cmaper_history_tcp_ports_dispose(&newer_ports);
    cmaper_history_tcp_ports_dispose(&older_ports);
  }

  return CMAPER_OK;
}

cmaper_err_t cmaper_history_query_device(
    sqlite3 *db, const cmaper_history_session_ref_t *session_ref,
    sqlite3_int64 device_id,
    const cmaper_history_device_query_options_t *options,
    cmaper_history_device_report_t *out_report) {
  static const char *SQL_DEVICE =
      "SELECT d.stable_key, d.fallback_key, COALESCE(d.mac_address,''), "
      "COALESCE(d.mac_vendor,''), "
      "       COALESCE(fs.session_uid,''), COALESCE(ls.session_uid,'') "
      "FROM devices d "
      "LEFT JOIN scan_sessions fs ON fs.id=d.first_seen_session_id "
      "LEFT JOIN scan_sessions ls ON ls.id=d.last_seen_session_id "
      "WHERE d.id=?;";
  static const char *SQL_SELECTED_OBS =
      "SELECT ho.primary_ip, COALESCE(ho.hostname_primary,''), "
      "COALESCE(ho.status,''), "
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
      "WHERE ho.session_id=? AND ho.device_id=? "
      "ORDER BY ho.primary_ip ASC "
      "LIMIT 1;";
  static const char *SQL_IPS =
      "SELECT dip.ip_address, COALESCE(dip.address_type,''), dip.is_current, "
      "       COALESCE(fs.session_uid,''), COALESCE(ls.session_uid,'') "
      "FROM device_ip_addresses dip "
      "LEFT JOIN scan_sessions fs ON fs.id=dip.first_seen_session_id "
      "LEFT JOIN scan_sessions ls ON ls.id=dip.last_seen_session_id "
      "WHERE dip.device_id=? "
      "ORDER BY dip.is_current DESC, dip.ip_address ASC;";
  static const char *SQL_OBSERVATIONS =
      "WITH per_session AS ("
      "  SELECT ho.session_id, MIN(ho.id) AS host_observation_id "
      "  FROM host_observations ho "
      "  WHERE ho.device_id=?1 "
      "  GROUP BY ho.session_id"
      ") "
      "SELECT ps.host_observation_id, s.session_uid, COALESCE(s.started_at,''), "
      "       COALESCE(s.status,''), ho.primary_ip, "
      "       COALESCE(ho.hostname_primary,''), COALESCE(ho.status,''), "
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
      "FROM per_session ps "
      "JOIN host_observations ho ON ho.id=ps.host_observation_id "
      "JOIN scan_sessions s ON s.id=ps.session_id "
      "WHERE s.started_at <= (SELECT started_at FROM scan_sessions WHERE id=?2) "
      "  AND (?3<=0 OR julianday(s.started_at) >= "
      "       julianday((SELECT started_at FROM scan_sessions WHERE id=?2), "
      "                 printf('-%d days', ?3))) "
      "ORDER BY s.started_at DESC, s.id DESC;";
  sqlite3_stmt *stmt_device = NULL;
  sqlite3_stmt *stmt_selected = NULL;
  sqlite3_stmt *stmt_ips = NULL;
  sqlite3_stmt *stmt_observations = NULL;
  cmaper_history_buffer_t ip_rows;
  cmaper_history_buffer_t observation_rows;
  cmaper_err_t rc;
  int step_rc;

  if (db == NULL || session_ref == NULL || out_report == NULL ||
      device_id <= 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  memset(&ip_rows, 0, sizeof(ip_rows));
  memset(&observation_rows, 0, sizeof(observation_rows));

  cmaper_history_device_report_dispose(out_report);
  cmaper_history_device_report_init(out_report);
  out_report->db_available = true;
  out_report->has_window_days = options != NULL && options->has_window_days;
  out_report->window_days = options != NULL ? options->window_days : 0;
  out_report->changes_only = options != NULL && options->changes_only;
  cmaper_history_copy_string(out_report->session_id,
                             sizeof(out_report->session_id),
                             session_ref->session_uid);
  (void)snprintf(out_report->device_id, sizeof(out_report->device_id), "%lld",
                 (long long)device_id);

  if (!session_ref->found || session_ref->id <= 0) {
    return CMAPER_OK;
  }
  out_report->session_found = true;

  rc = cmaper_history_prepare(db, SQL_DEVICE, &stmt_device);
  if (rc != CMAPER_OK) {
    return rc;
  }
  rc = cmaper_history_bind_int64(stmt_device, 1, device_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  step_rc = sqlite3_step(stmt_device);
  if (step_rc == SQLITE_DONE) {
    rc = CMAPER_OK;
    goto cleanup;
  }
  if (step_rc != SQLITE_ROW) {
    rc = CMAPER_ERR_IO;
    goto cleanup;
  }

  out_report->found = true;
  cmaper_history_copy_column_text(
      out_report->stable_key, sizeof(out_report->stable_key), stmt_device, 0);
  cmaper_history_copy_column_text(out_report->fallback_key,
                                  sizeof(out_report->fallback_key), stmt_device,
                                  1);
  cmaper_history_copy_column_text(
      out_report->mac_address, sizeof(out_report->mac_address), stmt_device, 2);
  cmaper_history_copy_column_text(
      out_report->mac_vendor, sizeof(out_report->mac_vendor), stmt_device, 3);
  cmaper_history_copy_column_text(out_report->first_seen_session_id,
                                  sizeof(out_report->first_seen_session_id),
                                  stmt_device, 4);
  cmaper_history_copy_column_text(out_report->last_seen_session_id,
                                  sizeof(out_report->last_seen_session_id),
                                  stmt_device, 5);

  rc = cmaper_history_prepare(db, SQL_SELECTED_OBS, &stmt_selected);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_history_bind_int64(stmt_selected, 1, session_ref->id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_history_bind_int64(stmt_selected, 2, device_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  step_rc = sqlite3_step(stmt_selected);
  if (step_rc == SQLITE_ROW) {
    out_report->selected_observation_found = true;
    cmaper_history_copy_column_text(out_report->selected_primary_ip,
                                    sizeof(out_report->selected_primary_ip),
                                    stmt_selected, 0);
    cmaper_history_copy_column_text(out_report->selected_hostname,
                                    sizeof(out_report->selected_hostname),
                                    stmt_selected, 1);
    cmaper_history_copy_column_text(out_report->selected_status,
                                    sizeof(out_report->selected_status),
                                    stmt_selected, 2);
    out_report->selected_open_tcp_ports =
        cmaper_history_column_size(stmt_selected, 3);
    out_report->selected_findings_open =
        cmaper_history_column_size(stmt_selected, 4);
    out_report->selected_findings_high_or_worse =
        cmaper_history_column_size(stmt_selected, 5);
    out_report->selected_management_surfaces =
        cmaper_history_column_size(stmt_selected, 6);
  } else if (step_rc != SQLITE_DONE) {
    rc = CMAPER_ERR_IO;
    goto cleanup;
  }

  rc = cmaper_history_buffer_init(&ip_rows,
                                  sizeof(cmaper_history_device_ip_row_t));
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_history_prepare(db, SQL_IPS, &stmt_ips);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_history_bind_int64(stmt_ips, 1, device_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  while ((step_rc = sqlite3_step(stmt_ips)) == SQLITE_ROW) {
    cmaper_history_device_ip_row_t *row =
        (cmaper_history_device_ip_row_t *)cmaper_history_buffer_push(&ip_rows);
    if (row == NULL) {
      rc = CMAPER_ERR_OOM;
      goto cleanup;
    }
    cmaper_history_device_ip_row_init(row);
    cmaper_history_copy_column_text(row->ip_address, sizeof(row->ip_address),
                                    stmt_ips, 0);
    cmaper_history_copy_column_text(row->address_type,
                                    sizeof(row->address_type), stmt_ips, 1);
    row->is_current = sqlite3_column_int(stmt_ips, 2) != 0;
    cmaper_history_copy_column_text(row->first_seen_session_id,
                                    sizeof(row->first_seen_session_id),
                                    stmt_ips, 3);
    cmaper_history_copy_column_text(row->last_seen_session_id,
                                    sizeof(row->last_seen_session_id), stmt_ips,
                                    4);
  }
  if (step_rc != SQLITE_DONE) {
    rc = CMAPER_ERR_IO;
    goto cleanup;
  }

  rc = cmaper_history_buffer_init(
      &observation_rows, sizeof(cmaper_history_device_observation_row_t));
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_history_prepare(db, SQL_OBSERVATIONS, &stmt_observations);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_history_bind_int64(stmt_observations, 1, device_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_history_bind_int64(stmt_observations, 2, session_ref->id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_history_bind_int(stmt_observations, 3,
                               options != NULL && options->has_window_days
                                   ? options->window_days
                                   : 0);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  while ((step_rc = sqlite3_step(stmt_observations)) == SQLITE_ROW) {
    cmaper_history_device_observation_row_t *row =
        (cmaper_history_device_observation_row_t *)cmaper_history_buffer_push(
            &observation_rows);
    if (row == NULL) {
      rc = CMAPER_ERR_OOM;
      goto cleanup;
    }
    cmaper_history_device_observation_row_init(row);
    row->host_observation_id = (long long)sqlite3_column_int64(stmt_observations, 0);
    cmaper_history_copy_column_text(row->session_id, sizeof(row->session_id),
                                    stmt_observations, 1);
    cmaper_history_copy_column_text(row->started_at, sizeof(row->started_at),
                                    stmt_observations, 2);
    cmaper_history_copy_column_text(row->status, sizeof(row->status),
                                    stmt_observations, 3);
    cmaper_history_copy_column_text(row->primary_ip, sizeof(row->primary_ip),
                                    stmt_observations, 4);
    cmaper_history_copy_column_text(row->hostname, sizeof(row->hostname),
                                    stmt_observations, 5);
    cmaper_history_copy_column_text(row->host_status, sizeof(row->host_status),
                                    stmt_observations, 6);
    row->open_tcp_ports = cmaper_history_column_size(stmt_observations, 7);
    row->findings_open = cmaper_history_column_size(stmt_observations, 8);
    row->findings_high_or_worse =
        cmaper_history_column_size(stmt_observations, 9);
    row->management_surfaces = cmaper_history_column_size(stmt_observations, 10);
  }
  if (step_rc != SQLITE_DONE) {
    rc = CMAPER_ERR_IO;
    goto cleanup;
  }

  out_report->observations =
      (cmaper_history_device_observation_row_t *)observation_rows.items;
  out_report->observation_count = observation_rows.count;
  observation_rows.items = NULL;

  rc = cmaper_history_build_device_change_events(db, out_report);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  if (ip_rows.count > 1U) {
    qsort(ip_rows.items, ip_rows.count, sizeof(cmaper_history_device_ip_row_t),
          cmaper_history_device_ip_row_compare);
  }

  out_report->ip_addresses = (cmaper_history_device_ip_row_t *)ip_rows.items;
  out_report->ip_address_count = ip_rows.count;
  ip_rows.items = NULL;
  rc = CMAPER_OK;

cleanup:
  cmaper_history_finalize(&stmt_device);
  cmaper_history_finalize(&stmt_selected);
  cmaper_history_finalize(&stmt_ips);
  cmaper_history_finalize(&stmt_observations);
  cmaper_history_buffer_dispose(&ip_rows);
  cmaper_history_buffer_dispose(&observation_rows);
  return rc;
}

cmaper_err_t
cmaper_history_query_host_snapshots(sqlite3 *db, sqlite3_int64 session_id,
                                    cmaper_history_host_snapshot_t **out_items,
                                    size_t *out_count) {
  static const char *SQL_HOSTS =
      "SELECT ho.id, ho.device_id, CAST(ho.device_id AS TEXT), ho.primary_ip, "
      "       COALESCE(ho.mac_address,''), COALESCE(ho.hostname_primary,''), "
      "COALESCE(ho.status,'') "
      "FROM host_observations ho "
      "WHERE ho.session_id=? "
      "ORDER BY ho.primary_ip ASC, ho.id ASC;";
  sqlite3_stmt *stmt_hosts = NULL;
  cmaper_history_buffer_t rows;
  cmaper_err_t rc;
  int step_rc;
  size_t i;

  if (db == NULL || out_items == NULL || out_count == NULL || session_id <= 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_items = NULL;
  *out_count = 0;

  rc =
      cmaper_history_buffer_init(&rows, sizeof(cmaper_history_host_snapshot_t));
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_history_prepare(db, SQL_HOSTS, &stmt_hosts);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_history_bind_int64(stmt_hosts, 1, session_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  while ((step_rc = sqlite3_step(stmt_hosts)) == SQLITE_ROW) {
    cmaper_history_host_snapshot_t *row =
        (cmaper_history_host_snapshot_t *)cmaper_history_buffer_push(&rows);
    if (row == NULL) {
      rc = CMAPER_ERR_OOM;
      goto cleanup;
    }
    cmaper_history_host_snapshot_init(row);
    row->host_observation_id = sqlite3_column_int64(stmt_hosts, 0);
    row->device_db_id = sqlite3_column_int64(stmt_hosts, 1);
    cmaper_history_copy_column_text(row->device_id, sizeof(row->device_id),
                                    stmt_hosts, 2);
    cmaper_history_copy_column_text(row->primary_ip, sizeof(row->primary_ip),
                                    stmt_hosts, 3);
    cmaper_history_copy_column_text(row->mac_address, sizeof(row->mac_address),
                                    stmt_hosts, 4);
    cmaper_history_copy_column_text(row->hostname, sizeof(row->hostname),
                                    stmt_hosts, 5);
    cmaper_history_copy_column_text(row->status, sizeof(row->status),
                                    stmt_hosts, 6);
  }
  if (step_rc != SQLITE_DONE) {
    rc = CMAPER_ERR_IO;
    goto cleanup;
  }

  for (i = 0; i < rows.count; ++i) {
    cmaper_history_host_snapshot_t *snapshot =
        &((cmaper_history_host_snapshot_t *)rows.items)[i];
    rc = cmaper_history_load_ports(db, snapshot->host_observation_id, snapshot);
    if (rc != CMAPER_OK) {
      goto cleanup;
    }
    rc = cmaper_history_load_fingerprints(db, snapshot->host_observation_id,
                                          snapshot);
    if (rc != CMAPER_OK) {
      goto cleanup;
    }
    rc = cmaper_history_load_script_results(db, snapshot->host_observation_id,
                                            snapshot);
    if (rc != CMAPER_OK) {
      goto cleanup;
    }
    rc = cmaper_history_load_findings(db, snapshot->host_observation_id,
                                      snapshot);
    if (rc != CMAPER_OK) {
      goto cleanup;
    }
    rc = cmaper_history_load_surfaces(db, snapshot->host_observation_id,
                                      snapshot);
    if (rc != CMAPER_OK) {
      goto cleanup;
    }
  }

  if (rows.count > 1U) {
    qsort(rows.items, rows.count, sizeof(cmaper_history_host_snapshot_t),
          cmaper_history_snapshot_compare);
  }

  *out_items = (cmaper_history_host_snapshot_t *)rows.items;
  *out_count = rows.count;
  rows.items = NULL;
  rc = CMAPER_OK;

cleanup:
  cmaper_history_finalize(&stmt_hosts);
  if (rc != CMAPER_OK && rows.items != NULL) {
    cmaper_history_host_snapshots_dispose(
        (cmaper_history_host_snapshot_t *)rows.items, rows.count);
    rows.items = NULL;
  }
  cmaper_history_buffer_dispose(&rows);
  return rc;
}
