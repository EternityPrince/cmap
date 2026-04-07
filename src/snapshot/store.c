#include "cmaper/snapshot/store.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "cmaper/platform/fs.h"
#include "cmaper/snapshot/internal/sqlite_internal.h"
#include "cmaper/snapshot/schema.h"
#include "cmaper/snapshot/write.h"

static const char *
cmaper_snapshot_spoof_mode_name(cmaper_scan_spoof_mac_mode_t mode) {
  switch (mode) {
  case CMAPER_SCAN_SPOOF_MAC_OFF:
    return "off";
  case CMAPER_SCAN_SPOOF_MAC_RANDOM:
    return "random";
  case CMAPER_SCAN_SPOOF_MAC_CUSTOM:
    return "custom";
  }

  return "off";
}

static int cmaper_snapshot_bool_to_int(bool value) { return value ? 1 : 0; }

static void cmaper_snapshot_diag_set_sqlite(cmaper_snapshot_diag_t *diag,
                                            const char *field, sqlite3 *db) {
  const char *message = db != NULL ? sqlite3_errmsg(db) : "sqlite error";
  cmaper_snapshot_diag_setf(diag, field, "%s", message);
}

void cmaper_snapshot_diag_clear(cmaper_snapshot_diag_t *diag) {
  if (diag == NULL) {
    return;
  }

  diag->field = NULL;
  diag->message[0] = '\0';
}

void cmaper_snapshot_diag_setf(cmaper_snapshot_diag_t *diag, const char *field,
                               const char *fmt, ...) {
  va_list args;

  cmaper_snapshot_diag_clear(diag);
  if (diag == NULL) {
    return;
  }

  diag->field = field;
  if (fmt == NULL) {
    return;
  }

  va_start(args, fmt);
  vsnprintf(diag->message, sizeof(diag->message), fmt, args);
  va_end(args);
}

void cmaper_snapshot_store_init(cmaper_snapshot_store_t *store) {
  if (store == NULL) {
    return;
  }

  store->enabled = false;
  store->db = NULL;
  store->db_path[0] = '\0';
}

cmaper_err_t cmaper_snapshot_store_open(cmaper_snapshot_store_t *store,
                                        const cmaper_runtime_paths_t *paths,
                                        bool enable_persistence,
                                        cmaper_logger_t *logger,
                                        cmaper_snapshot_diag_t *diag) {
  sqlite3 *db = NULL;
  cmaper_snapshot_schema_diag_t schema_diag;
  cmaper_err_t rc;

  if (store == NULL || paths == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_snapshot_diag_clear(diag);
  cmaper_snapshot_store_close(store);
  cmaper_snapshot_store_init(store);

  if (!enable_persistence) {
    cmaper_log(logger, CMAPER_LOG_INFO,
               "snapshot/store: persistence is disabled (xml-only mode)");
    return CMAPER_OK;
  }

  rc = cmaper_fs_ensure_directory_recursive(paths->db_dir);
  if (rc != CMAPER_OK) {
    cmaper_snapshot_diag_setf(
        diag, "db-dir", "failed to ensure db directory '%s'", paths->db_dir);
    return rc;
  }

  if (sqlite3_open_v2(paths->db_path, &db,
                      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                          SQLITE_OPEN_FULLMUTEX,
                      NULL) != SQLITE_OK) {
    cmaper_snapshot_diag_set_sqlite(diag, "db-open", db);
    if (db != NULL) {
      sqlite3_close(db);
    }
    return CMAPER_ERR_IO;
  }

  if (sqlite3_busy_timeout(db, 5000) != SQLITE_OK) {
    cmaper_snapshot_diag_set_sqlite(diag, "db-open", db);
    sqlite3_close(db);
    return CMAPER_ERR_IO;
  }

  if (sqlite3_exec(db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL) !=
      SQLITE_OK) {
    cmaper_snapshot_diag_set_sqlite(diag, "db-open", db);
    sqlite3_close(db);
    return CMAPER_ERR_IO;
  }

  cmaper_snapshot_schema_diag_clear(&schema_diag);
  rc = cmaper_snapshot_schema_bootstrap(db, &schema_diag);
  if (rc != CMAPER_OK) {
    cmaper_snapshot_diag_setf(
        diag, schema_diag.field != NULL ? schema_diag.field : "schema", "%s",
        schema_diag.message[0] != '\0' ? schema_diag.message
                                       : "schema bootstrap failed");
    sqlite3_close(db);
    return rc;
  }

  store->enabled = true;
  store->db = db;
  snprintf(store->db_path, sizeof(store->db_path), "%s", paths->db_path);
  cmaper_log(logger, CMAPER_LOG_OK, "snapshot/store: ready at '%s'",
             store->db_path);

  return CMAPER_OK;
}

bool cmaper_snapshot_store_is_enabled(const cmaper_snapshot_store_t *store) {
  if (store == NULL) {
    return false;
  }

  return store->enabled && store->db != NULL;
}

void cmaper_snapshot_store_close(cmaper_snapshot_store_t *store) {
  if (store == NULL) {
    return;
  }

  if (store->db != NULL) {
    sqlite3_close(store->db);
    store->db = NULL;
  }

  store->enabled = false;
  store->db_path[0] = '\0';
}

cmaper_err_t
cmaper_snapshot_session_start(cmaper_snapshot_store_t *store,
                              const cmaper_snapshot_session_start_t *request) {
  static const char *SQL =
      "INSERT INTO scan_sessions ("
      "  "
      "session_uid,status,target,profile,exact_ports,no_ping,timing_template,"
      "detail_workers,"
      "  "
      "service_detection,os_detection,sudo,spoof_mac_mode,spoof_mac_value,"
      "traceroute,udp_enrichment,"
      "  started_at,completed_at,failed_at,error_message,discovery_xml_path,"
      "  "
      "detail_targets_total,detail_hosts_success,detail_hosts_failed,detail_"
      "hosts_degraded"
      ") VALUES ("
      "  ?, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
      "  strftime('%Y-%m-%dT%H:%M:%fZ','now'), NULL, NULL, NULL, NULL, 0, 0, "
      "0, 0"
      ")"
      "ON CONFLICT(session_uid) DO UPDATE SET "
      "  status='running',"
      "  target=excluded.target,"
      "  profile=excluded.profile,"
      "  exact_ports=excluded.exact_ports,"
      "  no_ping=excluded.no_ping,"
      "  timing_template=excluded.timing_template,"
      "  detail_workers=excluded.detail_workers,"
      "  service_detection=excluded.service_detection,"
      "  os_detection=excluded.os_detection,"
      "  sudo=excluded.sudo,"
      "  spoof_mac_mode=excluded.spoof_mac_mode,"
      "  spoof_mac_value=excluded.spoof_mac_value,"
      "  traceroute=excluded.traceroute,"
      "  udp_enrichment=excluded.udp_enrichment,"
      "  started_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),"
      "  completed_at=NULL,"
      "  failed_at=NULL,"
      "  error_message=NULL,"
      "  discovery_xml_path=NULL,"
      "  detail_targets_total=0,"
      "  detail_hosts_success=0,"
      "  detail_hosts_failed=0,"
      "  detail_hosts_degraded=0;";
  sqlite3_stmt *stmt = NULL;
  cmaper_err_t rc;

  if (request == NULL || request->session_uid == NULL ||
      request->session_uid[0] == '\0' || request->plan == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (!cmaper_snapshot_store_is_enabled(store)) {
    return CMAPER_OK;
  }

  rc = cmaper_snapshot_sqlite_prepare(store->db, SQL, &stmt);
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_snapshot_sqlite_bind_text(stmt, 1, request->session_uid);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text(stmt, 2, request->plan->target);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text(
      stmt, 3, cmaper_scan_profile_name(request->plan->profile));
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt, 4,
                                                request->plan->exact_ports);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int(
      stmt, 5, cmaper_snapshot_bool_to_int(request->plan->no_ping));
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int(stmt, 6, request->plan->timing_template);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int(stmt, 7, request->plan->detail_workers);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int(
      stmt, 8, cmaper_snapshot_bool_to_int(request->plan->service_detection));
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int(
      stmt, 9, cmaper_snapshot_bool_to_int(request->plan->os_detection));
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int(
      stmt, 10, cmaper_snapshot_bool_to_int(request->plan->sudo));
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text(
      stmt, 11, cmaper_snapshot_spoof_mode_name(request->plan->spoof_mac_mode));
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt, 12,
                                                request->plan->spoof_mac_value);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int(
      stmt, 13, cmaper_snapshot_bool_to_int(request->plan->traceroute));
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int(
      stmt, 14, cmaper_snapshot_bool_to_int(request->plan->udp_enrichment));
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  rc = cmaper_snapshot_sqlite_step_done(stmt);

cleanup:
  cmaper_snapshot_sqlite_finalize(&stmt);
  return rc;
}

cmaper_err_t
cmaper_snapshot_session_fail(cmaper_snapshot_store_t *store,
                             const cmaper_snapshot_session_fail_t *request) {
  static const char *SQL =
      "UPDATE scan_sessions "
      "SET status='failed', "
      "    failed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'), "
      "    error_message=? "
      "WHERE session_uid=?;";
  sqlite3_stmt *stmt = NULL;
  cmaper_err_t rc;

  if (request == NULL || request->session_uid == NULL ||
      request->session_uid[0] == '\0') {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (!cmaper_snapshot_store_is_enabled(store)) {
    return CMAPER_OK;
  }

  rc = cmaper_snapshot_sqlite_prepare(store->db, SQL, &stmt);
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc =
      cmaper_snapshot_sqlite_bind_text_or_null(stmt, 1, request->error_message);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text(stmt, 2, request->session_uid);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  rc = cmaper_snapshot_sqlite_step_done(stmt);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  if (sqlite3_changes(store->db) <= 0) {
    rc = CMAPER_ERR_INVALID_ARGUMENT;
  }

cleanup:
  cmaper_snapshot_sqlite_finalize(&stmt);
  return rc;
}

cmaper_err_t cmaper_snapshot_session_complete(
    cmaper_snapshot_store_t *store,
    const cmaper_snapshot_session_complete_t *request) {
  static const char *SQL =
      "UPDATE scan_sessions "
      "SET status='completed', "
      "    completed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'), "
      "    error_message=NULL, "
      "    discovery_xml_path=?, "
      "    detail_targets_total=?, "
      "    detail_hosts_success=?, "
      "    detail_hosts_failed=?, "
      "    detail_hosts_degraded=? "
      "WHERE session_uid=?;";
  sqlite3_stmt *stmt = NULL;
  cmaper_err_t rc;

  if (request == NULL || request->session_uid == NULL ||
      request->session_uid[0] == '\0') {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (!cmaper_snapshot_store_is_enabled(store)) {
    return CMAPER_OK;
  }

  rc = cmaper_snapshot_sqlite_prepare(store->db, SQL, &stmt);
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt, 1,
                                                request->discovery_xml_path);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int(stmt, 2,
                                       (int)request->detail_targets_total);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int(stmt, 3,
                                       (int)request->detail_hosts_success);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int(stmt, 4,
                                       (int)request->detail_hosts_failed);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int(stmt, 5,
                                       (int)request->detail_hosts_degraded);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text(stmt, 6, request->session_uid);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  rc = cmaper_snapshot_sqlite_step_done(stmt);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  if (sqlite3_changes(store->db) <= 0) {
    rc = CMAPER_ERR_INVALID_ARGUMENT;
  }

cleanup:
  cmaper_snapshot_sqlite_finalize(&stmt);
  return rc;
}

cmaper_err_t
cmaper_snapshot_store_write_scan(cmaper_snapshot_store_t *store,
                                 const cmaper_snapshot_write_request_t *request,
                                 cmaper_logger_t *logger) {
  if (request == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (!cmaper_snapshot_store_is_enabled(store)) {
    return CMAPER_OK;
  }

  return cmaper_snapshot_write_scan_data(store->db, request, logger);
}
