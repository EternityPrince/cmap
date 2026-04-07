#include "cmaper/snapshot/internal/host_observation_internal.h"

#include <stddef.h>

#include "cmaper/snapshot/internal/sqlite_internal.h"

cmaper_err_t cmaper_snapshot_upsert_host_observation(
    sqlite3 *db, sqlite3_int64 session_id, sqlite3_int64 device_id,
    const char *primary_ip, const char *primary_ip_type, const char *status,
    const char *source, const char *hostname_primary, const char *mac_address,
    const char *mac_vendor, const char *detail_xml_path,
    sqlite3_int64 *out_host_observation_id) {
  static const char *SQL_UPSERT =
      "INSERT INTO host_observations("
      "  session_id, device_id, primary_ip, primary_ip_type, status, "
      "observation_source,"
      "  hostname_primary, mac_address, mac_vendor, detail_xml_path"
      ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
      "ON CONFLICT(session_id, device_id, primary_ip) DO UPDATE SET "
      "  primary_ip_type=excluded.primary_ip_type, "
      "  status=excluded.status, "
      "  observation_source=excluded.observation_source, "
      "  hostname_primary=excluded.hostname_primary, "
      "  mac_address=excluded.mac_address, "
      "  mac_vendor=excluded.mac_vendor, "
      "  detail_xml_path=excluded.detail_xml_path;";
  static const char *SQL_SELECT_ID =
      "SELECT id FROM host_observations WHERE session_id=? AND device_id=? AND "
      "primary_ip=?;";
  sqlite3_stmt *stmt_upsert = NULL;
  sqlite3_stmt *stmt_id = NULL;
  cmaper_err_t rc = CMAPER_OK;

  if (db == NULL || primary_ip == NULL || source == NULL ||
      out_host_observation_id == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_host_observation_id = 0;

  rc = cmaper_snapshot_sqlite_prepare(db, SQL_UPSERT, &stmt_upsert);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int64(stmt_upsert, 1, session_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int64(stmt_upsert, 2, device_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text(stmt_upsert, 3, primary_ip);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc =
      cmaper_snapshot_sqlite_bind_text_or_null(stmt_upsert, 4, primary_ip_type);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt_upsert, 5, status);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text(stmt_upsert, 6, source);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt_upsert, 7,
                                                hostname_primary);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt_upsert, 8, mac_address);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt_upsert, 9, mac_vendor);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt_upsert, 10,
                                                detail_xml_path);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_step_done(stmt_upsert);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  rc = cmaper_snapshot_sqlite_prepare(db, SQL_SELECT_ID, &stmt_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int64(stmt_id, 1, session_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int64(stmt_id, 2, device_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text(stmt_id, 3, primary_ip);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_step_row(stmt_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  *out_host_observation_id = sqlite3_column_int64(stmt_id, 0);
  rc = CMAPER_OK;

cleanup:
  cmaper_snapshot_sqlite_finalize(&stmt_upsert);
  cmaper_snapshot_sqlite_finalize(&stmt_id);
  return rc;
}
