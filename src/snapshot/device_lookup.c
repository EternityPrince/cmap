#include "cmaper/snapshot/internal/device_lookup_internal.h"

#include <stddef.h>

#include "cmaper/snapshot/internal/sqlite_internal.h"

cmaper_err_t cmaper_snapshot_find_device_by_mac(sqlite3 *db,
                                                const char *mac_address,
                                                sqlite3_int64 *out_device_id) {
  static const char *SQL =
      "SELECT id FROM devices WHERE mac_address=? LIMIT 1;";
  sqlite3_stmt *stmt = NULL;
  cmaper_err_t rc;
  int step_rc;

  if (db == NULL || mac_address == NULL || out_device_id == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_device_id = 0;

  rc = cmaper_snapshot_sqlite_prepare(db, SQL, &stmt);
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_snapshot_sqlite_bind_text(stmt, 1, mac_address);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_ROW) {
    *out_device_id = sqlite3_column_int64(stmt, 0);
    rc = CMAPER_OK;
  } else if (step_rc == SQLITE_DONE) {
    rc = CMAPER_OK;
  } else {
    rc = CMAPER_ERR_IO;
  }

cleanup:
  cmaper_snapshot_sqlite_finalize(&stmt);
  return rc;
}

cmaper_err_t
cmaper_snapshot_find_device_by_previous_ip(sqlite3 *db, const char *ip_address,
                                           sqlite3_int64 *out_device_id) {
  static const char *SQL =
      "SELECT d.id "
      "FROM devices d "
      "JOIN device_ip_addresses dip ON dip.device_id=d.id "
      "WHERE dip.ip_address=? AND dip.is_current=1 "
      "ORDER BY COALESCE(dip.last_seen_session_id, 0) DESC "
      "LIMIT 1;";
  sqlite3_stmt *stmt = NULL;
  cmaper_err_t rc;
  int step_rc;

  if (db == NULL || ip_address == NULL || out_device_id == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_device_id = 0;

  rc = cmaper_snapshot_sqlite_prepare(db, SQL, &stmt);
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_snapshot_sqlite_bind_text(stmt, 1, ip_address);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_ROW) {
    *out_device_id = sqlite3_column_int64(stmt, 0);
    rc = CMAPER_OK;
  } else if (step_rc == SQLITE_DONE) {
    rc = CMAPER_OK;
  } else {
    rc = CMAPER_ERR_IO;
  }

cleanup:
  cmaper_snapshot_sqlite_finalize(&stmt);
  return rc;
}

cmaper_err_t cmaper_snapshot_find_device_by_fallback_key(
    sqlite3 *db, const char *fallback_key, sqlite3_int64 *out_device_id) {
  static const char *SQL =
      "SELECT id FROM devices WHERE fallback_key=? LIMIT 1;";
  sqlite3_stmt *stmt = NULL;
  cmaper_err_t rc;
  int step_rc;

  if (db == NULL || fallback_key == NULL || out_device_id == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_device_id = 0;

  rc = cmaper_snapshot_sqlite_prepare(db, SQL, &stmt);
  if (rc != CMAPER_OK) {
    return rc;
  }
  rc = cmaper_snapshot_sqlite_bind_text(stmt, 1, fallback_key);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_ROW) {
    *out_device_id = sqlite3_column_int64(stmt, 0);
    rc = CMAPER_OK;
  } else if (step_rc == SQLITE_DONE) {
    rc = CMAPER_OK;
  } else {
    rc = CMAPER_ERR_IO;
  }

cleanup:
  cmaper_snapshot_sqlite_finalize(&stmt);
  return rc;
}
