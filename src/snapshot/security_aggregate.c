#include "cmaper/snapshot/security.h"

#include "cmaper/snapshot/internal/sqlite_internal.h"

static cmaper_err_t cmaper_snapshot_security_query_count(
    sqlite3 *db, const char *sql, sqlite3_int64 session_id, size_t *out_count) {
  sqlite3_stmt *stmt = NULL;
  int step_rc;
  cmaper_err_t rc;

  if (db == NULL || sql == NULL || out_count == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_count = 0;

  rc = cmaper_snapshot_sqlite_prepare(db, sql, &stmt);
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_snapshot_sqlite_bind_int64(stmt, 1, session_id);
  if (rc != CMAPER_OK) {
    cmaper_snapshot_sqlite_finalize(&stmt);
    return rc;
  }

  step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_ROW) {
    *out_count = (size_t)sqlite3_column_int64(stmt, 0);
    cmaper_snapshot_sqlite_finalize(&stmt);
    return CMAPER_OK;
  }

  cmaper_snapshot_sqlite_finalize(&stmt);
  return CMAPER_ERR_IO;
}

void cmaper_snapshot_security_aggregate_init(
    cmaper_snapshot_security_aggregate_t *aggregate) {
  if (aggregate == NULL) {
    return;
  }

  aggregate->findings_total = 0;
  aggregate->findings_open = 0;
  aggregate->findings_high_or_worse = 0;
  aggregate->management_surfaces_total = 0;
  aggregate->hosts_with_management_surfaces = 0;
}

cmaper_err_t cmaper_snapshot_security_query_session_aggregate(
    sqlite3 *db, sqlite3_int64 session_id,
    cmaper_snapshot_security_aggregate_t *out_aggregate) {
  static const char *SQL_FINDINGS_TOTAL =
      "SELECT COUNT(*) "
      "FROM vulnerability_findings vf "
      "JOIN host_observations ho ON ho.id=vf.host_observation_id "
      "WHERE ho.session_id=?;";
  static const char *SQL_FINDINGS_OPEN =
      "SELECT COUNT(*) "
      "FROM vulnerability_findings vf "
      "JOIN host_observations ho ON ho.id=vf.host_observation_id "
      "WHERE ho.session_id=? AND vf.state='open';";
  static const char *SQL_FINDINGS_HIGH =
      "SELECT COUNT(*) "
      "FROM vulnerability_findings vf "
      "JOIN host_observations ho ON ho.id=vf.host_observation_id "
      "WHERE ho.session_id=? AND vf.severity IN ('high','critical');";
  static const char *SQL_SURFACES_TOTAL =
      "SELECT COUNT(*) "
      "FROM management_surfaces ms "
      "JOIN host_observations ho ON ho.id=ms.host_observation_id "
      "WHERE ho.session_id=?;";
  static const char *SQL_SURFACE_HOSTS =
      "SELECT COUNT(DISTINCT ho.id) "
      "FROM management_surfaces ms "
      "JOIN host_observations ho ON ho.id=ms.host_observation_id "
      "WHERE ho.session_id=?;";
  cmaper_err_t rc;

  if (db == NULL || out_aggregate == NULL || session_id <= 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_snapshot_security_aggregate_init(out_aggregate);

  rc = cmaper_snapshot_security_query_count(db, SQL_FINDINGS_TOTAL, session_id,
                                            &out_aggregate->findings_total);
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_snapshot_security_query_count(db, SQL_FINDINGS_OPEN, session_id,
                                            &out_aggregate->findings_open);
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_snapshot_security_query_count(
      db, SQL_FINDINGS_HIGH, session_id,
      &out_aggregate->findings_high_or_worse);
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_snapshot_security_query_count(
      db, SQL_SURFACES_TOTAL, session_id,
      &out_aggregate->management_surfaces_total);
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_snapshot_security_query_count(
      db, SQL_SURFACE_HOSTS, session_id,
      &out_aggregate->hosts_with_management_surfaces);
  if (rc != CMAPER_OK) {
    return rc;
  }

  return CMAPER_OK;
}
