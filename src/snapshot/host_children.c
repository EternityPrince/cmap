#include "cmaper/snapshot/internal/host_children_internal.h"

#include "cmaper/snapshot/internal/sqlite_internal.h"

static cmaper_err_t
cmaper_snapshot_clear_host_children(sqlite3 *db,
                                    sqlite3_int64 host_observation_id) {
  static const char *SQL_DELETE_TLS =
      "DELETE FROM tls_fingerprints WHERE host_observation_id=?;";
  static const char *SQL_DELETE_SSH =
      "DELETE FROM ssh_fingerprints WHERE host_observation_id=?;";
  static const char *SQL_DELETE_HTTP =
      "DELETE FROM http_fingerprints WHERE host_observation_id=?;";
  static const char *SQL_DELETE_SMB =
      "DELETE FROM smb_fingerprints WHERE host_observation_id=?;";
  static const char *SQL_DELETE_FINDINGS =
      "DELETE FROM vulnerability_findings WHERE host_observation_id=?;";
  static const char *SQL_DELETE_SURFACES =
      "DELETE FROM management_surfaces WHERE host_observation_id=?;";
  static const char *SQL_DELETE_HOST_SCRIPTS =
      "DELETE FROM script_results WHERE host_observation_id=?;";
  static const char *SQL_DELETE_SERVICES =
      "DELETE FROM service_observations WHERE host_observation_id=?;";
  static const char *SQL_DELETE_OS =
      "DELETE FROM os_matches WHERE host_observation_id=?;";
  static const char *SQL_DELETE_TRACES =
      "DELETE FROM traces WHERE host_observation_id=?;";
  sqlite3_stmt *stmt = NULL;
  const char *sql_list[10];
  size_t i;
  cmaper_err_t rc = CMAPER_OK;

  if (db == NULL || host_observation_id <= 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  sql_list[0] = SQL_DELETE_TLS;
  sql_list[1] = SQL_DELETE_SSH;
  sql_list[2] = SQL_DELETE_HTTP;
  sql_list[3] = SQL_DELETE_SMB;
  sql_list[4] = SQL_DELETE_FINDINGS;
  sql_list[5] = SQL_DELETE_SURFACES;
  sql_list[6] = SQL_DELETE_HOST_SCRIPTS;
  sql_list[7] = SQL_DELETE_SERVICES;
  sql_list[8] = SQL_DELETE_OS;
  sql_list[9] = SQL_DELETE_TRACES;

  for (i = 0; i < 10; ++i) {
    rc = cmaper_snapshot_sqlite_prepare(db, sql_list[i], &stmt);
    if (rc != CMAPER_OK) {
      goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_int64(stmt, 1, host_observation_id);
    if (rc != CMAPER_OK) {
      goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_step_done(stmt);
    if (rc != CMAPER_OK) {
      goto cleanup;
    }
    cmaper_snapshot_sqlite_finalize(&stmt);
  }

cleanup:
  cmaper_snapshot_sqlite_finalize(&stmt);
  return rc;
}

static cmaper_err_t
cmaper_snapshot_find_or_create_port_id(sqlite3 *db, const char *protocol,
                                       int port_number,
                                       sqlite3_int64 *out_port_id) {
  static const char *SQL_INSERT =
      "INSERT INTO ports(protocol, port_number) VALUES(?, ?) "
      "ON CONFLICT(protocol, port_number) DO NOTHING;";
  static const char *SQL_SELECT =
      "SELECT id FROM ports WHERE protocol=? AND port_number=?;";
  sqlite3_stmt *stmt_insert = NULL;
  sqlite3_stmt *stmt_select = NULL;
  cmaper_err_t rc = CMAPER_OK;

  if (db == NULL || protocol == NULL || out_port_id == NULL ||
      port_number <= 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_port_id = 0;

  rc = cmaper_snapshot_sqlite_prepare(db, SQL_INSERT, &stmt_insert);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text(stmt_insert, 1, protocol);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int(stmt_insert, 2, port_number);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_step_done(stmt_insert);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  rc = cmaper_snapshot_sqlite_prepare(db, SQL_SELECT, &stmt_select);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text(stmt_select, 1, protocol);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int(stmt_select, 2, port_number);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_step_row(stmt_select);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  *out_port_id = sqlite3_column_int64(stmt_select, 0);
  rc = CMAPER_OK;

cleanup:
  cmaper_snapshot_sqlite_finalize(&stmt_insert);
  cmaper_snapshot_sqlite_finalize(&stmt_select);
  return rc;
}

static cmaper_err_t cmaper_snapshot_upsert_service_observation(
    sqlite3 *db, sqlite3_int64 host_observation_id, sqlite3_int64 port_id,
    const cmaper_nmap_xml_port_t *port,
    sqlite3_int64 *out_service_observation_id) {
  static const char *SQL_UPSERT =
      "INSERT INTO service_observations("
      "  host_observation_id, port_id, state, reason, service_name, "
      "service_product, service_version"
      ") VALUES(?, ?, ?, ?, ?, ?, ?) "
      "ON CONFLICT(host_observation_id, port_id) DO UPDATE SET "
      "  state=excluded.state, "
      "  reason=excluded.reason, "
      "  service_name=excluded.service_name, "
      "  service_product=excluded.service_product, "
      "  service_version=excluded.service_version;";
  static const char *SQL_SELECT = "SELECT id FROM service_observations WHERE "
                                  "host_observation_id=? AND port_id=?;";
  sqlite3_stmt *stmt_upsert = NULL;
  sqlite3_stmt *stmt_select = NULL;
  cmaper_err_t rc = CMAPER_OK;

  if (db == NULL || port == NULL || out_service_observation_id == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_service_observation_id = 0;

  rc = cmaper_snapshot_sqlite_prepare(db, SQL_UPSERT, &stmt_upsert);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int64(stmt_upsert, 1, host_observation_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int64(stmt_upsert, 2, port_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt_upsert, 3, port->state);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt_upsert, 4, port->reason);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt_upsert, 5,
                                                port->service_name);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt_upsert, 6,
                                                port->service_product);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt_upsert, 7,
                                                port->service_version);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_step_done(stmt_upsert);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  rc = cmaper_snapshot_sqlite_prepare(db, SQL_SELECT, &stmt_select);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int64(stmt_select, 1, host_observation_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int64(stmt_select, 2, port_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_step_row(stmt_select);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  *out_service_observation_id = sqlite3_column_int64(stmt_select, 0);
  rc = CMAPER_OK;

cleanup:
  cmaper_snapshot_sqlite_finalize(&stmt_upsert);
  cmaper_snapshot_sqlite_finalize(&stmt_select);
  return rc;
}

static cmaper_err_t cmaper_snapshot_insert_script_result(
    sqlite3 *db, sqlite3_int64 host_observation_id,
    sqlite3_int64 service_observation_id, const char *script_id,
    const char *output) {
  static const char *SQL =
      "INSERT INTO script_results("
      "  host_observation_id, service_observation_id, script_id, output"
      ") VALUES(?, ?, ?, ?);";
  sqlite3_stmt *stmt = NULL;
  cmaper_err_t rc;

  if (db == NULL || script_id == NULL || script_id[0] == '\0') {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  rc = cmaper_snapshot_sqlite_prepare(db, SQL, &stmt);
  if (rc != CMAPER_OK) {
    return rc;
  }
  rc = cmaper_snapshot_sqlite_bind_int64(stmt, 1, host_observation_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  if (service_observation_id > 0) {
    rc = cmaper_snapshot_sqlite_bind_int64(stmt, 2, service_observation_id);
  } else {
    rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt, 2, NULL);
  }
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text(stmt, 3, script_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt, 4, output);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_step_done(stmt);

cleanup:
  cmaper_snapshot_sqlite_finalize(&stmt);
  return rc;
}

static cmaper_err_t
cmaper_snapshot_insert_os_match(sqlite3 *db, sqlite3_int64 host_observation_id,
                                const cmaper_nmap_xml_osmatch_t *osmatch) {
  static const char *SQL =
      "INSERT INTO os_matches(host_observation_id, name, accuracy, line) "
      "VALUES(?, ?, ?, ?);";
  sqlite3_stmt *stmt = NULL;
  cmaper_err_t rc;

  if (db == NULL || osmatch == NULL || osmatch->name == NULL ||
      osmatch->name[0] == '\0') {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  rc = cmaper_snapshot_sqlite_prepare(db, SQL, &stmt);
  if (rc != CMAPER_OK) {
    return rc;
  }
  rc = cmaper_snapshot_sqlite_bind_int64(stmt, 1, host_observation_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text(stmt, 2, osmatch->name);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int(stmt, 3, osmatch->accuracy);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int(stmt, 4, osmatch->line);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_step_done(stmt);

cleanup:
  cmaper_snapshot_sqlite_finalize(&stmt);
  return rc;
}

static cmaper_err_t
cmaper_snapshot_insert_trace(sqlite3 *db, sqlite3_int64 host_observation_id,
                             const cmaper_nmap_xml_trace_hop_t *hops,
                             size_t hop_count) {
  static const char *SQL_TRACE =
      "INSERT INTO traces(host_observation_id) VALUES(?);";
  static const char *SQL_HOP =
      "INSERT INTO trace_hops(trace_id, hop_index, ttl, ipaddr, rtt, host) "
      "VALUES(?, ?, ?, ?, ?, ?);";
  sqlite3_stmt *stmt_trace = NULL;
  sqlite3_stmt *stmt_hop = NULL;
  sqlite3_int64 trace_id;
  size_t i;
  cmaper_err_t rc = CMAPER_OK;

  if (db == NULL || hops == NULL || hop_count == 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  rc = cmaper_snapshot_sqlite_prepare(db, SQL_TRACE, &stmt_trace);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int64(stmt_trace, 1, host_observation_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_step_done(stmt_trace);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  trace_id = sqlite3_last_insert_rowid(db);

  rc = cmaper_snapshot_sqlite_prepare(db, SQL_HOP, &stmt_hop);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  for (i = 0; i < hop_count; ++i) {
    sqlite3_reset(stmt_hop);
    sqlite3_clear_bindings(stmt_hop);

    rc = cmaper_snapshot_sqlite_bind_int64(stmt_hop, 1, trace_id);
    if (rc != CMAPER_OK) {
      goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_int(stmt_hop, 2, (int)(i + 1U));
    if (rc != CMAPER_OK) {
      goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_int(stmt_hop, 3, hops[i].ttl);
    if (rc != CMAPER_OK) {
      goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt_hop, 4, hops[i].ipaddr);
    if (rc != CMAPER_OK) {
      goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt_hop, 5, hops[i].rtt);
    if (rc != CMAPER_OK) {
      goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt_hop, 6, hops[i].host);
    if (rc != CMAPER_OK) {
      goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_step_done(stmt_hop);
    if (rc != CMAPER_OK) {
      goto cleanup;
    }
  }

cleanup:
  cmaper_snapshot_sqlite_finalize(&stmt_trace);
  cmaper_snapshot_sqlite_finalize(&stmt_hop);
  return rc;
}

cmaper_err_t cmaper_snapshot_replace_host_children(
    sqlite3 *db, sqlite3_int64 host_observation_id,
    const cmaper_snapshot_host_view_t *host_view) {
  size_t i;
  cmaper_err_t rc;

  if (db == NULL || host_observation_id <= 0 || host_view == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  rc = cmaper_snapshot_clear_host_children(db, host_observation_id);
  if (rc != CMAPER_OK) {
    return rc;
  }

  for (i = 0; i < host_view->os_count; ++i) {
    rc = cmaper_snapshot_insert_os_match(db, host_observation_id,
                                         &host_view->os_matches[i]);
    if (rc != CMAPER_OK) {
      return rc;
    }
  }

  for (i = 0; i < host_view->host_script_count; ++i) {
    const cmaper_nmap_xml_script_t *script = &host_view->host_scripts[i];

    if (script->id == NULL || script->id[0] == '\0') {
      continue;
    }

    rc = cmaper_snapshot_insert_script_result(db, host_observation_id, 0,
                                              script->id, script->output);
    if (rc != CMAPER_OK) {
      return rc;
    }
  }

  for (i = 0; i < host_view->port_count; ++i) {
    const cmaper_nmap_xml_port_t *port = &host_view->ports[i];
    sqlite3_int64 port_id = 0;
    sqlite3_int64 service_observation_id = 0;
    size_t script_index;

    if (port->protocol == NULL || port->protocol[0] == '\0' ||
        port->portid <= 0) {
      continue;
    }

    rc = cmaper_snapshot_find_or_create_port_id(db, port->protocol,
                                                port->portid, &port_id);
    if (rc != CMAPER_OK) {
      return rc;
    }

    rc = cmaper_snapshot_upsert_service_observation(
        db, host_observation_id, port_id, port, &service_observation_id);
    if (rc != CMAPER_OK) {
      return rc;
    }

    for (script_index = 0; script_index < port->script_count; ++script_index) {
      const cmaper_nmap_xml_script_t *script = &port->scripts[script_index];

      if (script->id == NULL || script->id[0] == '\0') {
        continue;
      }

      rc = cmaper_snapshot_insert_script_result(db, host_observation_id,
                                                service_observation_id,
                                                script->id, script->output);
      if (rc != CMAPER_OK) {
        return rc;
      }
    }
  }

  if (host_view->trace_count > 0 && host_view->trace_hops != NULL) {
    rc = cmaper_snapshot_insert_trace(
        db, host_observation_id, host_view->trace_hops, host_view->trace_count);
    if (rc != CMAPER_OK) {
      return rc;
    }
  }

  return CMAPER_OK;
}
