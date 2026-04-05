#include "cmaper/history/delete.h"

#include <stdio.h>

#include <sqlite3.h>

#include "cmaper/history/query.h"
#include "cmaper/platform/fs.h"

static cmaper_err_t cmaper_history_delete_exec(sqlite3 *db, const char *sql) {
    int rc;

    if (db == NULL || sql == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        return CMAPER_ERR_IO;
    }
    return CMAPER_OK;
}

static cmaper_err_t cmaper_history_delete_prepare(
    sqlite3 *db,
    const char *sql,
    sqlite3_stmt **out_stmt
) {
    int rc;

    if (db == NULL || sql == NULL || out_stmt == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_stmt = NULL;
    rc = sqlite3_prepare_v2(db, sql, -1, out_stmt, NULL);
    if (rc != SQLITE_OK) {
        return CMAPER_ERR_IO;
    }
    return CMAPER_OK;
}

static void cmaper_history_delete_finalize(sqlite3_stmt **stmt) {
    if (stmt == NULL || *stmt == NULL) {
        return;
    }
    sqlite3_finalize(*stmt);
    *stmt = NULL;
}

static cmaper_err_t cmaper_history_delete_bind_int64(
    sqlite3_stmt *stmt,
    int index,
    sqlite3_int64 value
) {
    if (stmt == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }
    if (sqlite3_bind_int64(stmt, index, value) != SQLITE_OK) {
        return CMAPER_ERR_IO;
    }
    return CMAPER_OK;
}

static cmaper_err_t cmaper_history_delete_count(
    sqlite3 *db,
    const char *sql,
    size_t *out_count
) {
    sqlite3_stmt *stmt = NULL;
    cmaper_err_t rc;
    int step_rc;
    sqlite3_int64 count;

    if (db == NULL || sql == NULL || out_count == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_count = 0;

    rc = cmaper_history_delete_prepare(db, sql, &stmt);
    if (rc != CMAPER_OK) {
        return rc;
    }

    step_rc = sqlite3_step(stmt);
    if (step_rc != SQLITE_ROW) {
        cmaper_history_delete_finalize(&stmt);
        return CMAPER_ERR_IO;
    }

    count = sqlite3_column_int64(stmt, 0);
    if (count > 0) {
        *out_count = (size_t) count;
    }

    cmaper_history_delete_finalize(&stmt);
    return CMAPER_OK;
}

static cmaper_err_t cmaper_history_delete_open_rw(
    const char *db_path,
    sqlite3 **out_db,
    bool *out_db_available
) {
    sqlite3 *db = NULL;

    if (db_path == NULL || out_db == NULL || out_db_available == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_db = NULL;
    *out_db_available = false;

    if (!cmaper_fs_path_exists(db_path)) {
        return CMAPER_OK;
    }

    if (sqlite3_open_v2(
            db_path,
            &db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
            NULL) != SQLITE_OK) {
        if (db != NULL) {
            sqlite3_close(db);
        }
        return CMAPER_ERR_IO;
    }

    if (sqlite3_busy_timeout(db, 5000) != SQLITE_OK) {
        sqlite3_close(db);
        return CMAPER_ERR_IO;
    }

    if (sqlite3_exec(db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return CMAPER_ERR_IO;
    }

    *out_db = db;
    *out_db_available = true;
    return CMAPER_OK;
}

static void cmaper_history_delete_close_db(sqlite3 **db) {
    if (db == NULL || *db == NULL) {
        return;
    }
    sqlite3_close(*db);
    *db = NULL;
}

static cmaper_err_t cmaper_history_delete_rebuild_metadata(
    sqlite3 *db,
    size_t *out_orphan_devices_deleted,
    size_t *out_orphan_networks_deleted
) {
    static const char *SQL_REBUILD_DEVICES =
        "UPDATE devices "
        "SET first_seen_session_id=("
        "      SELECT MIN(ho.session_id) "
        "      FROM host_observations ho "
        "      WHERE ho.device_id=devices.id"
        "    ), "
        "    last_seen_session_id=("
        "      SELECT MAX(ho.session_id) "
        "      FROM host_observations ho "
        "      WHERE ho.device_id=devices.id"
        "    ), "
        "    updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now');";
    static const char *SQL_REBUILD_DEVICE_IPS =
        "UPDATE device_ip_addresses "
        "SET first_seen_session_id=("
        "      SELECT MIN(ho.session_id) "
        "      FROM host_observations ho "
        "      WHERE ho.device_id=device_ip_addresses.device_id "
        "        AND ho.primary_ip=device_ip_addresses.ip_address"
        "    ), "
        "    last_seen_session_id=("
        "      SELECT MAX(ho.session_id) "
        "      FROM host_observations ho "
        "      WHERE ho.device_id=device_ip_addresses.device_id "
        "        AND ho.primary_ip=device_ip_addresses.ip_address"
        "    ), "
        "    is_current=CASE WHEN ("
        "      SELECT ho.primary_ip "
        "      FROM host_observations ho "
        "      WHERE ho.device_id=device_ip_addresses.device_id "
        "      ORDER BY ho.session_id DESC, ho.id DESC "
        "      LIMIT 1"
        "    )=device_ip_addresses.ip_address THEN 1 ELSE 0 END;";
    static const char *SQL_DELETE_ORPHAN_DEVICE_IPS =
        "DELETE FROM device_ip_addresses "
        "WHERE NOT EXISTS ("
        "  SELECT 1 "
        "  FROM host_observations ho "
        "  WHERE ho.device_id=device_ip_addresses.device_id "
        "    AND ho.primary_ip=device_ip_addresses.ip_address"
        ");";
    static const char *SQL_DELETE_ORPHAN_DEVICES =
        "DELETE FROM devices "
        "WHERE NOT EXISTS ("
        "  SELECT 1 "
        "  FROM host_observations ho "
        "  WHERE ho.device_id=devices.id"
        ");";
    static const char *SQL_REBUILD_NETWORKS =
        "UPDATE networks "
        "SET first_seen_session_id=("
        "      SELECT MIN(sn.session_id) "
        "      FROM session_networks sn "
        "      WHERE sn.network_id=networks.id"
        "    ), "
        "    last_seen_session_id=("
        "      SELECT MAX(sn.session_id) "
        "      FROM session_networks sn "
        "      WHERE sn.network_id=networks.id"
        "    );";
    static const char *SQL_DELETE_ORPHAN_NETWORKS =
        "DELETE FROM networks "
        "WHERE NOT EXISTS ("
        "  SELECT 1 "
        "  FROM session_networks sn "
        "  WHERE sn.network_id=networks.id"
        ");";
    cmaper_err_t rc;

    if (db == NULL || out_orphan_devices_deleted == NULL || out_orphan_networks_deleted == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_orphan_devices_deleted = 0;
    *out_orphan_networks_deleted = 0;

    rc = cmaper_history_delete_exec(db, SQL_REBUILD_DEVICES);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_delete_exec(db, SQL_REBUILD_DEVICE_IPS);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_delete_exec(db, SQL_DELETE_ORPHAN_DEVICE_IPS);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_delete_exec(db, SQL_DELETE_ORPHAN_DEVICES);
    if (rc != CMAPER_OK) {
        return rc;
    }
    if (sqlite3_changes(db) > 0) {
        *out_orphan_devices_deleted = (size_t) sqlite3_changes(db);
    }

    rc = cmaper_history_delete_exec(db, SQL_REBUILD_NETWORKS);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_delete_exec(db, SQL_DELETE_ORPHAN_NETWORKS);
    if (rc != CMAPER_OK) {
        return rc;
    }
    if (sqlite3_changes(db) > 0) {
        *out_orphan_networks_deleted = (size_t) sqlite3_changes(db);
    }

    return CMAPER_OK;
}

void cmaper_history_delete_report_init(cmaper_history_delete_report_t *report) {
    if (report == NULL) {
        return;
    }

    report->db_available = false;
    report->session_found = false;
    report->performed = false;
    report->session_id[0] = '\0';
    report->sessions_before = 0;
    report->sessions_deleted = 0;
    report->orphan_devices_deleted = 0;
    report->orphan_networks_deleted = 0;
}

cmaper_err_t cmaper_history_delete_session(
    const char *db_path,
    const char *session_token,
    cmaper_history_delete_report_t *report
) {
    static const char *SQL_DELETE_SESSION =
        "DELETE FROM scan_sessions WHERE id=?;";
    sqlite3 *db = NULL;
    bool db_available = false;
    cmaper_history_session_ref_t session_ref;
    sqlite3_stmt *stmt = NULL;
    cmaper_err_t rc;

    if (db_path == NULL || session_token == NULL || session_token[0] == '\0' || report == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_history_delete_report_init(report);
    cmaper_history_session_ref_init(&session_ref);

    rc = cmaper_history_delete_open_rw(db_path, &db, &db_available);
    if (rc != CMAPER_OK) {
        return rc;
    }

    report->db_available = db_available;
    if (!db_available) {
        return CMAPER_OK;
    }

    rc = cmaper_history_query_resolve_session(db, session_token, &session_ref);
    if (rc != CMAPER_OK) {
        cmaper_history_delete_close_db(&db);
        return rc;
    }

    if (!session_ref.found || session_ref.id <= 0) {
        cmaper_history_delete_close_db(&db);
        return CMAPER_OK;
    }

    report->session_found = true;
    (void) snprintf(report->session_id, sizeof(report->session_id), "%s", session_ref.session_uid);

    rc = cmaper_history_delete_exec(db, "BEGIN IMMEDIATE TRANSACTION;");
    if (rc != CMAPER_OK) {
        cmaper_history_delete_close_db(&db);
        return rc;
    }

    rc = cmaper_history_delete_prepare(db, SQL_DELETE_SESSION, &stmt);
    if (rc != CMAPER_OK) {
        (void) cmaper_history_delete_exec(db, "ROLLBACK;");
        cmaper_history_delete_close_db(&db);
        return rc;
    }

    rc = cmaper_history_delete_bind_int64(stmt, 1, session_ref.id);
    if (rc != CMAPER_OK) {
        cmaper_history_delete_finalize(&stmt);
        (void) cmaper_history_delete_exec(db, "ROLLBACK;");
        cmaper_history_delete_close_db(&db);
        return rc;
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        cmaper_history_delete_finalize(&stmt);
        (void) cmaper_history_delete_exec(db, "ROLLBACK;");
        cmaper_history_delete_close_db(&db);
        return CMAPER_ERR_IO;
    }
    cmaper_history_delete_finalize(&stmt);

    if (sqlite3_changes(db) > 0) {
        report->sessions_deleted = (size_t) sqlite3_changes(db);
    }

    rc = cmaper_history_delete_rebuild_metadata(
        db,
        &report->orphan_devices_deleted,
        &report->orphan_networks_deleted
    );
    if (rc != CMAPER_OK) {
        (void) cmaper_history_delete_exec(db, "ROLLBACK;");
        cmaper_history_delete_close_db(&db);
        return rc;
    }

    rc = cmaper_history_delete_exec(db, "COMMIT;");
    if (rc != CMAPER_OK) {
        (void) cmaper_history_delete_exec(db, "ROLLBACK;");
        cmaper_history_delete_close_db(&db);
        return rc;
    }

    report->performed = true;
    cmaper_history_delete_close_db(&db);
    return CMAPER_OK;
}

cmaper_err_t cmaper_history_delete_all_sessions(
    const char *db_path,
    cmaper_history_delete_report_t *report
) {
    static const char *SQL_DELETE_ALL = "DELETE FROM scan_sessions;";
    sqlite3 *db = NULL;
    bool db_available = false;
    cmaper_err_t rc;

    if (db_path == NULL || report == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_history_delete_report_init(report);

    rc = cmaper_history_delete_open_rw(db_path, &db, &db_available);
    if (rc != CMAPER_OK) {
        return rc;
    }

    report->db_available = db_available;
    if (!db_available) {
        return CMAPER_OK;
    }

    rc = cmaper_history_delete_count(db, "SELECT COUNT(*) FROM scan_sessions;", &report->sessions_before);
    if (rc != CMAPER_OK) {
        cmaper_history_delete_close_db(&db);
        return rc;
    }

    rc = cmaper_history_delete_exec(db, "BEGIN IMMEDIATE TRANSACTION;");
    if (rc != CMAPER_OK) {
        cmaper_history_delete_close_db(&db);
        return rc;
    }

    rc = cmaper_history_delete_exec(db, SQL_DELETE_ALL);
    if (rc != CMAPER_OK) {
        (void) cmaper_history_delete_exec(db, "ROLLBACK;");
        cmaper_history_delete_close_db(&db);
        return rc;
    }
    if (sqlite3_changes(db) > 0) {
        report->sessions_deleted = (size_t) sqlite3_changes(db);
    }

    rc = cmaper_history_delete_rebuild_metadata(
        db,
        &report->orphan_devices_deleted,
        &report->orphan_networks_deleted
    );
    if (rc != CMAPER_OK) {
        (void) cmaper_history_delete_exec(db, "ROLLBACK;");
        cmaper_history_delete_close_db(&db);
        return rc;
    }

    rc = cmaper_history_delete_exec(db, "COMMIT;");
    if (rc != CMAPER_OK) {
        (void) cmaper_history_delete_exec(db, "ROLLBACK;");
        cmaper_history_delete_close_db(&db);
        return rc;
    }

    report->performed = true;
    cmaper_history_delete_close_db(&db);
    return CMAPER_OK;
}
