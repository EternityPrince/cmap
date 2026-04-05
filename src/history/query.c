#include "cmaper/history/query.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmaper/history/fuzzy.h"
#include "cmaper/platform/fs.h"

typedef struct {
    void *items;
    size_t count;
    size_t capacity;
    size_t item_size;
} cmaper_history_buffer_t;

static cmaper_err_t cmaper_history_prepare(
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

static void cmaper_history_finalize(sqlite3_stmt **stmt) {
    if (stmt == NULL || *stmt == NULL) {
        return;
    }

    sqlite3_finalize(*stmt);
    *stmt = NULL;
}

static cmaper_err_t cmaper_history_bind_int(sqlite3_stmt *stmt, int index, int value) {
    if (stmt == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    if (sqlite3_bind_int(stmt, index, value) != SQLITE_OK) {
        return CMAPER_ERR_IO;
    }
    return CMAPER_OK;
}

static cmaper_err_t cmaper_history_bind_int64(
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

static cmaper_err_t cmaper_history_bind_text(
    sqlite3_stmt *stmt,
    int index,
    const char *value
) {
    if (stmt == NULL || value == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    if (sqlite3_bind_text(stmt, index, value, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        return CMAPER_ERR_IO;
    }
    return CMAPER_OK;
}

static void cmaper_history_copy_string(char *out, size_t out_cap, const char *value) {
    if (out == NULL || out_cap == 0) {
        return;
    }

    out[0] = '\0';
    if (value == NULL) {
        return;
    }

    (void) snprintf(out, out_cap, "%s", value);
}

static void cmaper_history_copy_column_text(
    char *out,
    size_t out_cap,
    sqlite3_stmt *stmt,
    int index
) {
    const unsigned char *value;

    if (out == NULL || out_cap == 0 || stmt == NULL) {
        return;
    }

    value = sqlite3_column_text(stmt, index);
    if (value == NULL) {
        out[0] = '\0';
        return;
    }

    cmaper_history_copy_string(out, out_cap, (const char *) value);
}

static size_t cmaper_history_column_size(sqlite3_stmt *stmt, int index) {
    sqlite3_int64 value;

    if (stmt == NULL) {
        return 0;
    }

    value = sqlite3_column_int64(stmt, index);
    if (value <= 0) {
        return 0;
    }
    return (size_t) value;
}

static cmaper_err_t cmaper_history_buffer_init(cmaper_history_buffer_t *buffer, size_t item_size) {
    if (buffer == NULL || item_size == 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    buffer->items = NULL;
    buffer->count = 0;
    buffer->capacity = 0;
    buffer->item_size = item_size;
    return CMAPER_OK;
}

static void *cmaper_history_buffer_push(cmaper_history_buffer_t *buffer) {
    void *next;

    if (buffer == NULL || buffer->item_size == 0) {
        return NULL;
    }

    if (buffer->count == buffer->capacity) {
        size_t next_capacity = buffer->capacity == 0 ? 16U : buffer->capacity * 2U;
        next = realloc(buffer->items, next_capacity * buffer->item_size);
        if (next == NULL) {
            return NULL;
        }
        buffer->items = next;
        buffer->capacity = next_capacity;
    }

    next = (unsigned char *) buffer->items + buffer->count * buffer->item_size;
    memset(next, 0, buffer->item_size);
    buffer->count += 1U;
    return next;
}

static void cmaper_history_buffer_dispose(cmaper_history_buffer_t *buffer) {
    if (buffer == NULL) {
        return;
    }

    if (buffer->items != NULL) {
        free(buffer->items);
    }
    buffer->items = NULL;
    buffer->count = 0;
    buffer->capacity = 0;
    buffer->item_size = 0;
}

static int cmaper_history_session_host_row_compare(const void *left, const void *right) {
    const cmaper_history_session_host_row_t *a = (const cmaper_history_session_host_row_t *) left;
    const cmaper_history_session_host_row_t *b = (const cmaper_history_session_host_row_t *) right;
    int rc = cmaper_history_compare_ip(a->primary_ip, b->primary_ip);

    if (rc != 0) {
        return rc;
    }
    return strcmp(a->device_id, b->device_id);
}

static int cmaper_history_device_ip_row_compare(const void *left, const void *right) {
    const cmaper_history_device_ip_row_t *a = (const cmaper_history_device_ip_row_t *) left;
    const cmaper_history_device_ip_row_t *b = (const cmaper_history_device_ip_row_t *) right;
    int rc;

    if (a->is_current != b->is_current) {
        return a->is_current ? -1 : 1;
    }

    rc = cmaper_history_compare_ip(a->ip_address, b->ip_address);
    if (rc != 0) {
        return rc;
    }
    return strcmp(a->address_type, b->address_type);
}

static int cmaper_history_device_row_compare(const void *left, const void *right) {
    const cmaper_history_device_row_t *a = (const cmaper_history_device_row_t *) left;
    const cmaper_history_device_row_t *b = (const cmaper_history_device_row_t *) right;
    int rc = cmaper_history_compare_ip(a->primary_ip, b->primary_ip);
    if (rc != 0) {
        return rc;
    }
    return strcmp(a->device_id, b->device_id);
}

static int cmaper_history_snapshot_compare(const void *left, const void *right) {
    const cmaper_history_host_snapshot_t *a = (const cmaper_history_host_snapshot_t *) left;
    const cmaper_history_host_snapshot_t *b = (const cmaper_history_host_snapshot_t *) right;
    int rc = cmaper_history_compare_ip(a->primary_ip, b->primary_ip);
    if (rc != 0) {
        return rc;
    }
    return strcmp(a->device_id, b->device_id);
}

static cmaper_err_t cmaper_history_fill_session_row(
    sqlite3 *db,
    sqlite3_int64 session_id,
    cmaper_history_session_row_t *row,
    bool *out_found
) {
    static const char *SQL =
        "SELECT s.session_uid, s.status, s.target, s.profile, "
        "       COALESCE(s.started_at,''), COALESCE(s.completed_at,''), "
        "       s.detail_targets_total, s.detail_hosts_success, s.detail_hosts_failed, s.detail_hosts_degraded, "
        "       COALESCE((SELECT COUNT(*) FROM host_observations ho WHERE ho.session_id=s.id), 0), "
        "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
        "                 JOIN host_observations ho ON ho.id=vf.host_observation_id "
        "                 WHERE ho.session_id=s.id), 0), "
        "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
        "                 JOIN host_observations ho ON ho.id=vf.host_observation_id "
        "                 WHERE ho.session_id=s.id AND vf.state='open'), 0), "
        "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
        "                 JOIN host_observations ho ON ho.id=vf.host_observation_id "
        "                 WHERE ho.session_id=s.id AND vf.state='open' "
        "                   AND vf.severity IN ('high','critical')), 0), "
        "       COALESCE((SELECT COUNT(*) FROM management_surfaces ms "
        "                 JOIN host_observations ho ON ho.id=ms.host_observation_id "
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

    cmaper_history_copy_column_text(row->session_id, sizeof(row->session_id), stmt, 0);
    cmaper_history_copy_column_text(row->status, sizeof(row->status), stmt, 1);
    cmaper_history_copy_column_text(row->target, sizeof(row->target), stmt, 2);
    cmaper_history_copy_column_text(row->profile, sizeof(row->profile), stmt, 3);
    cmaper_history_copy_column_text(row->started_at, sizeof(row->started_at), stmt, 4);
    cmaper_history_copy_column_text(row->completed_at, sizeof(row->completed_at), stmt, 5);
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

static cmaper_err_t cmaper_history_query_timeline_presence(
    sqlite3 *db,
    sqlite3_int64 session_id,
    sqlite3_int64 device_id,
    bool *out_present,
    char *out_ip,
    size_t out_ip_cap,
    char *out_status,
    size_t out_status_cap
) {
    static const char *SQL =
        "SELECT ho.primary_ip, COALESCE(ho.status,'') "
        "FROM host_observations ho "
        "WHERE ho.session_id=? AND ho.device_id=? "
        "ORDER BY ho.primary_ip ASC "
        "LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || out_present == NULL || out_ip == NULL || out_status == NULL) {
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

void cmaper_history_session_ref_init(cmaper_history_session_ref_t *ref) {
    if (ref == NULL) {
        return;
    }

    ref->id = 0;
    ref->found = false;
    ref->session_uid[0] = '\0';
    ref->status[0] = '\0';
    ref->started_at[0] = '\0';
    ref->completed_at[0] = '\0';
}

void cmaper_history_host_snapshot_init(cmaper_history_host_snapshot_t *snapshot) {
    if (snapshot == NULL) {
        return;
    }

    snapshot->host_observation_id = 0;
    snapshot->device_db_id = 0;
    snapshot->device_id[0] = '\0';
    snapshot->primary_ip[0] = '\0';
    snapshot->mac_address[0] = '\0';
    snapshot->hostname[0] = '\0';
    snapshot->status[0] = '\0';
    snapshot->ports = NULL;
    snapshot->port_count = 0;
    snapshot->fingerprints = NULL;
    snapshot->fingerprint_count = 0;
    snapshot->findings = NULL;
    snapshot->finding_count = 0;
    snapshot->surfaces = NULL;
    snapshot->surface_count = 0;
}

void cmaper_history_host_snapshot_dispose(cmaper_history_host_snapshot_t *snapshot) {
    if (snapshot == NULL) {
        return;
    }

    if (snapshot->ports != NULL) {
        free(snapshot->ports);
    }
    if (snapshot->fingerprints != NULL) {
        free(snapshot->fingerprints);
    }
    if (snapshot->findings != NULL) {
        free(snapshot->findings);
    }
    if (snapshot->surfaces != NULL) {
        free(snapshot->surfaces);
    }
    cmaper_history_host_snapshot_init(snapshot);
}

void cmaper_history_host_snapshots_dispose(
    cmaper_history_host_snapshot_t *items,
    size_t count
) {
    size_t i;

    if (items == NULL) {
        return;
    }

    for (i = 0; i < count; ++i) {
        cmaper_history_host_snapshot_dispose(&items[i]);
    }
    free(items);
}

cmaper_err_t cmaper_history_query_open_db(
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
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
            NULL) != SQLITE_OK) {
        if (db != NULL) {
            sqlite3_close(db);
        }
        return CMAPER_ERR_IO;
    }

    if (sqlite3_busy_timeout(db, 2000) != SQLITE_OK) {
        sqlite3_close(db);
        return CMAPER_ERR_IO;
    }

    *out_db = db;
    *out_db_available = true;
    return CMAPER_OK;
}

void cmaper_history_query_close_db(sqlite3 **db) {
    if (db == NULL || *db == NULL) {
        return;
    }

    sqlite3_close(*db);
    *db = NULL;
}

cmaper_err_t cmaper_history_query_resolve_session(
    sqlite3 *db,
    const char *session_token,
    cmaper_history_session_ref_t *out_ref
) {
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

    if (db == NULL || session_token == NULL || session_token[0] == '\0' || out_ref == NULL) {
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
    cmaper_history_copy_column_text(out_ref->session_uid, sizeof(out_ref->session_uid), stmt, 1);
    cmaper_history_copy_column_text(out_ref->status, sizeof(out_ref->status), stmt, 2);
    cmaper_history_copy_column_text(out_ref->started_at, sizeof(out_ref->started_at), stmt, 3);
    cmaper_history_copy_column_text(out_ref->completed_at, sizeof(out_ref->completed_at), stmt, 4);

    cmaper_history_finalize(&stmt);
    return CMAPER_OK;
}

cmaper_err_t cmaper_history_query_resolve_device(
    sqlite3 *db,
    const char *device_token,
    sqlite3_int64 *out_device_id
) {
    static const char *SQL =
        "SELECT d.id "
        "FROM devices d "
        "WHERE CAST(d.id AS TEXT)=?1 "
        "   OR lower(d.stable_key)=lower(?1) "
        "   OR lower(d.fallback_key)=lower(?1) "
        "   OR replace(lower(COALESCE(d.mac_address,'')),'-',':')=replace(lower(?1),'-',':') "
        "LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || device_token == NULL || device_token[0] == '\0' || out_device_id == NULL) {
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

cmaper_err_t cmaper_history_query_sessions(
    sqlite3 *db,
    int limit,
    cmaper_history_sessions_report_t *out_report
) {
    static const char *SQL_TOTAL = "SELECT COUNT(*) FROM scan_sessions;";
    static const char *SQL_LIST =
        "SELECT s.session_uid, s.status, s.target, s.profile, "
        "       COALESCE(s.started_at,''), COALESCE(s.completed_at,''), "
        "       s.detail_targets_total, s.detail_hosts_success, s.detail_hosts_failed, s.detail_hosts_degraded, "
        "       COALESCE((SELECT COUNT(*) FROM host_observations ho WHERE ho.session_id=s.id), 0), "
        "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
        "                 JOIN host_observations ho ON ho.id=vf.host_observation_id "
        "                 WHERE ho.session_id=s.id), 0), "
        "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
        "                 JOIN host_observations ho ON ho.id=vf.host_observation_id "
        "                 WHERE ho.session_id=s.id AND vf.state='open'), 0), "
        "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
        "                 JOIN host_observations ho ON ho.id=vf.host_observation_id "
        "                 WHERE ho.session_id=s.id AND vf.state='open' "
        "                   AND vf.severity IN ('high','critical')), 0), "
        "       COALESCE((SELECT COUNT(*) FROM management_surfaces ms "
        "                 JOIN host_observations ho ON ho.id=ms.host_observation_id "
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
            (cmaper_history_session_row_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }

        cmaper_history_session_row_init(row);
        cmaper_history_copy_column_text(row->session_id, sizeof(row->session_id), stmt_list, 0);
        cmaper_history_copy_column_text(row->status, sizeof(row->status), stmt_list, 1);
        cmaper_history_copy_column_text(row->target, sizeof(row->target), stmt_list, 2);
        cmaper_history_copy_column_text(row->profile, sizeof(row->profile), stmt_list, 3);
        cmaper_history_copy_column_text(row->started_at, sizeof(row->started_at), stmt_list, 4);
        cmaper_history_copy_column_text(row->completed_at, sizeof(row->completed_at), stmt_list, 5);
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

    out_report->items = (cmaper_history_session_row_t *) rows.items;
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
    sqlite3 *db,
    const cmaper_history_session_ref_t *session_ref,
    cmaper_history_session_report_t *out_report
) {
    static const char *SQL_HOSTS =
        "SELECT CAST(d.id AS TEXT), ho.primary_ip, COALESCE(ho.status,''), "
        "       COALESCE(ho.hostname_primary,''), COALESCE(ho.mac_address,''), COALESCE(ho.mac_vendor,''), "
        "       COALESCE((SELECT COUNT(*) FROM service_observations so "
        "                 JOIN ports p ON p.id=so.port_id "
        "                 WHERE so.host_observation_id=ho.id AND so.state='open' AND p.protocol='tcp'), 0), "
        "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
        "                 WHERE vf.host_observation_id=ho.id AND vf.state='open'), 0), "
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

    rc = cmaper_history_fill_session_row(db, session_ref->id, &out_report->summary, &found);
    if (rc != CMAPER_OK) {
        return rc;
    }
    if (!found) {
        return CMAPER_OK;
    }

    out_report->found = true;

    rc = cmaper_history_buffer_init(&host_rows, sizeof(cmaper_history_session_host_row_t));
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
            (cmaper_history_session_host_row_t *) cmaper_history_buffer_push(&host_rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }

        cmaper_history_session_host_row_init(row);
        cmaper_history_copy_column_text(row->device_id, sizeof(row->device_id), stmt_hosts, 0);
        cmaper_history_copy_column_text(row->primary_ip, sizeof(row->primary_ip), stmt_hosts, 1);
        cmaper_history_copy_column_text(row->status, sizeof(row->status), stmt_hosts, 2);
        cmaper_history_copy_column_text(row->hostname, sizeof(row->hostname), stmt_hosts, 3);
        cmaper_history_copy_column_text(row->mac_address, sizeof(row->mac_address), stmt_hosts, 4);
        cmaper_history_copy_column_text(row->mac_vendor, sizeof(row->mac_vendor), stmt_hosts, 5);
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
        qsort(host_rows.items, host_rows.count, sizeof(cmaper_history_session_host_row_t),
            cmaper_history_session_host_row_compare);
    }

    out_report->hosts = (cmaper_history_session_host_row_t *) host_rows.items;
    out_report->host_count = host_rows.count;
    host_rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt_hosts);
    cmaper_history_buffer_dispose(&host_rows);
    return rc;
}

cmaper_err_t cmaper_history_query_devices(
    sqlite3 *db,
    const cmaper_history_session_ref_t *session_ref,
    int limit,
    cmaper_history_devices_report_t *out_report
) {
    static const char *SQL_TOTAL =
        "SELECT COUNT(DISTINCT ho.device_id) "
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
        "                 JOIN host_observations ho ON ho.id=so.host_observation_id "
        "                 JOIN ports p ON p.id=so.port_id "
        "                 WHERE ho.session_id=?1 AND ho.device_id=d.id "
        "                   AND so.state='open' AND p.protocol='tcp'), 0), "
        "       COALESCE((SELECT COUNT(*) "
        "                 FROM vulnerability_findings vf "
        "                 JOIN host_observations ho ON ho.id=vf.host_observation_id "
        "                 WHERE ho.session_id=?1 AND ho.device_id=d.id AND vf.state='open'), 0), "
        "       COALESCE((SELECT COUNT(*) "
        "                 FROM vulnerability_findings vf "
        "                 JOIN host_observations ho ON ho.id=vf.host_observation_id "
        "                 WHERE ho.session_id=?1 AND ho.device_id=d.id AND vf.state='open' "
        "                   AND vf.severity IN ('high','critical')), 0), "
        "       COALESCE((SELECT COUNT(*) "
        "                 FROM management_surfaces ms "
        "                 JOIN host_observations ho ON ho.id=ms.host_observation_id "
        "                 WHERE ho.session_id=?1 AND ho.device_id=d.id), 0) "
        "FROM devices d "
        "WHERE EXISTS (SELECT 1 FROM host_observations ho WHERE ho.session_id=?1 AND ho.device_id=d.id) "
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
    cmaper_history_copy_string(
        out_report->session_id,
        sizeof(out_report->session_id),
        session_ref->session_uid
    );

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
            (cmaper_history_device_row_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }

        cmaper_history_device_row_init(row);
        cmaper_history_copy_column_text(row->device_id, sizeof(row->device_id), stmt_list, 0);
        cmaper_history_copy_column_text(row->stable_key, sizeof(row->stable_key), stmt_list, 1);
        cmaper_history_copy_column_text(row->fallback_key, sizeof(row->fallback_key), stmt_list, 2);
        cmaper_history_copy_column_text(row->mac_address, sizeof(row->mac_address), stmt_list, 3);
        cmaper_history_copy_column_text(row->mac_vendor, sizeof(row->mac_vendor), stmt_list, 4);
        cmaper_history_copy_column_text(row->primary_ip, sizeof(row->primary_ip), stmt_list, 5);
        cmaper_history_copy_column_text(row->hostname, sizeof(row->hostname), stmt_list, 6);
        cmaper_history_copy_column_text(row->status, sizeof(row->status), stmt_list, 7);
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

    out_report->items = (cmaper_history_device_row_t *) rows.items;
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

cmaper_err_t cmaper_history_query_device(
    sqlite3 *db,
    const cmaper_history_session_ref_t *session_ref,
    sqlite3_int64 device_id,
    cmaper_history_device_report_t *out_report
) {
    static const char *SQL_DEVICE =
        "SELECT d.stable_key, d.fallback_key, COALESCE(d.mac_address,''), COALESCE(d.mac_vendor,''), "
        "       COALESCE(fs.session_uid,''), COALESCE(ls.session_uid,'') "
        "FROM devices d "
        "LEFT JOIN scan_sessions fs ON fs.id=d.first_seen_session_id "
        "LEFT JOIN scan_sessions ls ON ls.id=d.last_seen_session_id "
        "WHERE d.id=?;";
    static const char *SQL_SELECTED_OBS =
        "SELECT ho.primary_ip, COALESCE(ho.hostname_primary,''), COALESCE(ho.status,''), "
        "       COALESCE((SELECT COUNT(*) FROM service_observations so "
        "                 JOIN ports p ON p.id=so.port_id "
        "                 WHERE so.host_observation_id=ho.id AND so.state='open' AND p.protocol='tcp'), 0), "
        "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
        "                 WHERE vf.host_observation_id=ho.id AND vf.state='open'), 0), "
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
        "SELECT s.session_uid, COALESCE(s.started_at,''), COALESCE(s.status,''), "
        "       ho.primary_ip, COALESCE(ho.hostname_primary,''), COALESCE(ho.status,''), "
        "       COALESCE((SELECT COUNT(*) FROM service_observations so "
        "                 JOIN ports p ON p.id=so.port_id "
        "                 WHERE so.host_observation_id=ho.id AND so.state='open' AND p.protocol='tcp'), 0), "
        "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
        "                 WHERE vf.host_observation_id=ho.id AND vf.state='open'), 0), "
        "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
        "                 WHERE vf.host_observation_id=ho.id AND vf.state='open' "
        "                   AND vf.severity IN ('high','critical')), 0), "
        "       COALESCE((SELECT COUNT(*) FROM management_surfaces ms "
        "                 WHERE ms.host_observation_id=ho.id), 0) "
        "FROM host_observations ho "
        "JOIN scan_sessions s ON s.id=ho.session_id "
        "WHERE ho.device_id=? "
        "ORDER BY s.started_at DESC, s.id DESC;";
    sqlite3_stmt *stmt_device = NULL;
    sqlite3_stmt *stmt_selected = NULL;
    sqlite3_stmt *stmt_ips = NULL;
    sqlite3_stmt *stmt_observations = NULL;
    cmaper_history_buffer_t ip_rows;
    cmaper_history_buffer_t observation_rows;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || session_ref == NULL || out_report == NULL || device_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    memset(&ip_rows, 0, sizeof(ip_rows));
    memset(&observation_rows, 0, sizeof(observation_rows));

    cmaper_history_device_report_dispose(out_report);
    cmaper_history_device_report_init(out_report);
    out_report->db_available = true;
    cmaper_history_copy_string(out_report->session_id, sizeof(out_report->session_id),
        session_ref->session_uid);
    (void) snprintf(out_report->device_id, sizeof(out_report->device_id), "%lld",
        (long long) device_id);

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
    cmaper_history_copy_column_text(out_report->stable_key, sizeof(out_report->stable_key), stmt_device, 0);
    cmaper_history_copy_column_text(out_report->fallback_key, sizeof(out_report->fallback_key), stmt_device, 1);
    cmaper_history_copy_column_text(out_report->mac_address, sizeof(out_report->mac_address), stmt_device, 2);
    cmaper_history_copy_column_text(out_report->mac_vendor, sizeof(out_report->mac_vendor), stmt_device, 3);
    cmaper_history_copy_column_text(
        out_report->first_seen_session_id,
        sizeof(out_report->first_seen_session_id),
        stmt_device,
        4
    );
    cmaper_history_copy_column_text(
        out_report->last_seen_session_id,
        sizeof(out_report->last_seen_session_id),
        stmt_device,
        5
    );

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
        cmaper_history_copy_column_text(
            out_report->selected_primary_ip,
            sizeof(out_report->selected_primary_ip),
            stmt_selected,
            0
        );
        cmaper_history_copy_column_text(
            out_report->selected_hostname,
            sizeof(out_report->selected_hostname),
            stmt_selected,
            1
        );
        cmaper_history_copy_column_text(
            out_report->selected_status,
            sizeof(out_report->selected_status),
            stmt_selected,
            2
        );
        out_report->selected_open_tcp_ports = cmaper_history_column_size(stmt_selected, 3);
        out_report->selected_findings_open = cmaper_history_column_size(stmt_selected, 4);
        out_report->selected_findings_high_or_worse = cmaper_history_column_size(stmt_selected, 5);
        out_report->selected_management_surfaces = cmaper_history_column_size(stmt_selected, 6);
    } else if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    rc = cmaper_history_buffer_init(&ip_rows, sizeof(cmaper_history_device_ip_row_t));
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
            (cmaper_history_device_ip_row_t *) cmaper_history_buffer_push(&ip_rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_device_ip_row_init(row);
        cmaper_history_copy_column_text(row->ip_address, sizeof(row->ip_address), stmt_ips, 0);
        cmaper_history_copy_column_text(row->address_type, sizeof(row->address_type), stmt_ips, 1);
        row->is_current = sqlite3_column_int(stmt_ips, 2) != 0;
        cmaper_history_copy_column_text(
            row->first_seen_session_id,
            sizeof(row->first_seen_session_id),
            stmt_ips,
            3
        );
        cmaper_history_copy_column_text(
            row->last_seen_session_id,
            sizeof(row->last_seen_session_id),
            stmt_ips,
            4
        );
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    rc = cmaper_history_buffer_init(
        &observation_rows,
        sizeof(cmaper_history_device_observation_row_t)
    );
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

    while ((step_rc = sqlite3_step(stmt_observations)) == SQLITE_ROW) {
        cmaper_history_device_observation_row_t *row =
            (cmaper_history_device_observation_row_t *) cmaper_history_buffer_push(&observation_rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_device_observation_row_init(row);
        cmaper_history_copy_column_text(row->session_id, sizeof(row->session_id), stmt_observations, 0);
        cmaper_history_copy_column_text(row->started_at, sizeof(row->started_at), stmt_observations, 1);
        cmaper_history_copy_column_text(row->status, sizeof(row->status), stmt_observations, 2);
        cmaper_history_copy_column_text(row->primary_ip, sizeof(row->primary_ip), stmt_observations, 3);
        cmaper_history_copy_column_text(row->hostname, sizeof(row->hostname), stmt_observations, 4);
        cmaper_history_copy_column_text(row->host_status, sizeof(row->host_status), stmt_observations, 5);
        row->open_tcp_ports = cmaper_history_column_size(stmt_observations, 6);
        row->findings_open = cmaper_history_column_size(stmt_observations, 7);
        row->findings_high_or_worse = cmaper_history_column_size(stmt_observations, 8);
        row->management_surfaces = cmaper_history_column_size(stmt_observations, 9);
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    if (ip_rows.count > 1U) {
        qsort(ip_rows.items, ip_rows.count, sizeof(cmaper_history_device_ip_row_t),
            cmaper_history_device_ip_row_compare);
    }

    out_report->ip_addresses = (cmaper_history_device_ip_row_t *) ip_rows.items;
    out_report->ip_address_count = ip_rows.count;
    out_report->observations = (cmaper_history_device_observation_row_t *) observation_rows.items;
    out_report->observation_count = observation_rows.count;
    ip_rows.items = NULL;
    observation_rows.items = NULL;
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

cmaper_err_t cmaper_history_query_posture_counters(
    sqlite3 *db,
    sqlite3_int64 session_id,
    sqlite3_int64 device_id,
    cmaper_history_posture_counters_t *out_counters
) {
    static const char *SQL =
        "WITH host_scope AS ("
        "  SELECT ho.id, ho.device_id, COALESCE(ho.status,'') AS status "
        "  FROM host_observations ho "
        "  WHERE ho.session_id=?1 AND (?2<=0 OR ho.device_id=?2)"
        ") "
        "SELECT "
        "  COALESCE((SELECT COUNT(*) FROM host_scope), 0), "
        "  COALESCE((SELECT COUNT(*) FROM host_scope WHERE lower(status)='up'), 0), "
        "  COALESCE((SELECT COUNT(DISTINCT device_id) FROM host_scope), 0), "
        "  COALESCE((SELECT COUNT(*) "
        "            FROM service_observations so "
        "            JOIN ports p ON p.id=so.port_id "
        "            WHERE so.host_observation_id IN (SELECT id FROM host_scope) "
        "              AND so.state='open' AND p.protocol='tcp'), 0), "
        "  COALESCE((SELECT COUNT(*) "
        "            FROM vulnerability_findings vf "
        "            WHERE vf.host_observation_id IN (SELECT id FROM host_scope)), 0), "
        "  COALESCE((SELECT COUNT(*) "
        "            FROM vulnerability_findings vf "
        "            WHERE vf.host_observation_id IN (SELECT id FROM host_scope) "
        "              AND vf.state='open'), 0), "
        "  COALESCE((SELECT COUNT(*) "
        "            FROM vulnerability_findings vf "
        "            WHERE vf.host_observation_id IN (SELECT id FROM host_scope) "
        "              AND vf.state='open' AND vf.severity IN ('high','critical')), 0), "
        "  COALESCE((SELECT COUNT(*) "
        "            FROM management_surfaces ms "
        "            WHERE ms.host_observation_id IN (SELECT id FROM host_scope)), 0), "
        "  COALESCE((SELECT COUNT(DISTINCT ms.host_observation_id) "
        "            FROM management_surfaces ms "
        "            WHERE ms.host_observation_id IN (SELECT id FROM host_scope)), 0);";
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
    out_counters->hosts_with_management_surfaces = cmaper_history_column_size(stmt, 8);

    cmaper_history_finalize(&stmt);
    return CMAPER_OK;
}

cmaper_err_t cmaper_history_query_timeline(
    sqlite3 *db,
    const cmaper_history_session_ref_t *anchor_ref,
    sqlite3_int64 device_id,
    int limit,
    cmaper_history_timeline_report_t *out_report
) {
    static const char *SQL =
        "SELECT s.id, s.session_uid, s.status, COALESCE(s.started_at,''), COALESCE(s.completed_at,'') "
        "FROM scan_sessions s "
        "WHERE s.started_at <= (SELECT started_at FROM scan_sessions WHERE id=?1) "
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
        cmaper_history_copy_string(
            out_report->anchor_session_id,
            sizeof(out_report->anchor_session_id),
            anchor_ref->session_uid
        );
    }
    if (device_id > 0) {
        (void) snprintf(out_report->device_id, sizeof(out_report->device_id), "%lld",
            (long long) device_id);
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
            (cmaper_history_timeline_row_t *) cmaper_history_buffer_push(&rows);
        sqlite3_int64 session_id;

        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_timeline_row_init(row);

        session_id = sqlite3_column_int64(stmt, 0);
        cmaper_history_copy_column_text(row->session_id, sizeof(row->session_id), stmt, 1);
        cmaper_history_copy_column_text(row->status, sizeof(row->status), stmt, 2);
        cmaper_history_copy_column_text(row->started_at, sizeof(row->started_at), stmt, 3);
        cmaper_history_copy_column_text(row->completed_at, sizeof(row->completed_at), stmt, 4);

        {
            cmaper_history_posture_counters_t counters;
            cmaper_history_posture_counters_init(&counters);
            rc = cmaper_history_query_posture_counters(db, session_id, device_id, &counters);
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
                db,
                session_id,
                device_id,
                &row->device_present,
                row->device_ip,
                sizeof(row->device_ip),
                row->device_status,
                sizeof(row->device_status)
            );
            if (rc != CMAPER_OK) {
                goto cleanup;
            }
        }
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    out_report->items = (cmaper_history_timeline_row_t *) rows.items;
    out_report->count = rows.count;
    rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt);
    cmaper_history_buffer_dispose(&rows);
    return rc;
}

static cmaper_err_t cmaper_history_load_ports(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    cmaper_history_host_snapshot_t *snapshot
) {
    static const char *SQL =
        "SELECT p.protocol, p.port_number "
        "FROM service_observations so "
        "JOIN ports p ON p.id=so.port_id "
        "WHERE so.host_observation_id=? AND so.state='open' "
        "ORDER BY p.protocol ASC, p.port_number ASC;";
    sqlite3_stmt *stmt = NULL;
    cmaper_history_buffer_t rows;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || snapshot == NULL || host_observation_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_port_signal_t));
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cmaper_history_port_signal_t *row =
            (cmaper_history_port_signal_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_copy_column_text(row->protocol, sizeof(row->protocol), stmt, 0);
        row->port = sqlite3_column_int(stmt, 1);
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    snapshot->ports = (cmaper_history_port_signal_t *) rows.items;
    snapshot->port_count = rows.count;
    rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt);
    cmaper_history_buffer_dispose(&rows);
    return rc;
}

static cmaper_err_t cmaper_history_load_fingerprints(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    cmaper_history_host_snapshot_t *snapshot
) {
    static const char *SQL =
        "SELECT x.kind, x.fingerprint, COALESCE(x.protocol,''), COALESCE(x.port_number,0) "
        "FROM ("
        "  SELECT 'tls' AS kind, tf.fingerprint AS fingerprint, p.protocol AS protocol, p.port_number AS port_number "
        "  FROM tls_fingerprints tf "
        "  LEFT JOIN service_observations so ON so.id=tf.service_observation_id "
        "  LEFT JOIN ports p ON p.id=so.port_id "
        "  WHERE tf.host_observation_id=?1 "
        "  UNION ALL "
        "  SELECT 'ssh', sf.fingerprint, p.protocol, p.port_number "
        "  FROM ssh_fingerprints sf "
        "  LEFT JOIN service_observations so ON so.id=sf.service_observation_id "
        "  LEFT JOIN ports p ON p.id=so.port_id "
        "  WHERE sf.host_observation_id=?1 "
        "  UNION ALL "
        "  SELECT 'http', hf.fingerprint, p.protocol, p.port_number "
        "  FROM http_fingerprints hf "
        "  LEFT JOIN service_observations so ON so.id=hf.service_observation_id "
        "  LEFT JOIN ports p ON p.id=so.port_id "
        "  WHERE hf.host_observation_id=?1 "
        "  UNION ALL "
        "  SELECT 'smb', bf.fingerprint, p.protocol, p.port_number "
        "  FROM smb_fingerprints bf "
        "  LEFT JOIN service_observations so ON so.id=bf.service_observation_id "
        "  LEFT JOIN ports p ON p.id=so.port_id "
        "  WHERE bf.host_observation_id=?1 "
        ") AS x "
        "WHERE x.fingerprint IS NOT NULL AND x.fingerprint<>'' "
        "ORDER BY x.kind ASC, x.protocol ASC, x.port_number ASC, x.fingerprint ASC;";
    sqlite3_stmt *stmt = NULL;
    cmaper_history_buffer_t rows;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || snapshot == NULL || host_observation_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_fingerprint_signal_t));
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cmaper_history_fingerprint_signal_t *row =
            (cmaper_history_fingerprint_signal_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_copy_column_text(row->kind, sizeof(row->kind), stmt, 0);
        cmaper_history_copy_column_text(row->value, sizeof(row->value), stmt, 1);
        cmaper_history_copy_column_text(row->protocol, sizeof(row->protocol), stmt, 2);
        row->port = sqlite3_column_int(stmt, 3);
        row->has_service_context = row->port > 0 && row->protocol[0] != '\0';
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    snapshot->fingerprints = (cmaper_history_fingerprint_signal_t *) rows.items;
    snapshot->fingerprint_count = rows.count;
    rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt);
    cmaper_history_buffer_dispose(&rows);
    return rc;
}

static cmaper_err_t cmaper_history_load_findings(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    cmaper_history_host_snapshot_t *snapshot
) {
    static const char *SQL =
        "SELECT COALESCE(vf.finding_key,''), COALESCE(vf.severity,''), COALESCE(vf.state,''), "
        "       COALESCE(vf.title,''), COALESCE(p.protocol,''), COALESCE(p.port_number,0) "
        "FROM vulnerability_findings vf "
        "LEFT JOIN service_observations so ON so.id=vf.service_observation_id "
        "LEFT JOIN ports p ON p.id=so.port_id "
        "WHERE vf.host_observation_id=? "
        "ORDER BY vf.finding_key ASC, p.protocol ASC, p.port_number ASC;";
    sqlite3_stmt *stmt = NULL;
    cmaper_history_buffer_t rows;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || snapshot == NULL || host_observation_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_finding_signal_t));
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cmaper_history_finding_signal_t *row =
            (cmaper_history_finding_signal_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_copy_column_text(row->key, sizeof(row->key), stmt, 0);
        cmaper_history_copy_column_text(row->severity, sizeof(row->severity), stmt, 1);
        cmaper_history_copy_column_text(row->state, sizeof(row->state), stmt, 2);
        cmaper_history_copy_column_text(row->title, sizeof(row->title), stmt, 3);
        cmaper_history_copy_column_text(row->protocol, sizeof(row->protocol), stmt, 4);
        row->port = sqlite3_column_int(stmt, 5);
        row->has_service_context = row->port > 0 && row->protocol[0] != '\0';
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    snapshot->findings = (cmaper_history_finding_signal_t *) rows.items;
    snapshot->finding_count = rows.count;
    rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt);
    cmaper_history_buffer_dispose(&rows);
    return rc;
}

static cmaper_err_t cmaper_history_load_surfaces(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    cmaper_history_host_snapshot_t *snapshot
) {
    static const char *SQL =
        "SELECT COALESCE(ms.surface_type,''), COALESCE(ms.detail,''), "
        "       COALESCE(p.protocol,''), COALESCE(p.port_number,0) "
        "FROM management_surfaces ms "
        "LEFT JOIN service_observations so ON so.id=ms.service_observation_id "
        "LEFT JOIN ports p ON p.id=so.port_id "
        "WHERE ms.host_observation_id=? "
        "ORDER BY ms.surface_type ASC, p.protocol ASC, p.port_number ASC;";
    sqlite3_stmt *stmt = NULL;
    cmaper_history_buffer_t rows;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || snapshot == NULL || host_observation_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_surface_signal_t));
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cmaper_history_surface_signal_t *row =
            (cmaper_history_surface_signal_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_copy_column_text(row->type, sizeof(row->type), stmt, 0);
        cmaper_history_copy_column_text(row->detail, sizeof(row->detail), stmt, 1);
        cmaper_history_copy_column_text(row->protocol, sizeof(row->protocol), stmt, 2);
        row->port = sqlite3_column_int(stmt, 3);
        row->has_service_context = row->port > 0 && row->protocol[0] != '\0';
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    snapshot->surfaces = (cmaper_history_surface_signal_t *) rows.items;
    snapshot->surface_count = rows.count;
    rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt);
    cmaper_history_buffer_dispose(&rows);
    return rc;
}

cmaper_err_t cmaper_history_query_host_snapshots(
    sqlite3 *db,
    sqlite3_int64 session_id,
    cmaper_history_host_snapshot_t **out_items,
    size_t *out_count
) {
    static const char *SQL_HOSTS =
        "SELECT ho.id, ho.device_id, CAST(ho.device_id AS TEXT), ho.primary_ip, "
        "       COALESCE(ho.mac_address,''), COALESCE(ho.hostname_primary,''), COALESCE(ho.status,'') "
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

    rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_host_snapshot_t));
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
            (cmaper_history_host_snapshot_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_host_snapshot_init(row);
        row->host_observation_id = sqlite3_column_int64(stmt_hosts, 0);
        row->device_db_id = sqlite3_column_int64(stmt_hosts, 1);
        cmaper_history_copy_column_text(row->device_id, sizeof(row->device_id), stmt_hosts, 2);
        cmaper_history_copy_column_text(row->primary_ip, sizeof(row->primary_ip), stmt_hosts, 3);
        cmaper_history_copy_column_text(row->mac_address, sizeof(row->mac_address), stmt_hosts, 4);
        cmaper_history_copy_column_text(row->hostname, sizeof(row->hostname), stmt_hosts, 5);
        cmaper_history_copy_column_text(row->status, sizeof(row->status), stmt_hosts, 6);
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    for (i = 0; i < rows.count; ++i) {
        cmaper_history_host_snapshot_t *snapshot =
            &((cmaper_history_host_snapshot_t *) rows.items)[i];
        rc = cmaper_history_load_ports(db, snapshot->host_observation_id, snapshot);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
        rc = cmaper_history_load_fingerprints(db, snapshot->host_observation_id, snapshot);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
        rc = cmaper_history_load_findings(db, snapshot->host_observation_id, snapshot);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
        rc = cmaper_history_load_surfaces(db, snapshot->host_observation_id, snapshot);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
    }

    if (rows.count > 1U) {
        qsort(rows.items, rows.count, sizeof(cmaper_history_host_snapshot_t),
            cmaper_history_snapshot_compare);
    }

    *out_items = (cmaper_history_host_snapshot_t *) rows.items;
    *out_count = rows.count;
    rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt_hosts);
    if (rc != CMAPER_OK && rows.items != NULL) {
        cmaper_history_host_snapshots_dispose((cmaper_history_host_snapshot_t *) rows.items, rows.count);
        rows.items = NULL;
    }
    cmaper_history_buffer_dispose(&rows);
    return rc;
}

cmaper_err_t cmaper_history_query_previous_completed_session(
    sqlite3 *db,
    sqlite3_int64 anchor_session_id,
    cmaper_history_session_ref_t *out_previous
) {
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
    cmaper_history_copy_column_text(
        out_previous->session_uid,
        sizeof(out_previous->session_uid),
        stmt,
        1
    );
    cmaper_history_copy_column_text(out_previous->status, sizeof(out_previous->status), stmt, 2);
    cmaper_history_copy_column_text(
        out_previous->started_at,
        sizeof(out_previous->started_at),
        stmt,
        3
    );
    cmaper_history_copy_column_text(
        out_previous->completed_at,
        sizeof(out_previous->completed_at),
        stmt,
        4
    );

    cmaper_history_finalize(&stmt);
    return CMAPER_OK;
}
