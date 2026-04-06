#include "cmaper/snapshot/internal/device_upsert_internal.h"

#include <stddef.h>

#include "cmaper/snapshot/internal/sqlite_internal.h"

cmaper_err_t cmaper_snapshot_insert_device(
    sqlite3 *db,
    const char *stable_key,
    const char *fallback_key,
    const char *mac_address,
    const char *mac_vendor,
    sqlite3_int64 session_id,
    sqlite3_int64 *out_device_id
) {
    static const char *SQL =
        "INSERT INTO devices("
        "  stable_key, fallback_key, mac_address, mac_vendor,"
        "  first_seen_session_id, last_seen_session_id, updated_at"
        ") VALUES(?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'));";
    sqlite3_stmt *stmt = NULL;
    cmaper_err_t rc;

    if (db == NULL || stable_key == NULL || fallback_key == NULL || out_device_id == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_snapshot_sqlite_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_sqlite_bind_text(stmt, 1, stable_key);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_text(stmt, 2, fallback_key);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt, 3, mac_address);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt, 4, mac_vendor);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_int64(stmt, 5, session_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_int64(stmt, 6, session_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_step_done(stmt);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    *out_device_id = sqlite3_last_insert_rowid(db);
    rc = CMAPER_OK;

cleanup:
    cmaper_snapshot_sqlite_finalize(&stmt);
    return rc;
}

cmaper_err_t cmaper_snapshot_update_device(
    sqlite3 *db,
    sqlite3_int64 device_id,
    sqlite3_int64 session_id,
    const char *mac_address,
    const char *mac_vendor
) {
    static const char *SQL =
        "UPDATE devices "
        "SET last_seen_session_id=?, "
        "    mac_address=COALESCE(mac_address, ?), "
        "    mac_vendor=COALESCE(mac_vendor, ?), "
        "    updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') "
        "WHERE id=?;";
    sqlite3_stmt *stmt = NULL;
    cmaper_err_t rc;

    if (db == NULL || device_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_snapshot_sqlite_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_sqlite_bind_int64(stmt, 1, session_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt, 2, mac_address);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt, 3, mac_vendor);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_int64(stmt, 4, device_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_step_done(stmt);

cleanup:
    cmaper_snapshot_sqlite_finalize(&stmt);
    return rc;
}

cmaper_err_t cmaper_snapshot_upsert_device_ip(
    sqlite3 *db,
    sqlite3_int64 device_id,
    const char *ip_address,
    const char *address_type,
    sqlite3_int64 session_id
) {
    static const char *SQL_MARK_OLD =
        "UPDATE device_ip_addresses SET is_current=0 "
        "WHERE device_id=? AND ip_address<>?;";
    static const char *SQL_UPSERT =
        "INSERT INTO device_ip_addresses("
        "  device_id, ip_address, address_type, first_seen_session_id, last_seen_session_id, is_current"
        ") VALUES(?, ?, ?, ?, ?, 1) "
        "ON CONFLICT(device_id, ip_address) DO UPDATE SET "
        "  address_type=excluded.address_type, "
        "  last_seen_session_id=excluded.last_seen_session_id, "
        "  is_current=1;";
    sqlite3_stmt *stmt_old = NULL;
    sqlite3_stmt *stmt_upsert = NULL;
    cmaper_err_t rc = CMAPER_OK;

    if (db == NULL || device_id <= 0 || ip_address == NULL || ip_address[0] == '\0') {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_snapshot_sqlite_prepare(db, SQL_MARK_OLD, &stmt_old);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_int64(stmt_old, 1, device_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_text(stmt_old, 2, ip_address);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_step_done(stmt_old);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    rc = cmaper_snapshot_sqlite_prepare(db, SQL_UPSERT, &stmt_upsert);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_int64(stmt_upsert, 1, device_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_text(stmt_upsert, 2, ip_address);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt_upsert, 3, address_type);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_int64(stmt_upsert, 4, session_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_bind_int64(stmt_upsert, 5, session_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_step_done(stmt_upsert);

cleanup:
    cmaper_snapshot_sqlite_finalize(&stmt_old);
    cmaper_snapshot_sqlite_finalize(&stmt_upsert);
    return rc;
}
