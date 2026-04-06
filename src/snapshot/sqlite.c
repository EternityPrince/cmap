#include "cmaper/snapshot/internal/sqlite_internal.h"

#include <stddef.h>

cmaper_err_t cmaper_snapshot_sqlite_prepare(
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

void cmaper_snapshot_sqlite_finalize(sqlite3_stmt **stmt) {
    if (stmt == NULL || *stmt == NULL) {
        return;
    }

    sqlite3_finalize(*stmt);
    *stmt = NULL;
}

cmaper_err_t cmaper_snapshot_sqlite_bind_text(
    sqlite3_stmt *stmt,
    int index,
    const char *value
) {
    int rc;

    if (stmt == NULL || value == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_bind_text(stmt, index, value, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        return CMAPER_ERR_IO;
    }

    return CMAPER_OK;
}

cmaper_err_t cmaper_snapshot_sqlite_bind_text_or_null(
    sqlite3_stmt *stmt,
    int index,
    const char *value
) {
    int rc;

    if (stmt == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    if (value == NULL || value[0] == '\0') {
        rc = sqlite3_bind_null(stmt, index);
    } else {
        rc = sqlite3_bind_text(stmt, index, value, -1, SQLITE_TRANSIENT);
    }

    if (rc != SQLITE_OK) {
        return CMAPER_ERR_IO;
    }

    return CMAPER_OK;
}

cmaper_err_t cmaper_snapshot_sqlite_bind_int(sqlite3_stmt *stmt, int index, int value) {
    int rc;

    if (stmt == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_bind_int(stmt, index, value);
    if (rc != SQLITE_OK) {
        return CMAPER_ERR_IO;
    }

    return CMAPER_OK;
}

cmaper_err_t cmaper_snapshot_sqlite_bind_int64(
    sqlite3_stmt *stmt,
    int index,
    sqlite3_int64 value
) {
    int rc;

    if (stmt == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_bind_int64(stmt, index, value);
    if (rc != SQLITE_OK) {
        return CMAPER_ERR_IO;
    }

    return CMAPER_OK;
}

cmaper_err_t cmaper_snapshot_sqlite_step_done(sqlite3_stmt *stmt) {
    int rc;

    if (stmt == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        return CMAPER_ERR_IO;
    }

    return CMAPER_OK;
}

cmaper_err_t cmaper_snapshot_sqlite_step_row(sqlite3_stmt *stmt) {
    int rc;

    if (stmt == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        return CMAPER_ERR_IO;
    }

    return CMAPER_OK;
}

cmaper_err_t cmaper_snapshot_sqlite_exec(sqlite3 *db, const char *sql) {
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
