#include "cmaper/snapshot/internal/sqlite_internal.h"

#include <stddef.h>

#include "cmaper/core/sqlite.h"

cmaper_err_t cmaper_snapshot_sqlite_prepare(
    sqlite3 *db,
    const char *sql,
    sqlite3_stmt **out_stmt
) {
    return cmaper_sqlite_prepare(db, sql, out_stmt);
}

void cmaper_snapshot_sqlite_finalize(sqlite3_stmt **stmt) {
    cmaper_sqlite_finalize(stmt);
}

cmaper_err_t cmaper_snapshot_sqlite_bind_text(
    sqlite3_stmt *stmt,
    int index,
    const char *value
) {
    return cmaper_sqlite_bind_text(stmt, index, value);
}

cmaper_err_t cmaper_snapshot_sqlite_bind_text_or_null(
    sqlite3_stmt *stmt,
    int index,
    const char *value
) {
    return cmaper_sqlite_bind_text_or_null(stmt, index, value);
}

cmaper_err_t cmaper_snapshot_sqlite_bind_int(sqlite3_stmt *stmt, int index, int value) {
    return cmaper_sqlite_bind_int(stmt, index, value);
}

cmaper_err_t cmaper_snapshot_sqlite_bind_int64(
    sqlite3_stmt *stmt,
    int index,
    sqlite3_int64 value
) {
    return cmaper_sqlite_bind_int64(stmt, index, value);
}

cmaper_err_t cmaper_snapshot_sqlite_step_done(sqlite3_stmt *stmt) {
    return cmaper_sqlite_step_done(stmt);
}

cmaper_err_t cmaper_snapshot_sqlite_step_row(sqlite3_stmt *stmt) {
    return cmaper_sqlite_step_row(stmt);
}

cmaper_err_t cmaper_snapshot_sqlite_exec(sqlite3 *db, const char *sql) {
    return cmaper_sqlite_exec(db, sql);
}
