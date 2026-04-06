#ifndef CMAPER_CORE_SQLITE_H
#define CMAPER_CORE_SQLITE_H

#include <sqlite3.h>

#include "cmaper/core/error.h"

cmaper_err_t cmaper_sqlite_prepare(
    sqlite3 *db,
    const char *sql,
    sqlite3_stmt **out_stmt
);

void cmaper_sqlite_finalize(sqlite3_stmt **stmt);

cmaper_err_t cmaper_sqlite_bind_text(
    sqlite3_stmt *stmt,
    int index,
    const char *value
);

cmaper_err_t cmaper_sqlite_bind_text_or_null(
    sqlite3_stmt *stmt,
    int index,
    const char *value
);

cmaper_err_t cmaper_sqlite_bind_int(sqlite3_stmt *stmt, int index, int value);

cmaper_err_t cmaper_sqlite_bind_int64(
    sqlite3_stmt *stmt,
    int index,
    sqlite3_int64 value
);

cmaper_err_t cmaper_sqlite_step_done(sqlite3_stmt *stmt);
cmaper_err_t cmaper_sqlite_step_row(sqlite3_stmt *stmt);

cmaper_err_t cmaper_sqlite_exec(sqlite3 *db, const char *sql);

#endif
