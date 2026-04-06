#ifndef CMAPER_HISTORY_INTERNAL_QUERY_INTERNAL_H
#define CMAPER_HISTORY_INTERNAL_QUERY_INTERNAL_H

#include <stddef.h>

#include <sqlite3.h>

#include "cmaper/history/query.h"

typedef struct {
    void *items;
    size_t count;
    size_t capacity;
    size_t item_size;
} cmaper_history_buffer_t;

cmaper_err_t cmaper_history_prepare(
    sqlite3 *db,
    const char *sql,
    sqlite3_stmt **out_stmt
);

void cmaper_history_finalize(sqlite3_stmt **stmt);

cmaper_err_t cmaper_history_bind_int(sqlite3_stmt *stmt, int index, int value);

cmaper_err_t cmaper_history_bind_int64(
    sqlite3_stmt *stmt,
    int index,
    sqlite3_int64 value
);

cmaper_err_t cmaper_history_bind_text(
    sqlite3_stmt *stmt,
    int index,
    const char *value
);

void cmaper_history_copy_string(char *out, size_t out_cap, const char *value);

void cmaper_history_copy_column_text(
    char *out,
    size_t out_cap,
    sqlite3_stmt *stmt,
    int index
);

size_t cmaper_history_column_size(sqlite3_stmt *stmt, int index);

cmaper_err_t cmaper_history_buffer_init(cmaper_history_buffer_t *buffer, size_t item_size);
void *cmaper_history_buffer_push(cmaper_history_buffer_t *buffer);
void cmaper_history_buffer_dispose(cmaper_history_buffer_t *buffer);

int cmaper_history_session_host_row_compare(const void *left, const void *right);
int cmaper_history_device_ip_row_compare(const void *left, const void *right);
int cmaper_history_device_row_compare(const void *left, const void *right);
int cmaper_history_snapshot_compare(const void *left, const void *right);

#endif
