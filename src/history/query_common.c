#include "cmaper/history/internal/query_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmaper/core/sqlite.h"
#include "cmaper/history/fuzzy.h"
#include "cmaper/platform/fs.h"

cmaper_err_t cmaper_history_prepare(sqlite3 *db, const char *sql,
                                    sqlite3_stmt **out_stmt) {
  return cmaper_sqlite_prepare(db, sql, out_stmt);
}

void cmaper_history_finalize(sqlite3_stmt **stmt) {
  cmaper_sqlite_finalize(stmt);
}

cmaper_err_t cmaper_history_bind_int(sqlite3_stmt *stmt, int index, int value) {
  return cmaper_sqlite_bind_int(stmt, index, value);
}

cmaper_err_t cmaper_history_bind_int64(sqlite3_stmt *stmt, int index,
                                       sqlite3_int64 value) {
  return cmaper_sqlite_bind_int64(stmt, index, value);
}

cmaper_err_t cmaper_history_bind_text(sqlite3_stmt *stmt, int index,
                                      const char *value) {
  return cmaper_sqlite_bind_text(stmt, index, value);
}

void cmaper_history_copy_string(char *out, size_t out_cap, const char *value) {
  if (out == NULL || out_cap == 0) {
    return;
  }

  out[0] = '\0';
  if (value == NULL) {
    return;
  }

  (void)snprintf(out, out_cap, "%s", value);
}

void cmaper_history_copy_column_text(char *out, size_t out_cap,
                                     sqlite3_stmt *stmt, int index) {
  const unsigned char *value;

  if (out == NULL || out_cap == 0 || stmt == NULL) {
    return;
  }

  value = sqlite3_column_text(stmt, index);
  if (value == NULL) {
    out[0] = '\0';
    return;
  }

  cmaper_history_copy_string(out, out_cap, (const char *)value);
}

size_t cmaper_history_column_size(sqlite3_stmt *stmt, int index) {
  sqlite3_int64 value;

  if (stmt == NULL) {
    return 0;
  }

  value = sqlite3_column_int64(stmt, index);
  if (value <= 0) {
    return 0;
  }
  return (size_t)value;
}

cmaper_err_t cmaper_history_buffer_init(cmaper_history_buffer_t *buffer,
                                        size_t item_size) {
  if (buffer == NULL || item_size == 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  buffer->items = NULL;
  buffer->count = 0;
  buffer->capacity = 0;
  buffer->item_size = item_size;
  return CMAPER_OK;
}

void *cmaper_history_buffer_push(cmaper_history_buffer_t *buffer) {
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

  next = (unsigned char *)buffer->items + buffer->count * buffer->item_size;
  memset(next, 0, buffer->item_size);
  buffer->count += 1U;
  return next;
}

void cmaper_history_buffer_dispose(cmaper_history_buffer_t *buffer) {
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

int cmaper_history_session_host_row_compare(const void *left,
                                            const void *right) {
  const cmaper_history_session_host_row_t *a =
      (const cmaper_history_session_host_row_t *)left;
  const cmaper_history_session_host_row_t *b =
      (const cmaper_history_session_host_row_t *)right;
  int rc = cmaper_history_compare_ip(a->primary_ip, b->primary_ip);

  if (rc != 0) {
    return rc;
  }
  return strcmp(a->device_id, b->device_id);
}

int cmaper_history_device_ip_row_compare(const void *left, const void *right) {
  const cmaper_history_device_ip_row_t *a =
      (const cmaper_history_device_ip_row_t *)left;
  const cmaper_history_device_ip_row_t *b =
      (const cmaper_history_device_ip_row_t *)right;
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

int cmaper_history_device_row_compare(const void *left, const void *right) {
  const cmaper_history_device_row_t *a =
      (const cmaper_history_device_row_t *)left;
  const cmaper_history_device_row_t *b =
      (const cmaper_history_device_row_t *)right;
  int rc = cmaper_history_compare_ip(a->primary_ip, b->primary_ip);
  if (rc != 0) {
    return rc;
  }
  return strcmp(a->device_id, b->device_id);
}

int cmaper_history_snapshot_compare(const void *left, const void *right) {
  const cmaper_history_host_snapshot_t *a =
      (const cmaper_history_host_snapshot_t *)left;
  const cmaper_history_host_snapshot_t *b =
      (const cmaper_history_host_snapshot_t *)right;
  int rc = cmaper_history_compare_ip(a->primary_ip, b->primary_ip);
  if (rc != 0) {
    return rc;
  }
  return strcmp(a->device_id, b->device_id);
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

void cmaper_history_host_snapshot_init(
    cmaper_history_host_snapshot_t *snapshot) {
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
  snapshot->script_results = NULL;
  snapshot->script_result_count = 0;
  snapshot->findings = NULL;
  snapshot->finding_count = 0;
  snapshot->surfaces = NULL;
  snapshot->surface_count = 0;
}

void cmaper_history_host_snapshot_dispose(
    cmaper_history_host_snapshot_t *snapshot) {
  if (snapshot == NULL) {
    return;
  }

  if (snapshot->ports != NULL) {
    free(snapshot->ports);
  }
  if (snapshot->fingerprints != NULL) {
    free(snapshot->fingerprints);
  }
  if (snapshot->script_results != NULL) {
    free(snapshot->script_results);
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
    cmaper_history_host_snapshot_t *items, size_t count) {
  size_t i;

  if (items == NULL) {
    return;
  }

  for (i = 0; i < count; ++i) {
    cmaper_history_host_snapshot_dispose(&items[i]);
  }
  free(items);
}

cmaper_err_t cmaper_history_query_open_db(const char *db_path, sqlite3 **out_db,
                                          bool *out_db_available) {
  sqlite3 *db = NULL;

  if (db_path == NULL || out_db == NULL || out_db_available == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_db = NULL;
  *out_db_available = false;

  if (!cmaper_fs_path_exists(db_path)) {
    return CMAPER_OK;
  }

  if (sqlite3_open_v2(db_path, &db,
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
