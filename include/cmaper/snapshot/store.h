#ifndef CMAPER_SNAPSHOT_STORE_H
#define CMAPER_SNAPSHOT_STORE_H

#include <stdbool.h>
#include <stddef.h>

#include <sqlite3.h>

#include "cmaper/core/error.h"
#include "cmaper/core/log.h"
#include "cmaper/runtime/paths.h"
#include "cmaper/scan/plan.h"
#include "cmaper/scan/runner.h"

#define CMAPER_SNAPSHOT_DIAG_CAP 256

typedef struct {
    const char *field;
    char message[CMAPER_SNAPSHOT_DIAG_CAP];
} cmaper_snapshot_diag_t;

typedef struct {
    bool enabled;
    sqlite3 *db;
    char db_path[CMAPER_RUNTIME_PATH_CAP];
} cmaper_snapshot_store_t;

typedef struct {
    const char *session_uid;
    const cmaper_scan_plan_t *plan;
} cmaper_snapshot_session_start_t;

typedef struct {
    const char *session_uid;
    const char *error_message;
} cmaper_snapshot_session_fail_t;

typedef struct {
    const char *session_uid;
    const char *discovery_xml_path;
    size_t detail_targets_total;
    size_t detail_hosts_success;
    size_t detail_hosts_failed;
    size_t detail_hosts_degraded;
} cmaper_snapshot_session_complete_t;

typedef struct {
    const char *session_uid;
    const cmaper_scan_plan_t *plan;
    const cmaper_scan_result_t *scan_result;
} cmaper_snapshot_write_request_t;

void cmaper_snapshot_diag_clear(cmaper_snapshot_diag_t *diag);
void cmaper_snapshot_diag_setf(
    cmaper_snapshot_diag_t *diag,
    const char *field,
    const char *fmt,
    ...
);

void cmaper_snapshot_store_init(cmaper_snapshot_store_t *store);
cmaper_err_t cmaper_snapshot_store_open(
    cmaper_snapshot_store_t *store,
    const cmaper_runtime_paths_t *paths,
    bool enable_persistence,
    cmaper_logger_t *logger,
    cmaper_snapshot_diag_t *diag
);
bool cmaper_snapshot_store_is_enabled(const cmaper_snapshot_store_t *store);
void cmaper_snapshot_store_close(cmaper_snapshot_store_t *store);

cmaper_err_t cmaper_snapshot_session_start(
    cmaper_snapshot_store_t *store,
    const cmaper_snapshot_session_start_t *request
);
cmaper_err_t cmaper_snapshot_session_fail(
    cmaper_snapshot_store_t *store,
    const cmaper_snapshot_session_fail_t *request
);
cmaper_err_t cmaper_snapshot_session_complete(
    cmaper_snapshot_store_t *store,
    const cmaper_snapshot_session_complete_t *request
);

cmaper_err_t cmaper_snapshot_store_write_scan(
    cmaper_snapshot_store_t *store,
    const cmaper_snapshot_write_request_t *request,
    cmaper_logger_t *logger
);

#endif
