#ifndef CMAPER_SNAPSHOT_HOST_PERSIST_INTERNAL_H
#define CMAPER_SNAPSHOT_HOST_PERSIST_INTERNAL_H

#include <sqlite3.h>

#include "cmaper/core/error.h"
#include "cmaper/core/log.h"
#include "cmaper/snapshot/internal/merge_internal.h"

cmaper_err_t cmaper_snapshot_persist_merged_host(
    sqlite3 *db,
    sqlite3_int64 session_id,
    const cmaper_snapshot_merged_host_t *merged,
    cmaper_logger_t *logger
);

#endif
