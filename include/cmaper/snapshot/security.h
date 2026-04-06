#ifndef CMAPER_SNAPSHOT_SECURITY_H
#define CMAPER_SNAPSHOT_SECURITY_H

#include <stddef.h>

#include <sqlite3.h>

#include "cmaper/core/error.h"
#include "cmaper/core/log.h"
#include "cmaper/security/nmap_extract.h"

typedef struct {
    size_t findings_total;
    size_t findings_open;
    size_t findings_high_or_worse;
    size_t management_surfaces_total;
    size_t hosts_with_management_surfaces;
} cmaper_snapshot_security_aggregate_t;

void cmaper_snapshot_security_aggregate_init(cmaper_snapshot_security_aggregate_t *aggregate);

cmaper_err_t cmaper_snapshot_security_persist_host_artifacts(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    const cmaper_security_host_artifacts_t *artifacts,
    cmaper_logger_t *logger
);

cmaper_err_t cmaper_snapshot_security_query_session_aggregate(
    sqlite3 *db,
    sqlite3_int64 session_id,
    cmaper_snapshot_security_aggregate_t *out_aggregate
);

#endif
