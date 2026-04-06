#ifndef CMAPER_SNAPSHOT_HOST_CHILDREN_INTERNAL_H
#define CMAPER_SNAPSHOT_HOST_CHILDREN_INTERNAL_H

#include <sqlite3.h>

#include "cmaper/core/error.h"
#include "cmaper/snapshot/internal/host_view_internal.h"

cmaper_err_t cmaper_snapshot_replace_host_children(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    const cmaper_snapshot_host_view_t *host_view
);

#endif
