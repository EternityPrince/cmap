#ifndef CMAPER_SNAPSHOT_SESSION_INTERNAL_H
#define CMAPER_SNAPSHOT_SESSION_INTERNAL_H

#include <sqlite3.h>

#include "cmaper/core/error.h"

cmaper_err_t cmaper_snapshot_get_session_id(
    sqlite3 *db,
    const char *session_uid,
    sqlite3_int64 *out_session_id
);

cmaper_err_t cmaper_snapshot_upsert_session_networks(
    sqlite3 *db,
    sqlite3_int64 session_id,
    const char *target_expression
);

#endif
