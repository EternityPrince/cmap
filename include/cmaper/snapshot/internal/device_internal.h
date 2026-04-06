#ifndef CMAPER_SNAPSHOT_DEVICE_INTERNAL_H
#define CMAPER_SNAPSHOT_DEVICE_INTERNAL_H

#include <sqlite3.h>

#include "cmaper/core/error.h"

cmaper_err_t cmaper_snapshot_resolve_device(
    sqlite3 *db,
    sqlite3_int64 session_id,
    const char *primary_ip,
    const char *address_type,
    const char *mac_address,
    const char *mac_vendor,
    sqlite3_int64 *out_device_id
);

#endif
