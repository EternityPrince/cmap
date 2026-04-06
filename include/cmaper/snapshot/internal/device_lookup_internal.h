#ifndef CMAPER_SNAPSHOT_DEVICE_LOOKUP_INTERNAL_H
#define CMAPER_SNAPSHOT_DEVICE_LOOKUP_INTERNAL_H

#include <sqlite3.h>

#include "cmaper/core/error.h"

cmaper_err_t cmaper_snapshot_find_device_by_mac(
    sqlite3 *db,
    const char *mac_address,
    sqlite3_int64 *out_device_id
);

cmaper_err_t cmaper_snapshot_find_device_by_previous_ip(
    sqlite3 *db,
    const char *ip_address,
    sqlite3_int64 *out_device_id
);

cmaper_err_t cmaper_snapshot_find_device_by_fallback_key(
    sqlite3 *db,
    const char *fallback_key,
    sqlite3_int64 *out_device_id
);

#endif
