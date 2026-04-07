#ifndef CMAPER_SNAPSHOT_DEVICE_UPSERT_INTERNAL_H
#define CMAPER_SNAPSHOT_DEVICE_UPSERT_INTERNAL_H

#include <sqlite3.h>

#include "cmaper/core/error.h"

cmaper_err_t cmaper_snapshot_insert_device(sqlite3 *db, const char *stable_key,
                                           const char *fallback_key,
                                           const char *mac_address,
                                           const char *mac_vendor,
                                           sqlite3_int64 session_id,
                                           sqlite3_int64 *out_device_id);

cmaper_err_t cmaper_snapshot_update_device(sqlite3 *db, sqlite3_int64 device_id,
                                           sqlite3_int64 session_id,
                                           const char *mac_address,
                                           const char *mac_vendor);

cmaper_err_t cmaper_snapshot_upsert_device_ip(sqlite3 *db,
                                              sqlite3_int64 device_id,
                                              const char *ip_address,
                                              const char *address_type,
                                              sqlite3_int64 session_id);

#endif
