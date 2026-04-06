#ifndef CMAPER_SNAPSHOT_HOST_OBSERVATION_INTERNAL_H
#define CMAPER_SNAPSHOT_HOST_OBSERVATION_INTERNAL_H

#include <sqlite3.h>

#include "cmaper/core/error.h"

cmaper_err_t cmaper_snapshot_upsert_host_observation(
    sqlite3 *db,
    sqlite3_int64 session_id,
    sqlite3_int64 device_id,
    const char *primary_ip,
    const char *primary_ip_type,
    const char *status,
    const char *source,
    const char *hostname_primary,
    const char *mac_address,
    const char *mac_vendor,
    const char *detail_xml_path,
    sqlite3_int64 *out_host_observation_id
);

#endif
