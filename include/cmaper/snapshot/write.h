#ifndef CMAPER_SNAPSHOT_WRITE_H
#define CMAPER_SNAPSHOT_WRITE_H

#include <sqlite3.h>

#include "cmaper/core/error.h"
#include "cmaper/core/log.h"
#include "cmaper/snapshot/store.h"

cmaper_err_t
cmaper_snapshot_write_scan_data(sqlite3 *db,
                                const cmaper_snapshot_write_request_t *request,
                                cmaper_logger_t *logger);

#endif
