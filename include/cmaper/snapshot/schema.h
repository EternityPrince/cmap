#ifndef CMAPER_SNAPSHOT_SCHEMA_H
#define CMAPER_SNAPSHOT_SCHEMA_H

#include <sqlite3.h>

#include "cmaper/core/error.h"

#define CMAPER_SNAPSHOT_SCHEMA_DIAG_CAP 256

typedef struct {
    const char *field;
    char message[CMAPER_SNAPSHOT_SCHEMA_DIAG_CAP];
} cmaper_snapshot_schema_diag_t;

void cmaper_snapshot_schema_diag_clear(cmaper_snapshot_schema_diag_t *diag);
void cmaper_snapshot_schema_diag_setf(
    cmaper_snapshot_schema_diag_t *diag,
    const char *field,
    const char *fmt,
    ...
);

int cmaper_snapshot_schema_latest_version(void);
cmaper_err_t cmaper_snapshot_schema_bootstrap(
    sqlite3 *db,
    cmaper_snapshot_schema_diag_t *diag
);

#endif
