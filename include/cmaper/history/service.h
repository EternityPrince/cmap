#ifndef CMAPER_HISTORY_SERVICE_H
#define CMAPER_HISTORY_SERVICE_H

#include <stdio.h>

#include "cmaper/cli/config.h"
#include "cmaper/core/error.h"
#include "cmaper/core/log.h"
#include "cmaper/runtime/paths.h"

typedef struct {
    const cmaper_cli_config_t *config;
    const cmaper_runtime_paths_t *paths;
    cmaper_logger_t *logger;
    FILE *report_stream;
} cmaper_history_service_request_t;

cmaper_err_t cmaper_history_service_run(const cmaper_history_service_request_t *request);

#endif
