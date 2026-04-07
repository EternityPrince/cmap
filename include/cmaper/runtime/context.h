#ifndef CMAPER_RUNTIME_CONTEXT_H
#define CMAPER_RUNTIME_CONTEXT_H

#include "cmaper/cli/config.h"
#include "cmaper/core/log.h"
#include "cmaper/runtime/paths.h"

typedef struct {
  cmaper_cli_config_t config;
  cmaper_logger_t logger;
  cmaper_runtime_paths_t paths;
} cmaper_runtime_t;

cmaper_err_t cmaper_runtime_init(cmaper_runtime_t *runtime,
                                 const cmaper_cli_config_t *config,
                                 cmaper_runtime_paths_diag_t *diag);
void cmaper_runtime_dispose(cmaper_runtime_t *runtime);

#endif
