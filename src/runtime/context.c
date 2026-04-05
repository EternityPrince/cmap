#include "cmaper/runtime/context.h"

cmaper_err_t cmaper_runtime_init(
    cmaper_runtime_t *runtime,
    const cmaper_cli_config_t *config,
    cmaper_runtime_paths_diag_t *diag
) {
    cmaper_err_t rc;

    if (runtime == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    if (config != NULL) {
        runtime->config = *config;
    } else {
        cmaper_cli_config_init(&runtime->config);
    }

    cmaper_log_init(&runtime->logger, NULL, runtime->config.output.log_level);
    runtime->logger.use_color = runtime->logger.use_color && runtime->config.output.use_color;

    rc = cmaper_runtime_paths_resolve(&runtime->paths, diag);
    if (rc != CMAPER_OK) {
        return rc;
    }

    return CMAPER_OK;
}

void cmaper_runtime_dispose(cmaper_runtime_t *runtime) {
    if (runtime == NULL) {
        return;
    }

    runtime->logger.stream = NULL;
    runtime->logger.level = CMAPER_LOG_QUIET;
    runtime->logger.use_color = false;
    cmaper_runtime_paths_init(&runtime->paths);
    cmaper_cli_config_init(&runtime->config);
}
